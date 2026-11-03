<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\PendingLogin;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Facades\TwoFactor;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Notifications\TwoFactorEmailChangedNotification;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeDeliveryChannel;
use Nakipelo\Orchid2FA\Tests\Fixtures\ProbeVerifierChannel;
use Orchid\Alert\Toast;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §4.4, §4.5, §5.11, §6.3, §10.1 "the user's channel instead of the global one" (stage 1):
 * the channel comes from the user's record, not from `orchid-2fa.channel`.
 */
beforeEach(function () {
    Notification::fake();
    FakeDeliveryChannel::reset();
    TwoFactor::extend('fake', fn () => new FakeDeliveryChannel);
});

function ucRecord(User $user, string $channel, array $attributes = []): TwoFactorAuthentication
{
    return TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'channel' => $channel] + $attributes);
}

/**
 * The masked destination of the fake channel.
 */
function ucMask(User $user): string
{
    return '+1***'.substr('+1555000'.$user->id, -2);
}

it('signs in through the channel of the record, not the default channel', function () {
    Event::fake([TwoFactorChallengeSent::class, TwoFactorPassed::class]);
    $user = tfEnforcedUser();
    ucRecord($user, 'fake', ['confirmed_at' => now()]);

    expect(config('orchid-2fa.channel'))->toBe('email');

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));

    expect(FakeDeliveryChannel::$sent)->toHaveCount(1)
        ->and(FakeDeliveryChannel::$sent[0]['destination'])->toBe('+1555000'.$user->id)
        ->and(tfSentCodes())->toBe([])
        ->and(PendingLogin::fromSession(session()->driver())?->channel)->toBe('fake');

    $this->get(route('platform.two-factor.challenge'))
        ->assertOk()
        ->assertSee(ucMask($user), false)
        ->assertDontSee('e***@example.com');

    tfVerify(FakeDeliveryChannel::lastCode())->assertRedirect(route('platform.main'));
    $this->assertAuthenticatedAs($user);

    Event::assertDispatched(TwoFactorChallengeSent::class, fn (TwoFactorChallengeSent $event) => $event->channel === 'fake'
        && $event->maskedDestination === ucMask($user)
        && $event->context === 'login');
    Event::assertDispatched(TwoFactorPassed::class, fn (TwoFactorPassed $event) => $event->channel === 'fake'
        && $event->via === 'code');
});

it('fires the failure and lockout events with the channel of the challenge', function () {
    Event::fake([TwoFactorFailed::class, TwoFactorLockedOut::class]);
    $user = tfEnforcedUser();
    ucRecord($user, 'fake');

    tfLogin();
    $wrong = tfWrongCode(FakeDeliveryChannel::lastCode());

    foreach (range(1, 5) as $i) {
        tfVerify($wrong)->assertSessionHasErrors('code');
    }

    Event::assertDispatchedTimes(TwoFactorFailed::class, 5);
    Event::assertDispatched(TwoFactorFailed::class, fn (TwoFactorFailed $event) => $event->channel === 'fake'
        && $event->reason === 'invalid_code');
    Event::assertDispatched(TwoFactorLockedOut::class, fn (TwoFactorLockedOut $event) => $event->channel === 'fake'
        && $event->reason === 'attempts_exceeded');
    $this->assertGuest();
});

it('uses the record channel email although the default channel is another one', function () {
    config(['orchid-2fa.channel' => 'fake']);
    $user = tfEnforcedUser();
    ucRecord($user, 'email');

    tfLogin();

    expect(tfSentCodes('enforced@example.com'))->toHaveCount(1)
        ->and(FakeDeliveryChannel::$sent)->toBe([]);

    tfVerify(tfLastCode())->assertRedirect(route('platform.main'));
    $this->assertAuthenticatedAs($user);
});

it('gives a user without a record the default channel and writes it to the new record', function () {
    config(['orchid-2fa.channel' => 'fake']);
    $user = tfEnforcedUser();

    tfLogin();

    expect(FakeDeliveryChannel::$sent)->toHaveCount(1)
        ->and(tfSentCodes())->toBe([])
        ->and(TwoFactorAuthentication::query()->where('user_id', $user->id)->value('channel'))->toBe('fake');

    tfVerify(FakeDeliveryChannel::lastCode());
    $this->assertAuthenticatedAs($user);
});

it('refuses a pending challenge of another channel than the user has now', function () {
    Event::fake([TwoFactorFailed::class]);
    $user = tfEnforcedUser();
    ucRecord($user, 'fake');

    tfLogin();
    $code = FakeDeliveryChannel::lastCode();

    // The method is changed (or reset) while the code step is pending.
    TwoFactorAuthentication::query()->where('user_id', $user->id)->update(['channel' => 'email']);

    tfVerify($code)->assertSessionHasErrors(['code' => 'The code is no longer valid. Please request a new one.']);
    $this->assertGuest();
    Event::assertDispatched(TwoFactorFailed::class, fn (TwoFactorFailed $event) => $event->channel === 'fake'
        && $event->reason === 'expired');
});

it('treats an unexpected channel error as a failed delivery and keeps no code', function () {
    Event::fake([TwoFactorFailed::class, TwoFactorChallengeSent::class]);
    config(['orchid-2fa.resend.cooldown' => 0]);
    FakeDeliveryChannel::$failWith = new RuntimeException('gateway timeout');
    $user = tfEnforcedUser();
    ucRecord($user, 'fake');

    expect(fn () => app(ChallengeManager::class)->issue($user))
        ->toThrow(DeliveryFailedException::class, 'gateway timeout');

    expect(cache()->get('orchid-2fa:code:'.$user->id))->toBeNull()
        ->and($this->logHandler()->hasErrorThatContains('the two-factor code could not be sent'))->toBeTrue();
    Event::assertDispatched(TwoFactorFailed::class, fn (TwoFactorFailed $event) => $event->channel === 'fake'
        && $event->reason === 'delivery_failed');
    Event::assertNotDispatched(TwoFactorChallengeSent::class);

    // The login shows the delivery error as with the e-mail channel (spec §4.10 of 0.1).
    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    $this->get(route('platform.two-factor.challenge'))->assertSee('We could not send the code. Please try again later.');
});

it('counts the attempts before calling the channel', function () {
    Event::fake([TwoFactorChallengeSent::class, TwoFactorLockedOut::class]);
    $probe = new ProbeVerifierChannel;
    TwoFactor::extend('probe', fn () => $probe);
    $user = tfEnforcedUser();
    ucRecord($user, 'probe');
    $manager = app(ChallengeManager::class);

    $challenge = $manager->issue($user);

    expect($challenge->channel)->toBe('probe')
        ->and($manager->sendAvailableIn($user))->toBe(0)
        ->and($manager->activeChallenge($user))->toBeNull();
    // Nothing is sent by a verifier channel.
    Event::assertNotDispatched(TwoFactorChallengeSent::class);

    foreach (range(1, 4) as $i) {
        expect($manager->verify($user, $challenge, '000000'))->toBe(VerificationResult::Invalid);
    }

    expect($manager->attemptsLeft($user, $challenge))->toBe(1)
        ->and($manager->verify($user, $challenge, '000000'))->toBe(VerificationResult::LockedOut)
        ->and($probe->calls)->toBe(5);
    Event::assertDispatched(TwoFactorLockedOut::class, fn (TwoFactorLockedOut $event) => $event->channel === 'probe');

    // The attempts are used up: the channel is not asked any more, even for the right code.
    expect($manager->verify($user, $challenge, '424242'))->toBe(VerificationResult::Expired)
        ->and($probe->calls)->toBe(5);
});

it('keeps the confirmation of a record of another channel when the e-mail address changes', function () {
    $user = tfUser('old@example.com');
    ucRecord($user, 'fake', ['enabled_at' => now(), 'confirmed_at' => now()]);
    app(ChallengeManager::class)->issue($user);

    $user->forceFill(['email' => 'new@example.org'])->save();

    $record = TwoFactorAuthentication::query()->where('user_id', $user->id)->first();
    expect($record->confirmed_at)->not->toBeNull()
        ->and($record->trusted_devices_version)->toBe(1)
        // The active code is annulled whatever its channel; the old address is notified (spec 0.2 §5.11).
        ->and(cache()->get('orchid-2fa:code:'.$user->id))->toBeNull();
    Notification::assertSentOnDemandTimes(TwoFactorEmailChangedNotification::class, 1);
});

it('drops the confirmation of an e-mail record when the address changes', function () {
    $user = tfUser('old@example.com');
    ucRecord($user, 'email', ['enabled_at' => now(), 'confirmed_at' => now()]);

    $user->forceFill(['email' => 'new@example.org'])->save();

    expect(TwoFactorAuthentication::query()->where('user_id', $user->id)->value('confirmed_at'))->toBeNull();
});

it('shows the destination of the user channel in the reset layout', function () {
    $admin = tfUser('admin@example.com', [
        'platform.index' => true, 'platform.systems.users' => true, 'platform.systems.users.2fa-reset' => true,
    ]);
    $target = tfUser('target@example.com');
    ucRecord($target, 'fake', ['enabled_at' => now(), 'confirmed_at' => now()]);

    $this->actingAs($admin)
        ->get(route('platform.systems.users.edit', [$target]))
        ->assertOk()
        ->assertSee(ucMask($target).' (confirmed)', false)
        ->assertDontSee('t***@example.com');
});

it('shows and uses the user channel on the profile screen', function () {
    $user = tfUser();
    ucRecord($user, 'fake');
    $mask = ucMask($user);
    $this->actingAs($user);

    $this->get(route('platform.profile.two-factor'))
        ->assertOk()
        ->assertSee($mask, false)
        ->assertDontSee('u***@example.com');

    $url = fn (string $method) => route('platform.profile.two-factor', ['method' => $method]);

    $this->from(route('platform.profile.two-factor'))->post($url('sendEnableCode'))
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'A verification code has been sent to '.$mask.'.');

    expect(FakeDeliveryChannel::$sent)->toHaveCount(1)
        ->and(tfSentCodes())->toBe([]);

    $this->from(route('platform.profile.two-factor'))->post($url('enable'), ['code' => FakeDeliveryChannel::lastCode()])
        ->assertSessionHasNoErrors()
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Two-factor authentication is enabled.');

    $record = TwoFactorAuthentication::query()->where('user_id', $user->id)->first();
    expect($record->enabled_at)->not->toBeNull()
        ->and($record->channel)->toBe('fake');
});

it('does not accept a pending login of 0.1.1 without the channel', function () {
    $session = app('session')->driver();
    $session->put(PendingLogin::SESSION_KEY, [
        'user_id' => 5, 'remember' => false, 'created_at' => now()->getTimestamp(), 'challenge_id' => 'challenge',
        'password_hash' => 'fingerprint',
    ]);

    expect(PendingLogin::fromSession($session))->toBeNull();
});

it('reads the default channel only in the registry', function () {
    $root = dirname(__DIR__, 3).'/src';
    $offenders = [];

    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php' || str_ends_with($file->getPathname(), '/Channels/ChannelRegistry.php')) {
            continue;
        }

        if (preg_match('/orchid-2fa\.channel[\'"]/', (string) file_get_contents($file->getPathname())) === 1) {
            $offenders[] = substr($file->getPathname(), strlen($root) + 1);
        }
    }

    expect($offenders)->toBe([]);
});
