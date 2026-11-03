<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Events\TwoFactorChannelChanged;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Recovery\RecoveryCodes;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierChannel;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §5.4 (A and B), §6.4, §10.1 "enrollment at the login".
 */
beforeEach(function () {
    Notification::fake();
    tfUseFake(['fake']);
});

function elSecret(User $user): string
{
    $state = EnrollmentState::fromSession(session()->driver(), $user, 'fake', 'enroll', 900);

    expect($state)->not->toBeNull();

    return (string) $state->get('secret');
}

it('enrolls a user without a method only with the password (A) and shows the codes once', function () {
    Event::fake([TwoFactorPassed::class, TwoFactorChannelChanged::class]);
    $user = tfEnforcedUser();
    $user->forceFill(['remember_token' => 'old-token'])->save();

    tfLogin(extra: ['remember' => '1'])->assertRedirect(route('platform.two-factor.enroll'));
    expect($user->refresh()->remember_token)->not->toBe('old-token');

    // One allowed channel: straight to its step.
    $this->get(route('platform.two-factor.enroll'))->assertRedirect(route('platform.two-factor.enroll', ['channel' => 'fake']));
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']))
        ->assertOk()
        ->assertSee('data-fake-enrollment', false)
        ->assertSee('name="code"', false)
        ->assertDontSee('name="trust_device"', false)
        ->assertSee(route('platform.two-factor.cancel'), false);
    $secret = elSecret($user);

    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => FakeVerifierChannel::codeFor($secret) === '000000' ? '111111' : '000000'])
        ->assertSessionHasErrors(['code' => 'The code is incorrect. Attempts left: 4.']);
    expect(app(FakeVerifierChannel::class)->isAvailableFor($user))->toBeFalse();

    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => FakeVerifierChannel::codeFor($secret)])
        ->assertRedirect(route('platform.two-factor.recovery-codes'));
    $this->assertGuest();

    $record = TwoFactorAuthentication::query()->where('user_id', $user->id)->first();
    expect($record->channel)->toBe('fake')
        ->and($record->confirmed_at)->not->toBeNull()
        ->and($record->enabled_at)->toBeNull()
        ->and(app(RecoveryCodes::class)->remaining($user))->toBe(8);
    Event::assertDispatched(TwoFactorChannelChanged::class, fn ($event) => $event->from === null && $event->to === 'fake' && $event->reason === 'enrolled');

    // Protected by the password only (A): no trust checkbox, no cookie even when asked for.
    $codes = session('orchid-2fa.recovery_codes.codes');
    $this->get(route('platform.two-factor.recovery-codes'))
        ->assertOk()
        ->assertSee($codes[0])
        ->assertDontSee('name="trust_device"', false)
        ->assertSee('I have saved the codes');

    $response = $this->post(route('platform.two-factor.recovery-codes.confirm'), ['trust_device' => '1']);

    $response->assertRedirect(route('platform.main'))
        ->assertCookieMissing(app(TrustedDeviceCookie::class)->name($user->id));
    $this->assertAuthenticatedAs($user);
    expect(session()->has('orchid-2fa.recovery_codes'))->toBeFalse();
    Event::assertDispatched(TwoFactorPassed::class, fn ($event) => $event->via === 'enrollment' && ! $event->trustedDeviceIssued && $event->channel === 'fake');

    // Shown once: the codes page is gone with the pending login.
    $this->newBrowser();
    $this->get(route('platform.two-factor.recovery-codes'))->assertRedirect(route('platform.login'));
});

it('offers a choice when several channels are allowed', function () {
    config(['orchid-2fa.channels.allowed' => ['fake', 'email'], 'orchid-2fa.channel' => 'fake']);
    tfEnforcedUser();

    tfLogin()->assertRedirect(route('platform.two-factor.enroll'));

    $this->get(route('platform.two-factor.enroll'))
        ->assertOk()
        ->assertSee(route('platform.two-factor.enroll', ['channel' => 'fake']), false)
        ->assertSee(route('platform.two-factor.enroll', ['channel' => 'email']), false)
        ->assertSee('Fake authenticator')
        ->assertSee('E-mail');

    // E-mail: the code to the address, no recovery codes; no trust checkbox without a method (A).
    $this->get(route('platform.two-factor.enroll', ['channel' => 'email']))
        ->assertOk()
        ->assertSee('We have sent a code to e***@example.com.')
        ->assertDontSee('name="trust_device"', false);

    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'email']), ['code' => tfLastCode()])
        ->assertRedirect(route('platform.main'));

    expect(TwoFactorAuthentication::query()->value('channel'))->toBe('email')
        ->and(app(RecoveryCodes::class)->remaining(User::query()->first()))->toBe(0);
});

it('refuses a channel that is not allowed', function () {
    tfEnforcedUser();
    tfLogin();

    $this->get(route('platform.two-factor.enroll', ['channel' => 'email']))->assertRedirect(route('platform.two-factor.enroll', ['channel' => 'fake']));
    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'email']), ['code' => '123456'])
        ->assertRedirect(route('platform.two-factor.enroll'));
    expect(tfSentCodes())->toBe([]);
});

it('gives the enrollment enrollment_ttl from its start instead of pending_ttl', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']))->assertOk();

    // Longer than pending_ttl (600 s), shorter than enrollment_ttl (900 s).
    $this->travel(700)->seconds();
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']))->assertOk();
    $secret = elSecret($user);

    $this->travel(201)->seconds();
    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => FakeVerifierChannel::codeFor($secret)])
        ->assertRedirect(route('platform.login'))
        ->assertSessionHasErrors(['email' => 'Your sign-in session has expired. Please sign in again.']);
    expect(session()->has('orchid-2fa.pending'))->toBeFalse();
});

it('starts the enrollment deadline when the proof is passed (B)', function () {
    $user = tfEnforcedUser();
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'channel' => 'email', 'confirmed_at' => now()]);
    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    $this->travel(500)->seconds();

    tfVerify(tfLastCode())->assertRedirect(route('platform.two-factor.enroll'));

    // 500 + 800 > pending_ttl, but the step started at the proof.
    $this->travel(800)->seconds();
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']))->assertOk();
});

it('checks the password fingerprint at every step', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']))->assertOk();

    $user->forceFill(['password' => Hash::make('changed')])->save();

    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']))
        ->assertRedirect(route('platform.login'))
        ->assertSessionHasErrors(['email' => 'Your password has been changed. Please sign in again.']);
});

it('drops the pending login after 5 wrong enrollment codes', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']));
    $wrong = FakeVerifierChannel::codeFor(elSecret($user)) === '000000' ? '111111' : '000000';

    foreach (range(1, 4) as $ignored) {
        $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => $wrong])->assertSessionHasErrors('code');
    }

    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => $wrong])
        ->assertRedirect(route('platform.login'))
        ->assertSessionHasErrors(['email' => 'Too many wrong codes. Please sign in again.']);
    expect(session()->has('orchid-2fa.pending'))->toBeFalse();
});

it('answers 406 to JSON on the enrollment and recovery code routes without changing the pending login', function (string $method, string $route, array $parameters) {
    tfEnforcedUser();
    tfLogin();
    $pending = session('orchid-2fa.pending');

    $this->json($method, route($route, $parameters))
        ->assertStatus(406)
        ->assertJson(['message' => 'This step is available only in a browser.'])
        ->assertJsonStructure(['redirect']);

    expect(session('orchid-2fa.pending'))->toBe($pending);
})->with([
    'GET enroll' => ['GET', 'platform.two-factor.enroll', []],
    'POST enroll' => ['POST', 'platform.two-factor.enroll.confirm', ['channel' => 'fake']],
    'GET recovery-codes' => ['GET', 'platform.two-factor.recovery-codes', []],
    'POST recovery-codes' => ['POST', 'platform.two-factor.recovery-codes.confirm', []],
]);

it('moves the users of e-mail to the allowed method after an e-mail code (mass switch, §11)', function () {
    Event::fake([TwoFactorChannelChanged::class]);
    $user = tfEnforcedUser();
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'channel' => 'email', 'confirmed_at' => now()]);

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    tfVerify(tfLastCode())->assertRedirect(route('platform.two-factor.enroll'));

    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']))
        ->assertSee('Your current sign-in method is no longer available.');
    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => FakeVerifierChannel::codeFor(elSecret($user))])
        ->assertRedirect(route('platform.two-factor.recovery-codes'));
    $this->post(route('platform.two-factor.recovery-codes.confirm'))->assertRedirect(route('platform.main'));

    expect(TwoFactorAuthentication::query()->where('user_id', $user->id)->value('channel'))->toBe('fake');
    Event::assertDispatched(TwoFactorChannelChanged::class, fn ($event) => $event->from === 'email' && $event->to === 'fake' && $event->reason === 'enrolled');
});

it('continues with the enrollment after a recovery code, without the trust checkbox (B)', function () {
    config(['orchid-2fa.channels.allowed' => ['email']]);
    $user = tfFakeUser();
    $codes = app(RecoveryCodes::class)->generate($user);

    tfLogin();
    $this->post(route('platform.two-factor.recovery'), ['recovery_code' => $codes[0], 'trust_device' => '1'])
        ->assertRedirect(route('platform.two-factor.enroll'));
    expect(session('orchid-2fa.pending.via'))->toBe('recovery_code');

    $this->get(route('platform.two-factor.enroll', ['channel' => 'email']))
        ->assertOk()
        ->assertDontSee('name="trust_device"', false);

    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'email']), ['code' => tfLastCode(), 'trust_device' => '1'])
        ->assertRedirect(route('platform.main'))
        ->assertCookieMissing(app(TrustedDeviceCookie::class)->name($user->id));

    // Switching from the fake to e-mail erased the fake's data and the recovery codes.
    expect(TwoFactorAuthentication::query()->where('user_id', $user->id)->value('channel'))->toBe('email')
        ->and(app(FakeVerifierChannel::class)->isAvailableFor($user))->toBeFalse()
        ->and(app(RecoveryCodes::class)->exists($user))->toBeFalse();
});

it('sends the code of a delivery enrollment again on request', function () {
    config(['orchid-2fa.channels.allowed' => ['fake', 'email'], 'orchid-2fa.channel' => 'fake']);
    tfEnforcedUser();
    tfLogin();
    $this->get(route('platform.two-factor.enroll', ['channel' => 'email']));
    $this->travel(61)->seconds();

    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'email']), ['resend' => '1'])
        ->assertRedirect(route('platform.two-factor.enroll', ['channel' => 'email']))
        ->assertSessionHas('orchid-2fa.status', 'A new code has been sent.');

    expect(tfSentCodes())->toHaveCount(2);
    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'email']), ['code' => tfLastCode()])->assertRedirect(route('platform.main'));
});
