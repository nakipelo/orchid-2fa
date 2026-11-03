<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;
use Nakipelo\Orchid2FA\Notifications\TwoFactorSecurityNotification;
use Nakipelo\Orchid2FA\Recovery\RecoveryCodes;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierChannel;
use Nakipelo\Orchid2FA\TwoFactorManager;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §4.4, §5.2 item 5, §8.3, §10.1 "verifier limits": per pending, the window of the user,
 * the daily ceiling, the notice about guessing.
 */
beforeEach(function () {
    Notification::fake();
    tfUseFake();
});

/**
 * @return Collection<int, TwoFactorSecurityNotification>
 */
function vlAlerts(string $event = 'attempts_exceeded'): Collection
{
    return Notification::sent(new AnonymousNotifiable, TwoFactorSecurityNotification::class)
        ->filter(fn (TwoFactorSecurityNotification $notification) => $notification->event === $event)
        ->values();
}

it('refuses a wrong code with the attempts left and counts it before asking the driver', function () {
    Event::fake([TwoFactorFailed::class]);
    $user = tfFakeUser();
    tfLogin();

    tfVerify(tfWrongFakeCode($user))
        ->assertRedirect(route('platform.two-factor.challenge'))
        ->assertSessionHasErrors(['code' => 'The code is incorrect. Attempts left: 4.']);

    Event::assertDispatched(TwoFactorFailed::class, fn ($event) => $event->reason === 'invalid_code' && $event->channel === 'fake');
});

it('drops the pending login after the 5th wrong code of a verifier challenge', function () {
    Event::fake([TwoFactorLockedOut::class]);
    $user = tfFakeUser();
    tfLogin();

    foreach (range(1, 4) as $ignored) {
        tfVerify(tfWrongFakeCode($user))->assertSessionHasErrors('code');
    }

    tfVerify(tfWrongFakeCode($user))
        ->assertRedirect(route('platform.login'))
        ->assertSessionHasErrors(['email' => 'Too many wrong codes. Please sign in again.']);

    expect(session()->has('orchid-2fa.pending'))->toBeFalse();
    Event::assertDispatched(TwoFactorLockedOut::class, fn ($event) => $event->reason === 'attempts_exceeded' && $event->channel === 'fake');

    tfVerify(tfFakeCode($user))->assertRedirect(route('platform.login'));
    $this->assertGuest();
});

it('limits the user across pending logins and keeps the pending login (window)', function () {
    Event::fake([TwoFactorLockedOut::class]);
    $user = tfFakeUser();

    // A new pending login does not reset the window: 4 + 4 + 2 wrong codes.
    foreach ([4, 4, 2] as $count) {
        $this->newBrowser();
        tfLogin();

        foreach (range(1, $count) as $ignored) {
            $response = tfVerify(tfWrongFakeCode($user));
        }
    }

    $response->assertSessionHasErrors(['code' => 'Too many wrong codes. Please try again in 10 min.']);
    expect(session()->has('orchid-2fa.pending'))->toBeTrue();
    Event::assertDispatched(TwoFactorLockedOut::class, fn ($event) => $event->reason === 'user_attempts_exceeded'
        && $event->availableIn > 500 && $event->availableIn <= 600);

    // Even the right code is refused without asking the driver, and the pending login stays.
    // (A minute later: the per-IP throttle of the route allows 10 requests per minute.)
    $this->travel(61)->seconds();
    tfVerify(tfFakeCode($user))->assertSessionHasErrors(['code' => 'Too many wrong codes. Please try again in 9 min.']);
    $this->assertGuest();
    expect(session()->has('orchid-2fa.pending'))->toBeTrue();

    // The notice about guessing: once per window.
    expect(vlAlerts())->toHaveCount(1)
        ->and(vlAlerts()->first()->context)->toMatchArray(['channel' => 'fake', 'limit' => 'window']);

    $this->travel(540)->seconds();
    $this->newBrowser();
    tfLogin();
    tfVerify(tfFakeCode($user))->assertRedirect(route('platform.main'));
    $this->assertAuthenticatedAs($user);
});

it('counts only wrong codes against the user limits', function () {
    $user = tfFakeUser();
    $manager = app(ChallengeManager::class);
    $channel = $manager->channelFor($user);

    foreach (range(1, 3) as $i) {
        $this->travel(FakeVerifierChannel::STEP)->seconds();
        expect($manager->verify($user, $manager->issue($user, 'login', $channel), tfFakeCode($user)))->toBe(VerificationResult::Passed);
    }

    expect(cache()->get('orchid-2fa:verifier:'.$user->id))->toBe(0);
});

it('has a daily ceiling shared with the recovery codes', function () {
    Event::fake([TwoFactorLockedOut::class]);
    config(['orchid-2fa.verify.user_max_attempts' => 1000]);
    $user = tfFakeUser();
    app(RecoveryCodes::class)->generate($user);
    $manager = app(ChallengeManager::class);
    $channel = $manager->channelFor($user);

    foreach (range(1, 14) as $i) {
        $challenge = $manager->issue($user, 'login', $channel);
        $manager->verify($user, $challenge, tfWrongFakeCode($user));
        $manager->verifyRecoveryCode($user, $challenge, 'aaaa-aaaa');
    }

    $challenge = $manager->issue($user, 'login', $channel);
    expect($manager->verify($user, $challenge, tfWrongFakeCode($user)))->toBe(VerificationResult::Invalid)
        ->and($manager->verifyRecoveryCode($user, $challenge, 'aaaa-aaaa'))->toBe(VerificationResult::LockedOut)
        ->and($manager->lockout())->toMatchArray(['reason' => 'user_daily_attempts_exceeded']);

    Event::assertDispatched(TwoFactorLockedOut::class, fn ($event) => $event->reason === 'user_daily_attempts_exceeded'
        && $event->availableIn > 86000);

    $this->newBrowser();
    tfLogin();
    tfVerify(tfFakeCode($user))->assertSessionHasErrors(['code' => 'Too many wrong codes today. Please try again in 24 h.']);
    expect(vlAlerts())->toHaveCount(1)
        ->and(vlAlerts()->first()->context['limit'])->toBe('day');

    // The ceiling is fixed: 24 h after the first attempt it is over.
    $this->travel(86401)->seconds();
    $this->newBrowser();
    tfLogin();
    tfVerify(tfFakeCode($user))->assertRedirect(route('platform.main'));
});

it('does not send the notice about guessing when the security notices are off', function () {
    config(['orchid-2fa.notification.security.enabled' => false]);
    $user = tfFakeUser();
    $manager = app(ChallengeManager::class);

    foreach (range(1, 3) as $i) {
        $challenge = $manager->issue($user);

        foreach (range(1, 4) as $j) {
            $manager->verify($user, $challenge, tfWrongFakeCode($user));
        }
    }

    expect($manager->lockout()['reason'] ?? null)->toBe('user_attempts_exceeded')
        ->and(vlAlerts())->toBeEmpty();
});

it('refuses "send again" for a verifier method: it would only reset the attempts', function () {
    $user = tfFakeUser();
    tfLogin();
    $challenge = session('orchid-2fa.pending.challenge_id');

    $this->post(route('platform.two-factor.resend'))
        ->assertRedirect(route('platform.two-factor.challenge'))
        ->assertSessionHas('orchid-2fa.error', 'Your sign-in method does not send codes.');

    expect(session('orchid-2fa.pending.challenge_id'))->toBe($challenge);
});

it('clears the user limits and the marker of the notice on reset', function () {
    $user = tfFakeUser();
    $manager = app(ChallengeManager::class);

    foreach (range(1, 3) as $i) {
        $challenge = $manager->issue($user);

        foreach (range(1, 4) as $j) {
            $manager->verify($user, $challenge, tfWrongFakeCode($user));
        }
    }

    expect(cache()->has('orchid-2fa:verifier:'.$user->id))->toBeTrue();

    app(TwoFactorManager::class)->reset($user);

    foreach (['verifier', 'verifier-day', 'alert'] as $key) {
        expect(cache()->has('orchid-2fa:'.$key.':'.$user->id))->toBeFalse();
    }
});

it('refuses a code when the driver throws (fail-closed) and logs it', function () {
    $user = tfFakeUser();
    tfLogin();
    FakeVerifierChannel::$failWith = new RuntimeException('broken');

    tfVerify(tfFakeCode($user))->assertSessionHasErrors('code');

    $this->assertGuest();
    expect($this->logHandler()->hasErrorThatContains('the two-factor channel failed to verify a code'))->toBeTrue();
});
