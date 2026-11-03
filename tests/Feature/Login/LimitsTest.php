<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Testing\TestResponse;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;

uses(RefreshDatabase::class);

/**
 * Spec §4.11: resend cooldown, hourly send limit, attempts, per-IP throttle.
 */
beforeEach(function () {
    // Exact countdown values: no second may pass between the requests.
    $this->freezeTime();
    Notification::fake();
    // Keep the pending login alive across the hour of the hourly limit test.
    config(['orchid-2fa.pending_ttl' => 7200]);
});

function tfResend(): TestResponse
{
    return test()->from('/admin/two-factor')->post('/admin/two-factor/resend');
}

it('does not resend before the cooldown is over', function () {
    Event::fake([TwoFactorLockedOut::class]);
    $user = tfEnforcedUser();
    tfLogin();

    $this->travel(30)->seconds();

    tfResend()->assertRedirect(route('platform.two-factor.challenge'))
        ->assertSessionHas('orchid-2fa.error', 'Too many codes have been requested. Please try again later (in 1 min).');

    Notification::assertSentOnDemandTimes(TwoFactorCodeNotification::class, 1);
    Event::assertDispatched(TwoFactorLockedOut::class, fn ($e) => $e->user->is($user)
        && $e->reason === 'send_limit' && $e->availableIn === 30);

    $this->get(route('platform.two-factor.challenge'))
        ->assertSee('Too many codes have been requested. Please try again later (in 1 min).')
        ->assertSee('data-available-in="30"', false)
        ->assertSee('Send again in 0:30');
});

it('resends after the cooldown and annuls the previous code', function () {
    Event::fake([TwoFactorChallengeSent::class]);
    tfEnforcedUser();
    tfLogin();
    $first = tfLastCode();

    $this->travel(61)->seconds();
    $this->get(route('platform.two-factor.challenge'))
        ->assertSee('data-available-in="0"', false)
        ->assertDontSee('Send again in 0:')
        ->assertSee('Send the code again');

    tfResend()->assertRedirect(route('platform.two-factor.challenge'))
        ->assertSessionHas('orchid-2fa.status', 'A new code has been sent.');

    $codes = tfSentCodes();
    expect($codes)->toHaveCount(2);
    Event::assertDispatchedTimes(TwoFactorChallengeSent::class, 2);

    // The previous code is not valid for the new challenge.
    if ($first !== $codes[1]) {
        tfVerify($first)->assertSessionHasErrors(['code' => 'The code is incorrect. Attempts left: 4.']);
        $this->assertGuest();
    }

    tfVerify($codes[1])->assertRedirect(route('platform.main'));
    $this->assertAuthenticated();
});

it('limits sends per hour, counting the login send', function () {
    Event::fake([TwoFactorLockedOut::class]);
    tfEnforcedUser();
    tfLogin();

    foreach (range(1, 4) as $i) {
        $this->travel(61)->seconds();
        tfResend()->assertSessionHas('orchid-2fa.status');
    }

    expect(tfSentCodes())->toHaveCount(5);

    $this->travel(61)->seconds();
    tfResend()->assertSessionHas('orchid-2fa.error', 'Too many codes have been requested. Please try again later (in 55 min).');

    expect(tfSentCodes())->toHaveCount(5);
    Event::assertDispatched(TwoFactorLockedOut::class, fn ($e) => $e->reason === 'send_limit' && $e->availableIn === 3600 - 5 * 61);

    // The countdown takes the hourly limit into account.
    $this->get(route('platform.two-factor.challenge'))->assertSee('data-available-in="'.(3600 - 5 * 61).'"', false);

    $this->travel(3600)->seconds();
    tfResend()->assertSessionHas('orchid-2fa.status');
    expect(tfSentCodes())->toHaveCount(6);
});

it('applies the send limits to a new login too', function () {
    tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();

    // Exhaust the attempts: the code is annulled, the cooldown is still running.
    foreach (range(1, 5) as $i) {
        tfVerify(tfWrongCode($code));
    }
    $this->post(route('platform.two-factor.cancel'));

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));

    expect(tfSentCodes())->toHaveCount(1);
    $this->get(route('platform.two-factor.challenge'))
        ->assertSee('Too many codes have been requested. Please try again later (in 1 min).');
    $this->assertGuest();
});

it('does not count the sends of other users', function () {
    tfEnforcedUser('a@example.com');
    tfEnforcedUser('b@example.com');

    tfLogin('a@example.com');
    $this->post(route('platform.two-factor.cancel'));
    tfLogin('b@example.com');

    expect(tfSentCodes('a@example.com'))->toHaveCount(1)
        ->and(tfSentCodes('b@example.com'))->toHaveCount(1);
});

it('reports when the next send is available', function () {
    $user = tfEnforcedUser();
    $manager = app(ChallengeManager::class);

    expect($manager->sendAvailableIn($user))->toBe(0);
    $manager->issue($user);
    expect($manager->sendAvailableIn($user))->toBe(60);
});

it('throttles verify and resend per IP with the configured limit', function () {
    tfEnforcedUser();
    tfLogin();
    $wrong = tfWrongCode(tfLastCode());

    $route = app('router')->getRoutes()->getByName('platform.two-factor.verify');
    expect($route->gatherMiddleware())->toContain('throttle:10,1,orchid-2fa')
        ->and(app('router')->getRoutes()->getByName('platform.two-factor.resend')->gatherMiddleware())
        ->toContain('throttle:10,1,orchid-2fa');

    // 4 wrong codes + 6 resends (blocked by the cooldown) = 10 requests per minute.
    foreach (range(1, 4) as $i) {
        tfVerify($wrong)->assertSessionHasErrors('code');
    }
    foreach (range(1, 6) as $i) {
        tfResend()->assertRedirect(route('platform.two-factor.challenge'));
    }

    tfVerify($wrong)->assertTooManyRequests();
    tfResend()->assertTooManyRequests();

    // The login keeps its own throttle counter.
    $this->post(route('platform.two-factor.cancel'));
    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
});
