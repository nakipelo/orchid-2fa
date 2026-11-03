<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Facades\TwoFactor;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Policy\TwoFactorPolicy;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §4.5 (all four branches), §5.2, §10.1 "the user's method".
 */
beforeEach(function () {
    Notification::fake();
    tfUseFake();
});

it('signs in with the enrolled and allowed verifier method (item 1, §5.2)', function () {
    Event::fake([TwoFactorPassed::class]);
    $user = tfFakeUser();

    expect(TwoFactor::methodFor($user)->state)->toBe('active')
        ->and(app(TwoFactorPolicy::class)->channel($user))->toBe('fake');

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    expect(tfSentCodes())->toBe([]);

    $this->get(route('platform.two-factor.challenge'))
        ->assertOk()
        ->assertSee('Enter the code from your authenticator app.')
        ->assertDontSee(route('platform.two-factor.resend'), false)
        ->assertSee(route('platform.two-factor.recovery'), false)
        ->assertSee('Use a recovery code')
        ->assertDontSee(route('platform.two-factor.fallback'), false);

    tfVerify(tfFakeCode($user))->assertRedirect(route('platform.main'));
    $this->assertAuthenticatedAs($user);
    Event::assertDispatched(TwoFactorPassed::class, fn ($event) => $event->channel === 'fake' && $event->via === 'code');
});

it('answers JSON at the password step of a verifier method as for e-mail', function () {
    tfFakeUser();

    tfLogin(extra: [])->assertRedirect();
    $this->newBrowser();

    $this->postJson('/admin/login', ['email' => 'enforced@example.com', 'password' => 'password'])
        ->assertOk()
        ->assertExactJson(['two_factor' => true, 'redirect' => route('platform.two-factor.challenge')]);
});

it('uses an enrolled method that is no longer allowed as the proof, then asks to enroll (item 2, §5.4 B)', function () {
    config(['orchid-2fa.channels.allowed' => ['email']]);
    $user = tfFakeUser();

    expect(TwoFactor::methodFor($user)->state)->toBe('proof');

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    tfVerify(tfFakeCode($user))->assertRedirect(route('platform.two-factor.enroll'));
    $this->assertGuest();

    expect(session('orchid-2fa.pending.stage'))->toBe('enroll')
        ->and(session('orchid-2fa.pending.via'))->toBe('code');
});

it('answers JSON with enroll after the proof', function () {
    config(['orchid-2fa.channels.allowed' => ['email']]);
    $user = tfFakeUser();
    tfLogin();

    $this->postJson('/admin/two-factor', ['code' => tfFakeCode($user)])
        ->assertOk()
        ->assertExactJson(['two_factor' => true, 'enroll' => true, 'redirect' => route('platform.two-factor.enroll')]);
});

it('does not let a trusted device skip the enrollment of a no longer allowed method', function () {
    $user = tfFakeUser();
    tfLogin();
    $name = app(TrustedDeviceCookie::class)->name($user->id);
    $cookie = tfVerify(tfFakeCode($user), ['trust_device' => '1'])->getCookie($name)?->getValue();
    expect($cookie)->toBeString();
    $this->newBrowser();

    config(['orchid-2fa.channels.allowed' => ['email']]);

    $this->withCookie($name, (string) $cookie);
    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    $this->assertGuest();
});

it('fails closed when the driver of the method is gone (item 3)', function () {
    Event::fake([TwoFactorFailed::class]);
    $user = tfEnforcedUser();
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'channel' => 'totp', 'confirmed_at' => now()]);

    tfLogin()->assertSessionHasErrors(['email' => 'Your sign-in method is not available. Please contact your administrator.']);

    $this->assertGuest();
    expect(session()->has('orchid-2fa.pending'))->toBeFalse()
        ->and(tfSentCodes())->toBe([])
        ->and($this->logHandler()->hasErrorThatContains('the two-factor method of the user is not available'))->toBeTrue();
    Event::assertDispatched(TwoFactorFailed::class, fn ($event) => $event->reason === 'channel_unavailable' && $event->channel === 'totp');
});

it('enrolls at the login a user without a method when e-mail is not the default (item 4, §5.4 A)', function () {
    config(['orchid-2fa.channels.allowed' => ['fake']]);
    $user = tfEnforcedUser();

    expect(TwoFactor::methodFor($user)->state)->toBe('none')
        ->and(app(TwoFactorPolicy::class)->status($user))->toBe('not_enrolled');

    tfLogin()->assertRedirect(route('platform.two-factor.enroll'));
    expect(session('orchid-2fa.pending.via'))->toBeNull();

    $this->newBrowser();
    $this->postJson('/admin/login', ['email' => 'enforced@example.com', 'password' => 'password'])
        ->assertOk()
        ->assertExactJson(['two_factor' => true, 'enroll' => true, 'redirect' => route('platform.two-factor.enroll')]);
});

it('treats a not confirmed e-mail that is no longer allowed as no method (§5.4 A)', function () {
    config(['orchid-2fa.channels.allowed' => ['fake']]);
    $user = tfEnforcedUser();
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'channel' => 'email', 'confirmed_at' => null]);

    expect(TwoFactor::methodFor($user)->state)->toBe('none');

    tfLogin()->assertRedirect(route('platform.two-factor.enroll'));
    expect(tfSentCodes())->toBe([]);
});

it('falls back to the default e-mail for a method that is not enrolled', function () {
    $user = tfEnforcedUser();
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'channel' => 'fake']);

    expect(TwoFactor::for($user)?->name())->toBe('email');

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    expect(tfSentCodes())->toHaveCount(1);
});
