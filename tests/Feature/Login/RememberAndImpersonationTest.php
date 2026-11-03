<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Facades\TwoFactor;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TwoFactorManager;
use Orchid\Access\Impersonation;
use Orchid\Support\Facades\Dashboard;

uses(RefreshDatabase::class);

/**
 * Spec §4.5 (without the rotation on voluntary enablement — stage 4) and §4.6.
 */
beforeEach(function () {
    Notification::fake();
});

/**
 * A new browser: no session, no logged-in user in memory.
 */
function tfNewBrowser(): void
{
    test()->newBrowser();
}

it('issues the remember cookie only after the code', function () {
    $user = tfEnforcedUser();
    $recaller = Orchid::guard()->getRecallerName();

    tfLogin(extra: ['remember' => 'true'])
        ->assertCookieMissing($recaller)
        ->assertCookieMissing(Orchid::lockCookieName());

    tfVerify(tfLastCode())
        ->assertRedirect(route('platform.main'))
        ->assertCookie($recaller)
        ->assertCookie(Orchid::lockCookieName(), (string) $user->id);
});

it('does not ask for the code on a visit with the remember cookie', function () {
    $user = tfEnforcedUser();
    $recaller = Orchid::guard()->getRecallerName();
    tfLogin(extra: ['remember' => 'true']);
    $value = tfVerify(tfLastCode())->getCookie($recaller)?->getValue();
    expect($value)->not->toBeNull();

    tfNewBrowser();
    $this->withCookie($recaller, $value)->get(route('platform.profile'))->assertOk();

    $this->assertAuthenticatedAs($user);
    expect(Orchid::guard()->viaRemember())->toBeTrue();
    Notification::assertSentOnDemandTimes(TwoFactorCodeNotification::class, 1);
});

it('does not remember without the remember flag', function () {
    tfEnforcedUser();
    tfLogin();

    tfVerify(tfLastCode())
        ->assertCookieMissing(Orchid::guard()->getRecallerName())
        ->assertCookieMissing(Orchid::lockCookieName());
});

it('stops an old remember cookie once 2FA becomes required', function () {
    $user = tfUser();
    $user->forceFill(['remember_token' => 'old-token'])->save();
    $recaller = Orchid::guard()->getRecallerName();
    $cookie = $user->id.'|old-token|'.$user->password;

    // The cookie issued before the package works…
    $this->withCookie($recaller, $cookie)->get(route('platform.profile'))->assertOk();
    $this->assertAuthenticatedAs($user);

    // …until 2FA is required and the first challenge creates the record (spec §4.5, §4.7).
    $user->forceFill(['permissions' => ['platform.index' => true, 'platform.2fa.required' => true]])->save();
    tfNewBrowser();
    tfLogin('user@example.com')->assertRedirect(route('platform.two-factor.challenge'));
    expect($user->refresh()->remember_token)->not->toBe('old-token');

    tfNewBrowser();
    $this->withCookie($recaller, $cookie)->get(route('platform.main'))->assertRedirect(route('platform.login'));
    $this->assertGuest();
});

/**
 * Signs the user in without the second factor, with "remember me", and returns the remember cookie.
 */
function rmRememberCookieWithout2FA(string $email = 'user@example.com'): string
{
    $cookie = tfLogin($email, extra: ['remember' => 'true'])
        ->assertRedirect(route('platform.main'))
        ->getCookie(Orchid::guard()->getRecallerName())?->getValue();
    expect($cookie)->not->toBeNull();
    tfNewBrowser();

    return (string) $cookie;
}

function rmAssertCookieRejected(string $cookie): void
{
    test()->withCookie(Orchid::guard()->getRecallerName(), $cookie)
        ->get(route('platform.main'))
        ->assertRedirect(route('platform.login'));
    test()->assertGuest();
    tfNewBrowser();
}

it('stops an old remember cookie once 2FA becomes required for a user with an existing record', function () {
    // The record stays after the user enabled and disabled 2FA (confirmed_at = null).
    $user = tfUser();
    $manager = app(TwoFactorManager::class);
    $manager->commitEnrollment($user, TwoFactor::channel('email'), 'enrolled', true);
    $manager->disable($user);
    expect(TwoFactorAuthentication::query()->where('user_id', $user->id)->exists())->toBeTrue();

    $cookie = rmRememberCookieWithout2FA();
    $token = $user->refresh()->remember_token;

    $user->forceFill(['permissions' => ['platform.index' => true, 'platform.2fa.required' => true]])->save();
    tfLogin('user@example.com')->assertRedirect(route('platform.two-factor.challenge'));
    tfNewBrowser();

    expect($user->refresh()->remember_token)->not->toBe($token);
    rmAssertCookieRejected($cookie);
});

it('stops an old remember cookie when the permission is taken away and granted again', function () {
    $user = tfEnforcedUser('user@example.com');
    tfLogin('user@example.com');
    tfVerify(tfLastCode())->assertRedirect(route('platform.main'));
    tfNewBrowser();
    expect(TwoFactorAuthentication::query()->where('user_id', $user->id)->value('confirmed_at'))->not->toBeNull();

    // Not enforced for a while: the sign-in without the code issues a remember cookie…
    $user->forceFill(['permissions' => ['platform.index' => true]])->save();
    $cookie = rmRememberCookieWithout2FA();
    expect(TwoFactorAuthentication::query()->where('user_id', $user->id)->value('confirmed_at'))->toBeNull();

    // …which stops working at the first challenge after the permission comes back.
    $user->forceFill(['permissions' => ['platform.index' => true, 'platform.2fa.required' => true]])->save();
    $this->travel(61)->seconds();
    tfLogin('user@example.com')->assertRedirect(route('platform.two-factor.challenge'));
    tfNewBrowser();

    rmAssertCookieRejected($cookie);
});

it('stops old remember cookies of users with existing records once enforce_all is turned on', function () {
    $disabled = tfUser('disabled@example.com');
    $manager = app(TwoFactorManager::class);
    $manager->commitEnrollment($disabled, TwoFactor::channel('email'), 'enrolled', true);
    $manager->disable($disabled);
    $reset = tfUser('reset@example.com');
    TwoFactorAuthentication::query()->create(['user_id' => $reset->id, 'confirmed_at' => now()]);

    $cookies = [
        'disabled@example.com' => rmRememberCookieWithout2FA('disabled@example.com'),
        'reset@example.com' => rmRememberCookieWithout2FA('reset@example.com'),
    ];

    config(['orchid-2fa.enforce_all' => true]);

    foreach ($cookies as $email => $cookie) {
        tfLogin($email)->assertRedirect(route('platform.two-factor.challenge'));
        tfNewBrowser();
        rmAssertCookieRejected($cookie);
    }
});

it('rotates the remember token at every challenge while the record is not confirmed', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $token = $user->refresh()->remember_token;
    expect($token)->not->toBeNull();

    $this->post(route('platform.two-factor.cancel'));
    tfLogin();

    expect($user->refresh()->remember_token)->not->toBe($token);
});

it('keeps the remember cookie of a confirmed user on later sign-ins', function () {
    $user = tfEnforcedUser();
    $recaller = Orchid::guard()->getRecallerName();
    tfLogin(extra: ['remember' => 'true']);
    $cookie = tfVerify(tfLastCode())->getCookie($recaller)?->getValue();
    expect($cookie)->not->toBeNull();
    $token = $user->refresh()->remember_token;

    // Another browser signs in with the password and a new code.
    tfNewBrowser();
    $this->travel(61)->seconds();
    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    tfVerify(tfLastCode())->assertRedirect(route('platform.main'));
    tfNewBrowser();

    expect($user->refresh()->remember_token)->toBe($token);
    $this->withCookie($recaller, (string) $cookie)->get(route('platform.profile'))->assertOk();
    $this->assertAuthenticatedAs($user);
});

it('does not ask for the code on impersonation and switching back', function () {
    $admin = tfUser('admin@example.com', Dashboard::getAllowAllPermission()->all());
    $target = tfEnforcedUser();

    $this->actingAs($admin)
        ->post(route('platform.systems.users.edit', [$target, 'method' => 'loginAs']))
        ->assertRedirect(route('platform.main'));

    $this->assertAuthenticatedAs($target);
    expect(Impersonation::isSwitch())->toBeTrue();
    $this->get(route('platform.profile'))->assertOk();

    $this->get('/admin/switch-logout')->assertRedirect(route('platform.main'));
    $this->assertAuthenticatedAs($admin);

    Notification::assertNothingSent();
});
