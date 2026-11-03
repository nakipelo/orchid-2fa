<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;
use Nakipelo\Orchid2FA\Support\Orchid;
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

it('rotates the remember token only when the record is created', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $token = $user->refresh()->remember_token;
    expect($token)->not->toBeNull();

    $this->post(route('platform.two-factor.cancel'));
    tfLogin();

    expect($user->refresh()->remember_token)->toBe($token);
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
