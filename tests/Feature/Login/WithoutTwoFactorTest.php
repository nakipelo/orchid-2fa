<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\SessionGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Challenge\PendingLogin;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Support\Orchid;

uses(RefreshDatabase::class);

/**
 * Spec §4.1, §4.3: a user without 2FA logs in exactly as with Orchid.
 */
beforeEach(function () {
    Notification::fake();
});

it('logs a user without 2FA in like Orchid', function () {
    $user = tfUser();

    tfLogin('user@example.com')->assertRedirect(route('platform.main'));

    $this->assertAuthenticatedAs($user);
    expect(session()->has(PendingLogin::SESSION_KEY))->toBeFalse()
        ->and(TwoFactorAuthentication::query()->count())->toBe(0);
    Notification::assertNothingSent();
});

it('redirects to the intended URL', function () {
    tfUser();

    $this->get('/admin/users')->assertRedirect(route('platform.login'));

    tfLogin('user@example.com')->assertRedirect('/admin/users');
});

it('regenerates the session on login', function () {
    tfUser();
    $this->get('/admin/login');
    $before = session()->getId();

    tfLogin('user@example.com');

    expect(session()->getId())->not->toBe($before);
});

it('sets the remember and lock cookies when asked to remember', function () {
    $user = tfUser();

    $response = tfLogin('user@example.com', extra: ['remember' => 'true']);

    $response->assertCookie(Orchid::lockCookieName(), (string) $user->id)
        ->assertCookie(Orchid::guard()->getRecallerName());
    expect(Orchid::lockCookieName())->toBe('login_web_'.sha1(SessionGuard::class).'__orchid_lock');
});

it('does not set the lock cookie without remember', function () {
    tfUser();

    tfLogin('user@example.com')
        ->assertCookieMissing(Orchid::lockCookieName())
        ->assertCookieMissing(Orchid::guard()->getRecallerName());
});

it('answers 204 to JSON clients', function () {
    tfUser();

    $this->postJson('/admin/login', ['email' => 'user@example.com', 'password' => 'password'])
        ->assertNoContent();

    $this->assertAuthenticated();
});

it('rejects wrong credentials with Orchid\'s message', function () {
    tfUser();

    tfLogin('user@example.com', 'wrong')
        ->assertRedirect('/admin/login')
        ->assertSessionHasErrors(['email' => Orchid::failedLoginMessage()]);

    tfLogin('nobody@example.com', 'password')
        ->assertSessionHasErrors(['email' => Orchid::failedLoginMessage()]);

    $this->assertGuest();
    expect(Orchid::failedLoginMessage())->toBe('The details you entered did not match our records. Please double-check and try again.');
});

it('validates the fields like Orchid', function () {
    tfLogin('', '')->assertSessionHasErrors(['email', 'password']);

    $this->postJson('/admin/login', ['email' => ['x'], 'password' => 'x'])
        ->assertUnprocessable()
        ->assertJsonValidationErrors('email');
});

it('fires Attempting and Login on success', function () {
    Event::fake([Attempting::class, Failed::class, Login::class]);
    $user = tfUser();

    tfLogin('user@example.com', extra: ['remember' => 'true']);

    Event::assertDispatched(Attempting::class, fn (Attempting $e) => $e->guard === 'web'
        && $e->credentials === ['email' => 'user@example.com', 'password' => 'password']
        && $e->remember === true);
    Event::assertDispatched(Login::class, fn (Login $e) => $e->user->is($user) && $e->remember);
    Event::assertNotDispatched(Failed::class);
});

it('fires Attempting and Failed on wrong credentials', function () {
    Event::fake([Attempting::class, Failed::class, Login::class]);
    $user = tfUser();

    tfLogin('user@example.com', 'wrong');
    tfLogin('nobody@example.com', 'wrong');

    Event::assertDispatchedTimes(Attempting::class, 2);
    Event::assertDispatched(Failed::class, fn (Failed $e) => $e->guard === 'web'
        && $e->user?->is($user)
        && $e->credentials === ['email' => 'user@example.com', 'password' => 'wrong']);
    Event::assertDispatched(Failed::class, fn (Failed $e) => $e->user === null
        && $e->credentials['email'] === 'nobody@example.com');
    Event::assertNotDispatched(Login::class);
});

it('rehashes the password after validate()', function () {
    $user = tfUser();
    $user->forceFill(['password' => Hash::make('password', ['rounds' => 4])])->save();
    $old = $user->password;
    expect(Hash::needsRehash($old))->toBeTrue();

    tfLogin('user@example.com');

    $user->refresh();
    expect($user->password)->not->toBe($old)
        ->and(Hash::needsRehash($user->password))->toBeFalse()
        ->and(Hash::check('password', $user->password))->toBeTrue();
});

it('rehashes the password of a 2FA user at the password step', function () {
    $user = tfEnforcedUser();
    $user->forceFill(['password' => Hash::make('password', ['rounds' => 4])])->save();
    $old = $user->password;

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));

    $this->assertGuest();
    expect($user->refresh()->password)->not->toBe($old)
        ->and(Hash::check('password', $user->password))->toBeTrue();
});

it('does not rehash when rehash_on_login is off', function () {
    config(['hashing.rehash_on_login' => false]);
    $user = tfUser();
    $user->forceFill(['password' => Hash::make('password', ['rounds' => 4])])->save();
    $old = $user->password;

    tfLogin('user@example.com');

    $this->assertAuthenticated();
    expect($user->refresh()->password)->toBe($old);
});

it('does not rehash on wrong password', function () {
    $user = tfUser();
    $user->forceFill(['password' => Hash::make('password', ['rounds' => 4])])->save();
    $old = $user->password;

    tfLogin('user@example.com', 'wrong');

    expect($user->refresh()->password)->toBe($old);
});

it('redirects authenticated users to the index', function () {
    $this->actingAs(tfUser());

    $this->post('/admin/login', ['email' => 'user@example.com', 'password' => 'password'])
        ->assertRedirect(route('platform.main'));
    $this->get('/admin/two-factor')->assertRedirect(route('platform.main'));
});
