<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Login;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Challenge\PendingLogin;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;
use Nakipelo\Orchid2FA\Support\Orchid;
use Orchid\Platform\Models\Role;
use Orchid\Support\Facades\Dashboard;

uses(RefreshDatabase::class);

/**
 * Spec §4.2, §4.3, §6: login with the e-mail code.
 */
beforeEach(function () {
    // Exact countdown values: no second may pass between the requests.
    $this->freezeTime();
    Notification::fake();
});

it('sends a code and shows the code screen instead of logging in', function () {
    $user = tfEnforcedUser();
    $this->get('/admin/login');
    $sessionBefore = session()->getId();

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));

    $this->assertGuest();
    expect(session()->getId())->not->toBe($sessionBefore);

    $pending = PendingLogin::fromSession(session()->driver());
    expect($pending)->not->toBeNull()
        ->and($pending->userId)->toBe($user->id)
        ->and($pending->remember)->toBeFalse();

    Notification::assertSentOnDemandTimes(TwoFactorCodeNotification::class, 1);
    Notification::assertSentOnDemand(
        TwoFactorCodeNotification::class,
        fn ($notification, $channels, AnonymousNotifiable $notifiable) => $notifiable->routes === ['mail' => 'enforced@example.com']
            && $channels === ['mail']
            && preg_match('/^\d{6}$/', $notification->code) === 1
            && $notification->expiresAt->equalTo(now()->addSeconds(600)),
    );
});

it('renders the code screen on the Orchid auth layout', function () {
    tfEnforcedUser();
    tfLogin();

    $this->get(route('platform.two-factor.challenge'))
        ->assertOk()
        ->assertSee('Enter the verification code')
        ->assertSee('We have sent a code to e***@example.com.')
        ->assertSee('autocomplete="one-time-code"', false)
        ->assertSee('inputmode="numeric"', false)
        ->assertSee('pattern="\d{6}"', false)
        ->assertSee('maxlength="6"', false)
        ->assertSee('name="code"', false)
        ->assertSee('action="'.route('platform.two-factor.verify').'"', false)
        ->assertSee('action="'.route('platform.two-factor.resend').'"', false)
        ->assertSee('action="'.route('platform.two-factor.cancel').'"', false)
        ->assertSee('Send again in 1:00')
        ->assertSee('data-available-in="60"', false)
        ->assertSee('Sign in as a different user')
        ->assertSee('name="_token"', false)
        ->assertDontSee('enforced@example.com')
        ->assertDontSee('trust_device', false)
        // Orchid's auth layout
        ->assertSee('form-signin', false);
});

it('renders the code screen in Russian', function () {
    app()->setLocale('ru');
    tfEnforcedUser();
    tfLogin();

    $this->get(route('platform.two-factor.challenge'))
        ->assertOk()
        ->assertSee('Введите код подтверждения')
        ->assertSee('Код отправлен на e***@example.com.')
        ->assertSee('Отправить повторно через 1:00')
        ->assertSee('Войти под другим пользователем');
});

it('logs in with the correct code', function () {
    Event::fake([TwoFactorPassed::class, TwoFactorChallengeSent::class, Login::class]);
    $user = tfEnforcedUser();
    tfLogin();
    $sessionBefore = session()->getId();

    tfVerify(tfLastCode())->assertRedirect(route('platform.main'));

    $this->assertAuthenticatedAs($user);
    expect(session()->getId())->not->toBe($sessionBefore)
        ->and(session()->has(PendingLogin::SESSION_KEY))->toBeFalse()
        ->and($user->twoFactor()->first()?->confirmed_at)->not->toBeNull();

    Event::assertDispatched(TwoFactorChallengeSent::class, fn ($e) => $e->user->is($user)
        && $e->guard === 'web' && $e->channel === 'email'
        && $e->maskedDestination === 'e***@example.com' && $e->context === 'login');
    Event::assertDispatched(TwoFactorPassed::class, fn ($e) => $e->user->is($user)
        && $e->guard === 'web' && $e->via === 'code' && $e->trustedDeviceIssued === false);
    Event::assertDispatched(Login::class);

    $this->get(route('platform.profile'))->assertOk();
});

it('redirects to the intended URL after the code', function () {
    tfEnforcedUser();

    $this->get('/admin/users')->assertRedirect(route('platform.login'));
    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));

    tfVerify(tfLastCode())->assertRedirect('/admin/users');
});

it('accepts the code with spaces', function () {
    tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();

    tfVerify(substr($code, 0, 3).' '.substr($code, 3))->assertRedirect(route('platform.main'));

    $this->assertAuthenticated();
});

it('rejects a wrong code and counts the attempt', function () {
    Event::fake([TwoFactorFailed::class]);
    $user = tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();

    tfVerify(tfWrongCode($code))
        ->assertRedirect(route('platform.two-factor.challenge'))
        ->assertSessionHasErrors(['code' => 'The code is incorrect. Attempts left: 4.']);

    $this->assertGuest();
    Event::assertDispatched(TwoFactorFailed::class, fn ($e) => $e->user->is($user) && $e->reason === 'invalid_code');

    // The right code still works.
    tfVerify($code)->assertRedirect(route('platform.main'));
    $this->assertAuthenticatedAs($user);
});

it('annuls the code after five wrong attempts', function () {
    Event::fake([TwoFactorFailed::class, TwoFactorLockedOut::class]);
    $user = tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();

    foreach ([4, 3, 2, 1] as $left) {
        tfVerify(tfWrongCode($code))->assertSessionHasErrors(['code' => "The code is incorrect. Attempts left: {$left}."]);
    }

    tfVerify(tfWrongCode($code))->assertSessionHasErrors(['code' => 'The code is no longer valid. Please request a new one.']);
    Event::assertDispatched(TwoFactorLockedOut::class, fn ($e) => $e->user->is($user)
        && $e->reason === 'attempts_exceeded' && $e->availableIn === 60);
    Event::assertDispatchedTimes(TwoFactorFailed::class, 5);

    tfVerify($code)->assertSessionHasErrors(['code' => 'The code is no longer valid. Please request a new one.']);
    $this->assertGuest();
    Event::assertDispatched(TwoFactorFailed::class, fn ($e) => $e->reason === 'expired');
});

it('rejects an expired code', function () {
    config(['orchid-2fa.pending_ttl' => 3600]);
    tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();

    $this->travel(601)->seconds();

    tfVerify($code)->assertSessionHasErrors(['code' => 'The code is no longer valid. Please request a new one.']);
    $this->assertGuest();
});

it('sends to the login screen when the pending login expired', function () {
    tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();

    $this->travel(601)->seconds();

    tfVerify($code)
        ->assertRedirect(route('platform.login'))
        ->assertSessionHasErrors(['email' => 'Your sign-in session has expired. Please sign in again.']);
    $this->assertGuest();
    expect(session()->has(PendingLogin::SESSION_KEY))->toBeFalse();

    $this->get(route('platform.two-factor.challenge'))->assertRedirect(route('platform.login'));
});

it('shows the expired pending message on the code screen too', function () {
    tfEnforcedUser();
    tfLogin();

    $this->travel(601)->seconds();

    $this->get(route('platform.two-factor.challenge'))
        ->assertRedirect(route('platform.login'))
        ->assertSessionHasErrors('email');
});

it('redirects the code screen to the login without a pending login', function () {
    $this->get(route('platform.two-factor.challenge'))->assertRedirect(route('platform.login'));
    $this->post(route('platform.two-factor.resend'))->assertRedirect(route('platform.login'));
});

it('signs in as a different user', function () {
    tfEnforcedUser();
    tfLogin();

    $this->post(route('platform.two-factor.cancel'))
        ->assertRedirect(route('platform.login'))
        ->assertCookieExpired(Orchid::lockCookieName());

    expect(session()->has(PendingLogin::SESSION_KEY))->toBeFalse();
    $this->get(route('platform.two-factor.challenge'))->assertRedirect(route('platform.login'));
    tfVerify(tfLastCode())->assertRedirect(route('platform.login'));
    $this->assertGuest();
});

it('reuses the active code when the user signs in again', function () {
    tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();
    $this->post(route('platform.two-factor.cancel'));

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));

    Notification::assertSentOnDemandTimes(TwoFactorCodeNotification::class, 1);
    tfVerify($code)->assertRedirect(route('platform.main'));
    $this->assertAuthenticated();
});

it('requires 2FA for everybody with enforce_all', function () {
    config(['orchid-2fa.enforce_all' => true]);
    tfUser();

    tfLogin('user@example.com')->assertRedirect(route('platform.two-factor.challenge'));

    $this->assertGuest();
    tfVerify(tfLastCode('user@example.com'))->assertRedirect(route('platform.main'));
});

it('requires 2FA for the permission granted through a role', function () {
    $user = tfUser();
    $role = Role::query()->create([
        'slug' => 'secure', 'name' => 'Secure', 'permissions' => ['platform.2fa.required' => true],
    ]);
    $user->roles()->attach($role);

    tfLogin('user@example.com')->assertRedirect(route('platform.two-factor.challenge'));
    $this->assertGuest();
});

it('requires 2FA for a user who enabled it voluntarily', function () {
    $user = tfUser();
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'enabled_at' => now(), 'confirmed_at' => now()]);

    tfLogin('user@example.com')->assertRedirect(route('platform.two-factor.challenge'));
    $this->assertGuest();
});

it('registers the "2fa.required" permission, so orchid:admin users are enforced', function () {
    expect(Dashboard::getAllowAllPermission()->keys())->toContain('platform.2fa.required');

    $admin = tfUser('admin@example.com', Dashboard::getAllowAllPermission()->all());

    tfLogin('admin@example.com')->assertRedirect(route('platform.two-factor.challenge'));
    $this->assertGuest();
    expect($admin->refresh()->hasAccess('platform.2fa.required'))->toBeTrue();
});

it('creates the record of an enforced user lazily on the first challenge', function () {
    $user = tfEnforcedUser();
    expect(TwoFactorAuthentication::query()->count())->toBe(0);

    tfLogin();

    $record = $user->twoFactor()->first();
    expect($record)->not->toBeNull()
        ->and($record->enabled_at)->toBeNull()
        ->and($record->confirmed_at)->toBeNull();
});

it('answers JSON clients', function () {
    $user = tfEnforcedUser();

    $this->postJson('/admin/login', ['email' => 'enforced@example.com', 'password' => 'password'])
        ->assertOk()
        ->assertExactJson(['two_factor' => true, 'redirect' => route('platform.two-factor.challenge')]);
    $this->assertGuest();

    $this->postJson('/admin/two-factor', ['code' => tfWrongCode(tfLastCode())])
        ->assertUnprocessable()
        ->assertJsonValidationErrors(['code' => 'The code is incorrect. Attempts left: 4.']);

    $this->postJson('/admin/two-factor', ['code' => tfLastCode()])->assertNoContent();
    $this->assertAuthenticatedAs($user);
});

it('answers JSON clients without a pending login', function () {
    $this->postJson('/admin/two-factor', ['code' => '123456'])
        ->assertUnprocessable()
        ->assertJsonValidationErrors(['code' => 'Your sign-in session has expired. Please sign in again.']);
});

it('requires the code field', function () {
    tfEnforcedUser();
    tfLogin();

    tfVerify('')->assertSessionHasErrors('code');
    $this->assertGuest();
});
