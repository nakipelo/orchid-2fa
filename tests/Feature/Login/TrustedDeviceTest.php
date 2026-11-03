<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Login;
use Illuminate\Encryption\Encrypter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Testing\TestResponse;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Orchid2FAServiceProvider;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;
use Orchid\Support\Facades\Dashboard;
use Symfony\Component\HttpFoundation\Cookie;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

/**
 * Spec §4.4, §5.6, §11 stage 3: the trusted device.
 */
beforeEach(function () {
    Notification::fake();
});

function tdCookies(): TrustedDeviceCookie
{
    return app(TrustedDeviceCookie::class);
}

function tdName(User $user): string
{
    return tdCookies()->name($user->id);
}

/**
 * Log in with the code and the "trust this device" checkbox; returns the verify response.
 *
 * @param  array<string, mixed>  $loginExtra
 */
function tdTrust(string $email = 'enforced@example.com', array $loginExtra = []): TestResponse
{
    tfLogin($email, extra: $loginExtra)->assertRedirect(route('platform.two-factor.challenge'));

    return tfVerify(tfLastCode($email), ['trust_device' => '1']);
}

/**
 * The trusted device cookie value of the response, as the browser sends it back
 * (the `EncryptCookies` layer removed; the test client adds it again).
 */
function tdValue(TestResponse $response, User $user): string
{
    $value = $response->getCookie(tdName($user))?->getValue();

    expect($value)->toBeString()->not->toBe('');

    return (string) $value;
}

/**
 * @param  array<string, mixed>  $payload
 */
function tdForge(array $payload, ?Encrypter $encrypter = null): string
{
    return ($encrypter ?? Crypt::getFacadeRoot())->encryptString((string) json_encode($payload));
}

function tdCodesSent(): int
{
    return count(tfSentCodes());
}

/**
 * Asserts that the login asked for the code and deleted the given cookie.
 */
function tdAssertRejected(TestResponse $response, string $cookieName, bool $deleted = true): void
{
    $response->assertRedirect(route('platform.two-factor.challenge'));
    test()->assertGuest();

    $cookie = $response->getCookie($cookieName, false);

    if ($deleted) {
        expect($cookie)->not->toBeNull()
            ->and($cookie->getExpiresTime())->toBeLessThan(now()->getTimestamp())
            ->and($cookie->getPath())->toBe('/admin');
    } else {
        expect($cookie)->toBeNull();
    }
}

/*
|--------------------------------------------------------------------------
| The checkbox
|--------------------------------------------------------------------------
*/

it('shows the checkbox with the configured lifetime', function () {
    config(['orchid-2fa.trusted_devices.lifetime_days' => 7]);
    tfEnforcedUser();
    tfLogin();

    $this->get(route('platform.two-factor.challenge'))
        ->assertOk()
        ->assertSee('type="checkbox"', false)
        ->assertSee('name="trust_device"', false)
        ->assertSee('Trust this device for 7 days');
});

it('pluralises the checkbox label in Russian', function (int $days, string $label) {
    app()->setLocale('ru');
    config(['orchid-2fa.trusted_devices.lifetime_days' => $days]);
    tfEnforcedUser();
    tfLogin();

    $this->get(route('platform.two-factor.challenge'))->assertSee($label);
})->with([
    [1, 'Доверять этому устройству 1 день'],
    [3, 'Доверять этому устройству 3 дня'],
    [30, 'Доверять этому устройству 30 дней'],
    [21, 'Доверять этому устройству 21 день'],
]);

it('hides the checkbox when trusted devices are disabled', function () {
    config(['orchid-2fa.trusted_devices.enabled' => false]);
    tfEnforcedUser();
    tfLogin();

    $this->get(route('platform.two-factor.challenge'))
        ->assertOk()
        ->assertDontSee('trust_device', false)
        ->assertDontSee('Trust this device');
});

/*
|--------------------------------------------------------------------------
| Issuing the cookie
|--------------------------------------------------------------------------
*/

it('issues the cookie after the code with the checkbox', function () {
    $this->freezeTime();
    Event::fake([TwoFactorPassed::class]);
    $user = tfEnforcedUser();

    $response = tdTrust()->assertRedirect(route('platform.main'));

    $this->assertAuthenticatedAs($user);

    $cookie = $response->getCookie(tdName($user));
    expect($cookie)->not->toBeNull()
        ->and($cookie->isHttpOnly())->toBeTrue()
        ->and($cookie->getSameSite())->toBe(Cookie::SAMESITE_LAX)
        ->and($cookie->getPath())->toBe('/admin')
        ->and($cookie->isSecure())->toBeFalse()
        ->and($cookie->getExpiresTime())->toBe(now()->addDays(30)->getTimestamp());

    $payload = json_decode(Crypt::decryptString($cookie->getValue()), true);
    expect($payload)->toBe([
        'uid' => $user->id,
        'g' => 'web',
        'v' => 1,
        'exp' => now()->addDays(30)->getTimestamp(),
    ]);

    Event::assertDispatched(TwoFactorPassed::class, fn ($e) => $e->via === 'code' && $e->trustedDeviceIssued === true);
});

it('names the cookie per user without revealing the id', function () {
    $user = tfEnforcedUser();
    $other = tfEnforcedUser('other@example.com');

    expect(tdName($user))->toMatch('/^orchid_2fa_trusted_[0-9a-f]{16}$/')
        ->and(tdName($user))->not->toBe(tdName($other))
        ->and(tdName($user))->toBe(tdName($user));

    config(['orchid-2fa.trusted_devices.cookie' => 'my_trust']);
    expect(tdName($user))->toStartWith('my_trust_');
});

it('uses the configured lifetime', function () {
    $this->freezeTime();
    config(['orchid-2fa.trusted_devices.lifetime_days' => 7]);
    $user = tfEnforcedUser();

    $cookie = tdTrust()->getCookie(tdName($user));

    expect($cookie->getExpiresTime())->toBe(now()->addDays(7)->getTimestamp())
        ->and(json_decode(Crypt::decryptString($cookie->getValue()), true)['exp'])->toBe(now()->addDays(7)->getTimestamp());
});

it('marks the cookie secure from the session config or the request scheme', function () {
    $user = tfEnforcedUser();

    config(['session.secure' => true]);
    expect(tdTrust()->getCookie(tdName($user), false)->isSecure())->toBeTrue();

    $this->newBrowser();
    $this->travel(61)->seconds();
    config(['session.secure' => false]);
    tfLogin();
    $response = $this->post('https://localhost/admin/two-factor', ['code' => tfLastCode(), 'trust_device' => '1']);
    expect($response->getCookie(tdName($user), false)->isSecure())->toBeFalse();

    $this->newBrowser();
    $this->travel(61)->seconds();
    config(['session.secure' => null]);
    tfLogin();
    $response = $this->post('https://localhost/admin/two-factor', ['code' => tfLastCode(), 'trust_device' => '1']);
    expect($response->getCookie(tdName($user), false)->isSecure())->toBeTrue();
});

it('does not issue the cookie without the checkbox', function () {
    Event::fake([TwoFactorPassed::class]);
    $user = tfEnforcedUser();
    tfLogin();

    tfVerify(tfLastCode())->assertCookieMissing(tdName($user));

    Event::assertDispatched(TwoFactorPassed::class, fn ($e) => $e->trustedDeviceIssued === false);
});

it('does not issue the cookie when trusted devices are disabled', function () {
    config(['orchid-2fa.trusted_devices.enabled' => false]);
    Event::fake([TwoFactorPassed::class]);
    $user = tfEnforcedUser();

    tdTrust()->assertRedirect(route('platform.main'))->assertCookieMissing(tdName($user));

    Event::assertDispatched(TwoFactorPassed::class, fn ($e) => $e->trustedDeviceIssued === false);
});

it('does not issue the cookie after a wrong code', function () {
    $user = tfEnforcedUser();
    tfLogin();

    tfVerify(tfWrongCode(tfLastCode()), ['trust_device' => '1'])->assertCookieMissing(tdName($user));
});

/*
|--------------------------------------------------------------------------
| Signing in on a trusted device
|--------------------------------------------------------------------------
*/

it('skips the code on a trusted device', function () {
    // Faked before the first request: the route keeps its controller instance.
    Event::fake([TwoFactorPassed::class, Login::class]);
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();

    $this->withCookie(tdName($user), $value);
    tfLogin()->assertRedirect(route('platform.main'))->assertCookieMissing(tdName($user));

    $this->assertAuthenticatedAs($user);
    expect(tdCodesSent())->toBe(1);
    Event::assertDispatched(TwoFactorPassed::class, fn ($e) => $e->user->is($user)
        && $e->guard === 'web' && $e->via === 'trusted_device' && $e->trustedDeviceIssued === false);
    Event::assertDispatchedTimes(TwoFactorPassed::class, 2);
    Event::assertDispatchedTimes(Login::class, 2);
    $this->get(route('platform.profile'))->assertOk();
});

it('logs the trusted device login when logging is enabled', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();
    config(['orchid-2fa.log.enabled' => true]);
    $this->app->register(Orchid2FAServiceProvider::class, force: true);

    $this->withCookie(tdName($user), $value);
    tfLogin()->assertRedirect(route('platform.main'));

    $record = collect($this->logHandler()->getRecords())
        ->first(fn ($r) => $r->message === 'Two-factor authentication passed.' && $r->context['via'] === 'trusted_device');
    expect($record)->not->toBeNull()
        ->and($record->context)->toMatchArray(['user_id' => $user->id, 'guard' => 'web', 'trusted_device_issued' => false]);
});

it('still checks the password on a trusted device', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();

    $this->withCookie(tdName($user), $value);
    tfLogin(password: 'wrong')->assertRedirect('/admin/login')->assertSessionHasErrors('email');

    $this->assertGuest();
});

it('keeps the trusted device across logins until it expires', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);

    // Day 1 and day 29 of the 30-day lifetime.
    foreach ([1, 28] as $days) {
        $this->newBrowser();
        $this->travel($days)->days();
        $this->withCookie(tdName($user), $value);
        tfLogin()->assertRedirect(route('platform.main'));
    }

    expect(tdCodesSent())->toBe(1);
});

it('remembers the user on a trusted device with the remember flag', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();
    $recaller = Orchid::guard()->getRecallerName();

    $this->withCookie(tdName($user), $value);
    $response = tfLogin(extra: ['remember' => 'true'])
        ->assertRedirect(route('platform.main'))
        ->assertCookie($recaller)
        ->assertCookie(Orchid::lockCookieName(), (string) $user->id);

    $remember = $response->getCookie($recaller)?->getValue();
    $this->newBrowser();
    $this->withCookie($recaller, (string) $remember)->get(route('platform.profile'))->assertOk();
    $this->assertAuthenticatedAs($user);
    expect(tdCodesSent())->toBe(1);
});

it('issues both the remember and the trusted device cookie after the code', function () {
    $user = tfEnforcedUser();

    tdTrust(loginExtra: ['remember' => 'true'])
        ->assertCookie(tdName($user))
        ->assertCookie(Orchid::guard()->getRecallerName())
        ->assertCookie(Orchid::lockCookieName(), (string) $user->id);
});

it('answers 204 to a JSON login on a trusted device', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();

    $this->withCookie(tdName($user), $value)
        ->withCredentials()
        ->postJson('/admin/login', ['email' => 'enforced@example.com', 'password' => 'password'])
        ->assertNoContent();

    $this->assertAuthenticatedAs($user);
});

it('keeps several accounts trusted in one browser', function () {
    $first = tfEnforcedUser();
    $second = tfEnforcedUser('second@example.com');
    $firstValue = tdValue(tdTrust(), $first);
    $this->newBrowser();
    $secondValue = tdValue(tdTrust('second@example.com'), $second);

    foreach ([[$first, 'enforced@example.com'], [$second, 'second@example.com']] as [$user, $email]) {
        $this->newBrowser();
        $this->withCookie(tdName($first), $firstValue)->withCookie(tdName($second), $secondValue);
        tfLogin($email)->assertRedirect(route('platform.main'));
        $this->assertAuthenticatedAs($user);
    }

    expect(tdCodesSent())->toBe(2);
});

/*
|--------------------------------------------------------------------------
| Rejected cookies
|--------------------------------------------------------------------------
*/

it('ignores an expired cookie', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();
    $this->travel(30)->days();
    $this->travel(1)->second();

    $this->withCookie(tdName($user), $value);
    tdAssertRejected(tfLogin(), tdName($user));
});

it('ignores a cookie with an expired payload even if the browser keeps it', function () {
    $user = tfEnforcedUser();
    tdTrust();
    $this->newBrowser();

    $value = tdForge(['uid' => $user->id, 'g' => 'web', 'v' => 1, 'exp' => now()->subSecond()->getTimestamp()]);
    $this->withCookie(tdName($user), $value);
    tdAssertRejected(tfLogin(), tdName($user));
});

it('ignores the cookie after the version is bumped', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();

    $user->bumpTrustedDevicesVersion();
    // Past the resend cooldown, so the rejected login sends a new code.
    $this->travel(61)->seconds();

    $this->withCookie(tdName($user), $value);
    tdAssertRejected(tfLogin(), tdName($user));

    // A new code with the checkbox trusts the device again, with the new version.
    $response = tfVerify(tfLastCode(), ['trust_device' => '1'])->assertRedirect(route('platform.main'));
    expect(json_decode(Crypt::decryptString(tdValue($response, $user)), true)['v'])->toBe(2);
});

it('ignores the cookie after "sign out of all trusted devices" without the trait', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();

    TwoFactorAuthentication::bumpTrustedDevicesVersionFor($user->id);

    $this->withCookie(tdName($user), $value);
    tdAssertRejected(tfLogin(), tdName($user));
});

it('ignores a cookie of another user', function () {
    $owner = tfEnforcedUser();
    $victim = tfEnforcedUser('victim@example.com');
    $value = tdValue(tdTrust(), $owner);
    $this->newBrowser();

    // Under the owner's name the cookie is not even read for another user…
    $this->withCookie(tdName($owner), $value);
    tdAssertRejected(tfLogin('victim@example.com'), tdName($victim), deleted: false);

    // …and copied under the victim's name it does not match the user id.
    $this->newBrowser();
    $this->withCookie(tdName($victim), $value);
    tdAssertRejected(tfLogin('victim@example.com'), tdName($victim));
});

it('ignores a forged user id in an unencrypted payload', function () {
    $user = tfEnforcedUser();
    tdTrust();
    $this->newBrowser();

    $this->withCookie(tdName($user), (string) json_encode(['uid' => $user->id, 'g' => 'web', 'v' => 1, 'exp' => now()->addDay()->getTimestamp()]));
    tdAssertRejected(tfLogin(), tdName($user));
});

it('ignores a tampered cookie', function (string $value) {
    $user = tfEnforcedUser();
    tdTrust();
    $this->newBrowser();

    $this->withCookie(tdName($user), $value);
    tdAssertRejected(tfLogin(), tdName($user));
})->with([
    'garbage' => 'not-a-cookie',
    'tampered' => fn () => substr_replace($v = tdForge(['uid' => 1, 'g' => 'web', 'v' => 1, 'exp' => now()->addDay()->getTimestamp()]), $v[20] === 'A' ? 'B' : 'A', 20, 1),
    'not json' => fn () => Crypt::encryptString('nope'),
    'string version' => fn () => tdForge(['uid' => 1, 'g' => 'web', 'v' => '1', 'exp' => now()->addDay()->getTimestamp()]),
    'no expiry' => fn () => tdForge(['uid' => 1, 'g' => 'web', 'v' => 1]),
]);

it('ignores a cookie the EncryptCookies layer cannot decrypt', function () {
    $user = tfEnforcedUser();
    tdTrust();
    $this->newBrowser();

    $this->withUnencryptedCookie(tdName($user), 'raw-value');
    tdAssertRejected(tfLogin(), tdName($user));
});

it('ignores a cookie of another application', function () {
    $user = tfEnforcedUser();
    tdTrust();
    $this->newBrowser();

    $foreign = new Encrypter(str_repeat('x', 32), 'AES-256-CBC');
    $this->withCookie(tdName($user), tdForge(['uid' => $user->id, 'g' => 'web', 'v' => 1, 'exp' => now()->addDay()->getTimestamp()], $foreign));
    tdAssertRejected(tfLogin(), tdName($user));
});

it('ignores a cookie of another guard', function () {
    $user = tfEnforcedUser();
    tdTrust();
    $this->newBrowser();

    $this->withCookie(tdName($user), tdForge(['uid' => $user->id, 'g' => 'admin', 'v' => 1, 'exp' => now()->addDay()->getTimestamp()]));
    tdAssertRejected(tfLogin(), tdName($user));
});

it('names the cookie per guard', function () {
    $user = tfEnforcedUser();
    $name = tdName($user);

    config([
        'auth.guards.admin' => ['driver' => 'session', 'provider' => 'users'],
        'platform.guard' => 'admin',
    ]);

    expect(tdName($user))->not->toBe($name);
});

it('ignores the cookie when the 2FA record is missing', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();

    TwoFactorAuthentication::query()->delete();

    $this->withCookie(tdName($user), $value);
    tdAssertRejected(tfLogin(), tdName($user));
});

it('ignores the cookie while the current address is not confirmed', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();

    TwoFactorAuthentication::query()->update(['confirmed_at' => null]);

    $this->withCookie(tdName($user), $value);
    tdAssertRejected(tfLogin(), tdName($user));
});

it('ignores existing cookies when trusted devices are disabled', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();
    config(['orchid-2fa.trusted_devices.enabled' => false]);

    $this->withCookie(tdName($user), $value);
    tdAssertRejected(tfLogin(), tdName($user), deleted: false);

    // Enabled again, the untouched cookie works.
    $this->newBrowser();
    config(['orchid-2fa.trusted_devices.enabled' => true]);
    $this->withCookie(tdName($user), $value);
    tfLogin()->assertRedirect(route('platform.main'));
});

it('logs in a user without 2FA as before, ignoring the cookie', function () {
    $user = tfUser();

    $this->withCookie(tdName($user), 'whatever');
    tfLogin('user@example.com')->assertRedirect(route('platform.main'))->assertCookieMissing(tdName($user));

    $this->assertAuthenticatedAs($user);
    expect(tdCodesSent())->toBe(0);
});

/*
|--------------------------------------------------------------------------
| Invalidation by a password change (spec §4.4, §5.5)
|--------------------------------------------------------------------------
*/

it('bumps the version when the password changes through the model', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();

    $user->refresh();
    $user->name = 'renamed';
    $user->save();
    expect($user->twoFactor->trusted_devices_version)->toBe(1);

    $user->password = Hash::make('new-password');
    $user->save();
    expect($user->twoFactor->trusted_devices_version)->toBe(2);

    $this->withCookie(tdName($user), $value);
    tdAssertRejected(tfLogin(password: 'new-password'), tdName($user));
});

it('bumps the version when the password changes in the profile screen', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);

    $this->post(route('platform.profile', ['method' => 'changePassword']), [
        'old_password' => 'password',
        'password' => 'new-password',
        'password_confirmation' => 'new-password',
    ])->assertSessionHasNoErrors();

    expect(Hash::check('new-password', $user->refresh()->password))->toBeTrue()
        ->and($user->twoFactor->trusted_devices_version)->toBe(2);

    $this->newBrowser();
    $this->withCookie(tdName($user), $value);
    tdAssertRejected(tfLogin(password: 'new-password'), tdName($user));
});

it('bumps the version when an administrator changes the password in the user edit screen', function () {
    $user = tfEnforcedUser();
    $value = tdValue(tdTrust(), $user);
    $this->newBrowser();
    $admin = tfUser('admin@example.com', Dashboard::getAllowAllPermission()->all());

    $this->actingAs($admin)
        ->post(route('platform.systems.users.edit', [$user, 'method' => 'save']), [
            'user' => ['name' => 'user', 'email' => 'enforced@example.com', 'password' => 'new-password'],
            'permissions' => [base64_encode('platform.index') => '1', base64_encode('platform.2fa.required') => '1'],
        ])
        ->assertRedirect(route('platform.systems.users'));

    expect(Hash::check('new-password', $user->refresh()->password))->toBeTrue()
        ->and($user->twoFactor->trusted_devices_version)->toBe(2);

    $this->newBrowser();
    $this->withCookie(tdName($user), $value);
    tdAssertRejected(tfLogin(password: 'new-password'), tdName($user));
});

it('does not bump the version when the user edit screen saves without a password', function () {
    $user = tfEnforcedUser();
    tdTrust();
    $this->newBrowser();
    $admin = tfUser('admin@example.com', Dashboard::getAllowAllPermission()->all());

    $this->actingAs($admin)
        ->post(route('platform.systems.users.edit', [$user, 'method' => 'save']), [
            'user' => ['name' => 'renamed', 'email' => 'enforced@example.com'],
            'permissions' => [base64_encode('platform.index') => '1', base64_encode('platform.2fa.required') => '1'],
        ])
        ->assertRedirect(route('platform.systems.users'));

    expect($user->refresh()->name)->toBe('renamed')
        ->and($user->twoFactor->trusted_devices_version)->toBe(1);
});

it('does not create a record when the password of a user without one changes', function () {
    $user = tfUser();

    $user->password = Hash::make('new-password');
    $user->save();

    expect(TwoFactorAuthentication::query()->count())->toBe(0);
});
