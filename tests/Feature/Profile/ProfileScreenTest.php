<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Testing\TestResponse;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\ProfileChallenge;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;
use Orchid\Alert\Toast;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

/**
 * Spec §4.5, §4.7, §6, §10 "Profile and administration": the two-factor profile screen.
 */
beforeEach(function () {
    Notification::fake();
});

function pfUrl(?string $method = null): string
{
    return route('platform.profile.two-factor', $method === null ? [] : ['method' => $method]);
}

/**
 * @param  array<string, mixed>  $data
 */
function pfPost(string $method, array $data = []): TestResponse
{
    return test()->from(pfUrl())->post(pfUrl($method), $data);
}

function pfRecord(User $user): ?TwoFactorAuthentication
{
    return TwoFactorAuthentication::query()->where('user_id', $user->id)->first();
}

function pfEnabledUser(string $email = 'user@example.com'): User
{
    $user = tfUser($email);
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'enabled_at' => now(), 'confirmed_at' => now()]);

    return $user;
}

/*
|--------------------------------------------------------------------------
| The screen
|--------------------------------------------------------------------------
*/

it('registers the screen in the private Orchid group', function () {
    $route = app('router')->getRoutes()->getByName('platform.profile.two-factor');

    expect($route)->not->toBeNull()
        ->and($route->uri())->toBe('admin/profile/two-factor/{method?}')
        ->and($route->gatherMiddleware())->toContain('platform');

    $this->get(pfUrl())->assertRedirect(route('platform.login'));
});

it('shows the disabled status with the enable button', function () {
    $this->actingAs(tfUser())
        ->get(pfUrl())
        ->assertOk()
        ->assertSee('Two-factor authentication')
        ->assertSee('Disabled')
        ->assertSee('u***@example.com')
        ->assertSee(pfUrl('sendEnableCode'), false)
        ->assertDontSee(pfUrl('sendDisableCode'), false)
        ->assertDontSee('name="code"', false)
        ->assertSee(pfUrl('forgetTrustedDevices'), false);
});

it('shows the enabled status with the disable button', function () {
    $this->actingAs(pfEnabledUser())
        ->get(pfUrl())
        ->assertOk()
        ->assertSee('Enabled')
        ->assertSee('u***@example.com (confirmed)')
        ->assertSee(pfUrl('sendDisableCode'), false)
        ->assertDontSee(pfUrl('sendEnableCode'), false);
});

it('shows an unconfirmed address', function () {
    $user = pfEnabledUser();
    TwoFactorAuthentication::query()->update(['confirmed_at' => null]);

    $this->actingAs($user)->get(pfUrl())->assertSee('u***@example.com (not confirmed yet: the next sign-in confirms it)');
});

it('shows the required status without the disable button to an enforced user', function (Closure $makeUser) {
    $this->actingAs($makeUser())
        ->get(pfUrl())
        ->assertOk()
        ->assertSee('Required for your account')
        ->assertSee('cannot be disabled')
        ->assertDontSee(pfUrl('sendDisableCode'), false)
        ->assertDontSee(pfUrl('sendEnableCode'), false)
        ->assertSee(pfUrl('forgetTrustedDevices'), false);
})->with([
    'permission' => fn () => tfEnforcedUser(),
    'permission and enabled' => function () {
        $user = tfEnforcedUser();
        TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'enabled_at' => now(), 'confirmed_at' => now()]);

        return $user;
    },
    'enforce_all' => function () {
        config(['orchid-2fa.enforce_all' => true]);

        return tfUser();
    },
]);

it('is translated into Russian', function () {
    app()->setLocale('ru');

    $this->actingAs(tfEnforcedUser())
        ->get(pfUrl())
        ->assertOk()
        ->assertSee('Двухфакторная аутентификация')
        ->assertSee('Обязательна для вашей учётной записи')
        ->assertSee('Выйти со всех доверенных устройств');
});

/*
|--------------------------------------------------------------------------
| Enabling (spec §4.7, §4.5)
|--------------------------------------------------------------------------
*/

it('enables 2FA only after the code and rotates the remember token', function () {
    Event::fake([TwoFactorChallengeSent::class]);
    $user = tfUser();
    $user->forceFill(['remember_token' => 'old-token'])->save();
    $this->actingAs($user);

    pfPost('sendEnableCode')
        ->assertRedirect(pfUrl())
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'A verification code has been sent to u***@example.com.');

    expect(pfRecord($user))->toBeNull()
        ->and($user->refresh()->remember_token)->toBe('old-token');
    Event::assertDispatched(TwoFactorChallengeSent::class, fn ($event) => $event->context === 'enable'
        && $event->maskedDestination === 'u***@example.com');

    $this->get(pfUrl())
        ->assertSee('Confirm enabling')
        ->assertSee('name="code"', false)
        ->assertSee('autocomplete="one-time-code"', false)
        ->assertSee(pfUrl('enable'), false)
        ->assertSee(pfUrl('cancelCode'), false);

    pfPost('enable', ['code' => tfLastCode()])
        ->assertRedirect(pfUrl())
        ->assertSessionHasNoErrors()
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Two-factor authentication is enabled.');

    $record = pfRecord($user);
    expect($record->enabled_at)->not->toBeNull()
        ->and($record->confirmed_at)->not->toBeNull()
        ->and($record->channel)->toBe('email')
        ->and($user->refresh()->remember_token)->not->toBe('old-token')
        ->and($user->remember_token)->toHaveLength(60)
        ->and(session()->has(ProfileChallenge::SESSION_KEY))->toBeFalse();

    $this->get(pfUrl())->assertSee('Enabled')->assertDontSee('name="code"', false);
});

it('stops an old remember cookie after enabling', function () {
    $user = tfUser();
    $user->forceFill(['remember_token' => 'old-token'])->save();
    $recaller = Orchid::guard()->getRecallerName();
    $cookie = $user->id.'|old-token|'.$user->password;

    $this->withCookie($recaller, $cookie)->get(route('platform.profile'))->assertOk();
    $this->newBrowser();

    $this->actingAs($user);
    pfPost('sendEnableCode');
    pfPost('enable', ['code' => tfLastCode()])->assertSessionHasNoErrors();

    $this->newBrowser();
    $this->withCookie($recaller, $cookie)->get(route('platform.main'))->assertRedirect(route('platform.login'));
    $this->assertGuest();
});

it('asks for the code at the next login after enabling', function () {
    $user = tfUser();
    $this->actingAs($user);
    pfPost('sendEnableCode');
    pfPost('enable', ['code' => tfLastCode()]);
    $this->newBrowser();

    tfLogin('user@example.com')->assertRedirect(route('platform.two-factor.challenge'));
    $this->assertGuest();
});

it('does not enable with a wrong code and counts the attempts', function () {
    $user = tfUser();
    $this->actingAs($user);
    pfPost('sendEnableCode');
    $code = tfLastCode();

    pfPost('enable', ['code' => tfWrongCode($code)])
        ->assertRedirect(pfUrl())
        ->assertSessionHasErrors(['code' => 'The code is incorrect. Attempts left: 4.']);

    expect(pfRecord($user))->toBeNull();

    // The screen keeps the code step.
    $this->get(pfUrl())->assertSee('name="code"', false);

    pfPost('enable', ['code' => $code])->assertSessionHasNoErrors();
    expect(pfRecord($user)->enabled_at)->not->toBeNull();
});

it('annuls the code after the last wrong attempt', function () {
    $user = tfUser();
    $this->actingAs($user);
    pfPost('sendEnableCode');
    $code = tfLastCode();

    foreach (range(1, 4) as $ignored) {
        pfPost('enable', ['code' => tfWrongCode($code)])->assertSessionHasErrors('code');
    }

    pfPost('enable', ['code' => tfWrongCode($code)])
        ->assertSessionHasNoErrors()
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');

    pfPost('enable', ['code' => $code])->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');

    expect(pfRecord($user))->toBeNull();
    $this->get(pfUrl())->assertDontSee('name="code"', false);
});

it('does not enable by a direct request without a code request', function () {
    $user = tfUser();
    $this->actingAs($user);

    pfPost('enable', ['code' => '123456'])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');

    expect(pfRecord($user))->toBeNull();
});

it('requires the code field', function () {
    $user = tfUser();
    $this->actingAs($user);
    pfPost('sendEnableCode');

    pfPost('enable')->assertSessionHasErrors('code');

    expect(pfRecord($user))->toBeNull();
});

it('does not accept a code of another challenge, e.g. from a login', function () {
    $user = tfUser();
    $this->actingAs($user);
    pfPost('sendEnableCode');

    // Another session (a login) replaced the code: the profile challenge no longer matches.
    $this->travel(61)->seconds();
    app(ChallengeManager::class)->issue($user);

    pfPost('enable', ['code' => tfLastCode()])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');

    expect(pfRecord($user))->toBeNull();
});

it('does not accept the code of another user', function () {
    $other = tfUser('other@example.com');
    $this->actingAs($other);
    pfPost('sendEnableCode');
    $code = tfLastCode('other@example.com');

    $user = tfUser();
    $this->actingAs($user);

    pfPost('enable', ['code' => $code])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');

    expect(pfRecord($user))->toBeNull()
        ->and(pfRecord($other))->toBeNull();
});

it('applies the send limits of the login', function () {
    $user = tfUser();
    $this->actingAs($user);

    pfPost('sendEnableCode');
    pfPost('sendEnableCode')
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Too many codes have been requested. Please try again later (in 1 min).');

    expect(tfSentCodes())->toHaveCount(1);

    // The hourly limit counts all sends: login, resend and profile.
    foreach (range(1, 4) as $ignored) {
        $this->travel(61)->seconds();
        pfPost('sendEnableCode');
    }

    $this->travel(61)->seconds();
    pfPost('sendEnableCode')->assertSessionHas(Toast::SESSION_MESSAGE, fn ($message) => str_contains($message, 'Too many codes'));
    expect(tfSentCodes())->toHaveCount(5);
});

it('sends a new code with "send again" and accepts only the latest', function () {
    $user = tfUser();
    $this->actingAs($user);
    pfPost('sendEnableCode');
    $first = tfLastCode();
    $this->travel(61)->seconds();

    pfPost('sendEnableCode');
    $second = tfLastCode();
    expect(tfSentCodes())->toHaveCount(2);

    if ($first !== $second) {
        pfPost('enable', ['code' => $first])->assertSessionHasErrors('code');
    }

    pfPost('enable', ['code' => $second])->assertSessionHasNoErrors();
    expect(pfRecord($user)->enabled_at)->not->toBeNull();
});

it('reports a delivery failure and keeps 2FA disabled', function () {
    $user = tfUser();
    $user->forceFill(['email' => ''])->save();
    $this->actingAs($user);

    pfPost('sendEnableCode')
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'We could not send the code. Please try again later.');

    expect(session()->has(ProfileChallenge::SESSION_KEY))->toBeFalse()
        ->and(pfRecord($user))->toBeNull();
});

it('cancels the code step', function () {
    $user = tfUser();
    $this->actingAs($user);
    pfPost('sendEnableCode');

    pfPost('cancelCode')->assertRedirect(pfUrl());

    $this->get(pfUrl())->assertDontSee('name="code"', false)->assertSee(pfUrl('sendEnableCode'), false);
    pfPost('enable', ['code' => tfLastCode()]);
    expect(pfRecord($user))->toBeNull();
});

it('does not enable twice', function () {
    $user = pfEnabledUser();
    $this->actingAs($user);

    pfPost('sendEnableCode')->assertSessionHas(Toast::SESSION_MESSAGE, 'Two-factor authentication is already enabled.');

    Notification::assertNothingSent();
});

/*
|--------------------------------------------------------------------------
| Disabling (spec §4.7)
|--------------------------------------------------------------------------
*/

it('disables 2FA with the code and invalidates the trusted devices', function () {
    Event::fake([TwoFactorChallengeSent::class]);
    $user = pfEnabledUser();
    $this->actingAs($user);

    pfPost('sendDisableCode')->assertSessionHas(Toast::SESSION_MESSAGE, 'A verification code has been sent to u***@example.com.');
    Event::assertDispatched(TwoFactorChallengeSent::class, fn ($event) => $event->context === 'disable');

    $this->get(pfUrl())->assertSee('Confirm disabling')->assertSee(pfUrl('disable'), false);

    pfPost('disable', ['code' => tfLastCode(), 'password' => 'password'])
        ->assertSessionHasNoErrors()
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Two-factor authentication is disabled.');

    $record = pfRecord($user);
    expect($record->enabled_at)->toBeNull()
        ->and($record->confirmed_at)->toBeNull()
        ->and($record->trusted_devices_version)->toBe(2);

    $this->newBrowser();
    tfLogin('user@example.com')->assertRedirect(route('platform.main'));
});

it('does not disable with a wrong code or without the code request', function () {
    $user = pfEnabledUser();
    $this->actingAs($user);

    pfPost('disable', ['code' => '123456'])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');

    pfPost('sendDisableCode');
    pfPost('disable', ['code' => tfWrongCode(tfLastCode()), 'password' => 'password'])->assertSessionHasErrors('code');

    expect(pfRecord($user)->enabled_at)->not->toBeNull()
        ->and(pfRecord($user)->trusted_devices_version)->toBe(1);
});

it('does not use an enabling code for disabling', function () {
    $user = tfUser();
    $this->actingAs($user);
    pfPost('sendEnableCode');
    $code = tfLastCode();

    // Enabled meanwhile in another session: the pending enabling code must not disable.
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'enabled_at' => now(), 'confirmed_at' => now()]);

    pfPost('disable', ['code' => $code])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');

    expect(pfRecord($user)->enabled_at)->not->toBeNull();
});

it('does not send a disabling code to a user without 2FA', function () {
    $this->actingAs(tfUser());

    pfPost('sendDisableCode')->assertSessionHas(Toast::SESSION_MESSAGE, 'Two-factor authentication is not enabled.');

    Notification::assertNothingSent();
});

it('refuses disabling for an enforced user on a direct request', function (string $method) {
    $user = tfEnforcedUser();
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'enabled_at' => now(), 'confirmed_at' => now()]);
    $this->actingAs($user);

    pfPost($method, ['code' => '123456'])->assertForbidden();

    $record = pfRecord($user);
    expect($record->enabled_at)->not->toBeNull()
        ->and($record->confirmed_at)->not->toBeNull()
        ->and($record->trusted_devices_version)->toBe(1);
    Notification::assertNothingSent();
})->with(['sendDisableCode', 'disable']);

it('refuses disabling when 2FA became enforced after the code was sent', function () {
    $user = pfEnabledUser();
    $this->actingAs($user);
    pfPost('sendDisableCode');
    $code = tfLastCode();

    config(['orchid-2fa.enforce_all' => true]);

    pfPost('disable', ['code' => $code])->assertForbidden();

    expect(pfRecord($user)->enabled_at)->not->toBeNull();
    $this->get(pfUrl())->assertDontSee('name="code"', false);
});

it('refuses enabling for an enforced user', function () {
    $user = tfEnforcedUser();
    $this->actingAs($user);

    pfPost('sendEnableCode')->assertForbidden();
    pfPost('enable', ['code' => '123456'])->assertForbidden();

    Notification::assertNothingSent();
    expect(pfRecord($user))->toBeNull();
});

/*
|--------------------------------------------------------------------------
| Trusted devices (spec §4.4, §4.7)
|--------------------------------------------------------------------------
*/

it('signs out of all trusted devices with any status', function (Closure $makeUser, ?int $version) {
    $user = $makeUser();
    $this->actingAs($user);

    pfPost('forgetTrustedDevices')
        ->assertRedirect(pfUrl())
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Signed out of all trusted devices.');

    expect(pfRecord($user)?->trusted_devices_version)->toBe($version);
})->with([
    'enabled' => [fn () => pfEnabledUser(), 2],
    'enforced with a record' => [function () {
        $user = tfEnforcedUser();
        TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'confirmed_at' => now()]);

        return $user;
    }, 2],
    'without a record' => [fn () => tfUser(), null],
]);

it('makes a trusted device ask for the code again', function () {
    $user = tfEnforcedUser();
    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    $response = tfVerify(tfLastCode(), ['trust_device' => '1']);
    $name = app(TrustedDeviceCookie::class)->name($user->id);
    $value = $response->getCookie($name)?->getValue();
    expect($value)->toBeString();

    pfPost('forgetTrustedDevices');

    $this->newBrowser();
    $this->withCookie($name, (string) $value);
    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
});

/*
|--------------------------------------------------------------------------
| HTTP method and CSRF
|--------------------------------------------------------------------------
*/

it('does not run actions on GET', function (string $method) {
    $user = pfEnabledUser();
    $this->actingAs($user);

    $this->get(pfUrl($method))->assertRedirect();

    expect(pfRecord($user)->trusted_devices_version)->toBe(1)
        ->and(pfRecord($user)->enabled_at)->not->toBeNull();
    Notification::assertNothingSent();
})->with(['sendDisableCode', 'forgetTrustedDevices', 'disable']);

it('rejects actions without the CSRF token', function (string $method) {
    tfEnforceCsrf();
    $user = pfEnabledUser();
    $this->actingAs($user);

    $this->post(pfUrl($method), ['code' => '123456'])->assertStatus(419);

    expect(pfRecord($user)->trusted_devices_version)->toBe(1);
    Notification::assertNothingSent();
})->with(['sendDisableCode', 'forgetTrustedDevices', 'disable']);

it('accepts actions with the CSRF token', function () {
    tfEnforceCsrf();
    $user = pfEnabledUser();
    $this->actingAs($user)->withSession(['_token' => 'csrf-token']);

    $this->post(pfUrl('forgetTrustedDevices'), ['_token' => 'csrf-token'])->assertRedirect();

    expect(pfRecord($user)->trusted_devices_version)->toBe(2);
});

it('sends the profile code to the current address and keeps only its hash', function () {
    $user = tfUser();
    $this->actingAs($user);

    pfPost('sendEnableCode');

    Notification::assertSentOnDemand(TwoFactorCodeNotification::class, fn ($notification, $channels, $notifiable) => $notifiable->routes['mail'] === 'user@example.com');
    expect(cache()->get('orchid-2fa:code:'.$user->id)['hash'])->not->toBe(tfLastCode());
});
