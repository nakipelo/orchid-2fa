<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;
use Orchid\Alert\Toast;
use Orchid\Support\Facades\Dashboard;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

/**
 * Spec §4.8, §6, §8, §10 "Profile and administration": reset by an administrator.
 */
beforeEach(function () {
    Notification::fake();
});

function rsEditUrl(User $user, ?string $method = null): string
{
    return route('platform.systems.users.edit', $method === null ? [$user] : [$user, 'method' => $method]);
}

/**
 * An administrator with the user management permission, optionally with the reset permission.
 */
function rsAdmin(bool $reset = true): User
{
    $permissions = ['platform.index' => true, 'platform.systems.users' => true];

    if ($reset) {
        $permissions['platform.systems.users.2fa-reset'] = true;
    }

    return tfUser('admin@example.com', $permissions);
}

/**
 * A voluntary user with a confirmed record, version 3, an active code and used send limits.
 */
function rsTarget(bool $enforced = false): User
{
    $user = $enforced ? tfEnforcedUser('target@example.com') : tfUser('target@example.com');
    TwoFactorAuthentication::query()->create([
        'user_id' => $user->id,
        'enabled_at' => $enforced ? null : now(),
        'confirmed_at' => now(),
        'trusted_devices_version' => 3,
    ]);

    app(ChallengeManager::class)->issue($user);

    return $user;
}

function rsRecord(User $user): TwoFactorAuthentication
{
    return TwoFactorAuthentication::query()->where('user_id', $user->id)->firstOrFail();
}

function rsAssertReset(User $user): void
{
    $record = rsRecord($user);

    expect($record->enabled_at)->toBeNull()
        ->and($record->confirmed_at)->toBeNull()
        ->and($record->trusted_devices_version)->toBe(4)
        ->and(cache()->get('orchid-2fa:code:'.$user->id))->toBeNull()
        ->and(app(ChallengeManager::class)->sendAvailableIn($user))->toBe(0);
}

function rsAssertUntouched(User $user): void
{
    $record = rsRecord($user);

    expect($record->confirmed_at)->not->toBeNull()
        ->and($record->trusted_devices_version)->toBe(3)
        ->and(cache()->get('orchid-2fa:code:'.$user->id))->not->toBeNull();
}

it('registers the reset permission in the package group', function () {
    expect(Dashboard::getAllowAllPermission()->keys())->toContain('platform.systems.users.2fa-reset');

    $group = Dashboard::getPermission()->get('Two-factor authentication');
    expect(collect($group)->pluck('slug')->all())
        ->toContain('platform.2fa.required', 'platform.systems.users.2fa-reset');
});

it('shows the reset block with the permission', function () {
    $target = rsTarget();

    $this->actingAs(rsAdmin())
        ->get(rsEditUrl($target))
        ->assertOk()
        ->assertSee('Reset 2FA')
        ->assertSee('Enabled by the user')
        ->assertSee('t***@example.com (confirmed)')
        ->assertSee(rsEditUrl($target, 'resetTwoFactor'), false);
});

it('hides the reset block without the permission', function () {
    $target = rsTarget();

    $this->actingAs(rsAdmin(reset: false))
        ->get(rsEditUrl($target))
        ->assertOk()
        ->assertDontSee('Reset 2FA')
        ->assertDontSee(rsEditUrl($target, 'resetTwoFactor'), false);
});

it('hides the reset block on the create screen', function () {
    $this->actingAs(rsAdmin())
        ->get(route('platform.systems.users.create'))
        ->assertOk()
        ->assertDontSee('Reset 2FA');
});

it('resets 2FA through the user edit screen', function () {
    $target = rsTarget();

    $this->actingAs(rsAdmin())
        ->from(rsEditUrl($target))
        ->post(rsEditUrl($target, 'resetTwoFactor'))
        ->assertRedirect(rsEditUrl($target))
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Two-factor authentication has been reset.');

    rsAssertReset($target);
    expect($target->refresh()->hasTwoFactorEnabled())->toBeFalse();
});

it('makes a trusted device of the user ask for the code after the reset', function () {
    $target = rsTarget(enforced: true);
    $cookies = app(TrustedDeviceCookie::class);
    $cookie = $cookies->make($target->id, 3);

    $this->actingAs(rsAdmin())->post(rsEditUrl($target, 'resetTwoFactor'));
    $this->newBrowser();

    $this->withCookie($cookie->getName(), (string) $cookie->getValue());
    $this->travel(61)->minutes();
    tfLogin('target@example.com')->assertRedirect(route('platform.two-factor.challenge'));
    $this->assertGuest();
    expect(tfLastCode('target@example.com'))->toBeString();
});

it('lets an enforced user get a code at once after the reset, despite the used limits', function () {
    $target = rsTarget(enforced: true);
    expect(app(ChallengeManager::class)->sendAvailableIn($target))->toBeGreaterThan(0);

    $this->actingAs(rsAdmin())->post(rsEditUrl($target, 'resetTwoFactor'));
    $this->newBrowser();

    tfLogin('target@example.com')->assertRedirect(route('platform.two-factor.challenge'));
    expect(tfSentCodes('target@example.com'))->toHaveCount(2);
    $this->get(route('platform.two-factor.challenge'))->assertDontSee('alert-danger', false);
});

it('refuses the reset without the permission on a direct request', function () {
    $target = rsTarget();

    $this->actingAs(rsAdmin(reset: false))
        ->post(rsEditUrl($target, 'resetTwoFactor'))
        ->assertForbidden();

    rsAssertUntouched($target);
});

it('refuses the reset to a user without access to the user screens', function () {
    $target = rsTarget();
    $user = tfUser('plain@example.com', ['platform.index' => true, 'platform.systems.users.2fa-reset' => true]);

    $this->actingAs($user)
        ->post(rsEditUrl($target, 'resetTwoFactor'))
        ->assertForbidden();

    rsAssertUntouched($target);
});

it('does not reset on GET', function () {
    $target = rsTarget();

    // Orchid redirects a GET with a method to the screen itself (here it fails to build that URL
    // without the {user} parameter, which is Orchid's own behaviour); the method is never called.
    $this->actingAs(rsAdmin())->get(rsEditUrl($target, 'resetTwoFactor'));

    rsAssertUntouched($target);
});

it('rejects the reset without the CSRF token', function () {
    tfEnforceCsrf();
    $target = rsTarget();

    $this->actingAs(rsAdmin())->post(rsEditUrl($target, 'resetTwoFactor'))->assertStatus(419);

    rsAssertUntouched($target);
});

it('answers 404 for an unknown user', function () {
    $this->actingAs(rsAdmin())
        ->post(route('platform.systems.users.edit', [999, 'method' => 'resetTwoFactor']))
        ->assertNotFound();
});

it('resets a user without a record without creating one', function () {
    $target = tfUser('target@example.com');

    $this->actingAs(rsAdmin())->post(rsEditUrl($target, 'resetTwoFactor'))->assertRedirect();

    expect(TwoFactorAuthentication::query()->count())->toBe(0);
});

it('needs two lines in the user edit screen stub', function () {
    $stub = (string) file_get_contents(__DIR__.'/../../../workbench/app/Orchid/Screens/User/UserEditScreen.php');

    expect(substr_count($stub, 'use ResetsTwoFactor;'))->toBe(1)
        ->and(substr_count($stub, 'TwoFactorResetLayout::class,'))->toBe(1);
});

/*
|--------------------------------------------------------------------------
| orchid-2fa:reset
|--------------------------------------------------------------------------
*/

it('resets 2FA with the command after confirmation', function () {
    $target = rsTarget();

    $this->artisan('orchid-2fa:reset', ['email' => 'target@example.com'])
        ->expectsConfirmation('Reset two-factor authentication of [target@example.com]?', 'yes')
        ->expectsOutputToContain('has been reset')
        ->assertSuccessful();

    rsAssertReset($target);
});

it('resets 2FA with the command and --force without asking', function () {
    $target = rsTarget();

    $this->artisan('orchid-2fa:reset', ['email' => 'target@example.com', '--force' => true])
        ->assertSuccessful();

    rsAssertReset($target);
});

it('changes nothing when the confirmation is declined', function () {
    $target = rsTarget();

    $this->artisan('orchid-2fa:reset', ['email' => 'target@example.com'])
        ->expectsConfirmation('Reset two-factor authentication of [target@example.com]?', 'no')
        ->assertFailed();

    rsAssertUntouched($target);
});

it('fails for an unknown e-mail address', function () {
    $target = rsTarget();

    $this->artisan('orchid-2fa:reset', ['email' => 'nobody@example.com', '--force' => true])
        ->expectsOutputToContain('No user with the e-mail address [nobody@example.com].')
        ->assertExitCode(1);

    rsAssertUntouched($target);
});
