<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;

uses(RefreshDatabase::class);

/**
 * Spec §4.7, §6: the entry to the two-factor profile screen.
 */
it('shows the status and the link on the profile screen', function () {
    $this->actingAs(tfUser())
        ->get(route('platform.profile'))
        ->assertOk()
        ->assertSee('Two-factor authentication')
        ->assertSee('Disabled')
        ->assertSee('Manage')
        ->assertSee('href="'.route('platform.profile.two-factor').'"', false);
});

it('shows the current status in the link layout', function (Closure $makeUser, string $status) {
    $this->actingAs($makeUser())
        ->get(route('platform.profile'))
        ->assertOk()
        ->assertSee($status);
})->with([
    'enabled' => [function () {
        $user = tfUser();
        TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'enabled_at' => now(), 'confirmed_at' => now()]);

        return $user;
    }, 'Enabled'],
    'required' => [fn () => tfEnforcedUser(), 'Required for your account'],
]);

it('keeps the profile screen working: the link layout is one line in the stub', function () {
    $stub = (string) file_get_contents(__DIR__.'/../../../workbench/app/Orchid/Screens/User/UserProfileScreen.php');

    expect(substr_count($stub, 'TwoFactorProfileLinkLayout::class,'))->toBe(1);
});

it('does not add a main menu item by default', function () {
    expect(config('orchid-2fa.menu.enabled'))->toBeFalse();

    // A page with the main menu and without the link layout (PlatformScreen needs published assets).
    $this->actingAs(tfUser('admin@example.com', ['platform.index' => true, 'platform.systems.roles' => true]))
        ->get(route('platform.systems.roles'))
        ->assertOk()
        ->assertDontSee('href="'.route('platform.profile.two-factor').'"', false);
});
