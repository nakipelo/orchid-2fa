<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Nakipelo\Orchid2FA\Tests\MenuEnabled\MenuEnabledTestCase;

uses(MenuEnabledTestCase::class, RefreshDatabase::class);

it('adds the main menu item with menu.enabled', function () {
    // A page with the main menu and without the link layout (PlatformScreen needs published assets).
    $this->actingAs(tfUser('admin@example.com', ['platform.index' => true, 'platform.systems.roles' => true]))
        ->get(route('platform.systems.roles'))
        ->assertOk()
        ->assertSee('href="'.route('platform.profile.two-factor').'"', false)
        ->assertSee('Two-factor authentication');
});
