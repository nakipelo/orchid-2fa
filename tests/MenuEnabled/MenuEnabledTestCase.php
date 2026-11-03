<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\MenuEnabled;

use Nakipelo\Orchid2FA\Tests\TestCase;

/**
 * The application sets `orchid-2fa.menu.enabled = true` (spec §6): the menu is registered at boot.
 */
abstract class MenuEnabledTestCase extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('orchid-2fa.menu.enabled', true);
    }
}
