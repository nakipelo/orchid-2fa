<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\AuthDisabled;

use Nakipelo\Orchid2FA\Tests\TestCase;

/**
 * The application sets `platform.auth = false` (spec §5.3).
 */
abstract class AuthDisabledTestCase extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('platform.auth', false);
    }
}
