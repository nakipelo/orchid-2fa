<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\AuthDisabled;

/**
 * `platform.auth = false` in the production environment (spec §5.3).
 */
abstract class AuthDisabledProductionTestCase extends AuthDisabledTestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('app.env', 'production');
        $app->detectEnvironment(static fn (): string => 'production');
    }
}
