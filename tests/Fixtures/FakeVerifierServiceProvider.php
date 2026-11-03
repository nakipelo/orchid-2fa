<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Fixtures;

use Illuminate\Support\ServiceProvider;

/**
 * Loads the table, the view and the console command of the test driver FakeVerifierChannel. The
 * driver itself is registered only by FakeVerifierChannel::register() (tests, or the workbench with
 * ORCHID_2FA_FAKE=1), so the package stays e-mail only by default.
 */
class FakeVerifierServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/database/migrations');
        $this->loadViewsFrom(__DIR__.'/views', 'orchid-2fa-fake');

        if ($this->app->runningInConsole()) {
            $this->commands([FakeCodeCommand::class]);
        }
    }
}
