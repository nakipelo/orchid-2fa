<?php

declare(strict_types=1);

namespace Workbench\App\Providers;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Orchid\Platform\Dashboard;
use Orchid\Platform\Models\User as OrchidUser;
use Workbench\App\Models\User;
use Workbench\App\Orchid\PlatformProvider;

/**
 * Plays the role of an application with Orchid installed (`orchid:install`):
 * App\Models\User extends Orchid's user, routes/platform.php, PlatformProvider.
 */
class WorkbenchServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        config(['auth.providers.users.model' => User::class]);

        Dashboard::useModel(OrchidUser::class, User::class);

        $this->app->register(PlatformProvider::class);
    }

    public function boot(): void
    {
        // Orchid loads the application's routes/platform.php from its RouteServiceProvider,
        // after its route macros (Route::screen) exist; do the same once everything is booted.
        $this->app->booted(function (): void {
            if ($this->app->routesAreCached()) {
                return;
            }

            Route::domain((string) config('platform.domain'))
                ->prefix(Dashboard::prefix('/'))
                ->middleware(config('platform.middleware.private'))
                ->group(__DIR__.'/../../routes/platform.php');
        });
    }
}
