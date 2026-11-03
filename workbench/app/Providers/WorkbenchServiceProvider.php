<?php

declare(strict_types=1);

namespace Workbench\App\Providers;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierChannel;
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
        // Manual checks of the verifier flows (spec 0.2 §12 stage 2): ORCHID_2FA_FAKE=1 registers the
        // test driver `fake`; ORCHID_2FA_ALLOWED="email,fake" sets channels.allowed. By default the
        // workbench stays e-mail only.
        if (filter_var(env('ORCHID_2FA_FAKE', false), FILTER_VALIDATE_BOOL)) {
            FakeVerifierChannel::register();
        }

        if (is_string($allowed = env('ORCHID_2FA_ALLOWED')) && $allowed !== '') {
            config(['orchid-2fa.channels.allowed' => array_map('trim', explode(',', $allowed))]);
        }

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
