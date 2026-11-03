<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Nakipelo\Orchid2FA\Concerns\HasTwoFactor;
use Nakipelo\Orchid2FA\Exceptions\UnsupportedGuardException;
use Nakipelo\Orchid2FA\Http\Controllers\LoginController;
use Nakipelo\Orchid2FA\Support\Orchid;

class Orchid2FAServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/orchid-2fa.php', 'orchid-2fa');
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/orchid-2fa.php' => config_path('orchid-2fa.php'),
            ], 'orchid-2fa-config');

            $this->publishesMigrations([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'orchid-2fa-migrations');
        }

        // Orchid loads its routes in a "booted" callback of its RouteServiceProvider,
        // i.e. while the application boots. Application "booted" callbacks run after
        // all providers have booted, so routes registered here come after Orchid's.
        $this->app->booted(function (): void {
            $this->ensureSessionGuard();
            $this->registerLoginRoute();
            $this->warnAboutMissingTrait();
        });
    }

    /**
     * @throws UnsupportedGuardException
     */
    protected function ensureSessionGuard(): void
    {
        Orchid::guard();
    }

    /**
     * Replace Orchid's `POST login`. A route with the same method, domain and URI
     * added later replaces the earlier one in the RouteCollection, and the route
     * name points to the new route (spec §5.3).
     */
    protected function registerLoginRoute(): void
    {
        if (! Orchid::loginRoutesEnabled()) {
            $this->warnAboutDisabledLoginRoutes();

            return;
        }

        if ($this->app->routesAreCached()) {
            return;
        }

        Orchid::routeGroup(false, function (): void {
            Route::post('login', [LoginController::class, 'login'])
                ->middleware(['throttle:60,1', Orchid::guestMiddleware()])
                ->name($this->localRouteName(Orchid::loginAuthRoute()));
        });
    }

    /**
     * Only in local/testing: in production the setting is a deliberate choice
     * and the warning would be written on every request (spec §5.3).
     */
    protected function warnAboutDisabledLoginRoutes(): void
    {
        if (! $this->app->environment('local', 'testing')) {
            return;
        }

        Log::warning(sprintf(
            'nakipelo/orchid-2fa: [%s] is false, so Orchid does not register its login routes and '
            .'the two-factor login is not installed. Your own login must take care of the second factor.',
            Orchid::configKey('auth'),
        ));
    }

    /**
     * Route name inside `Orchid::routeGroup()`, which already adds the name prefix.
     */
    protected function localRouteName(string $name): string
    {
        return Str::after($name, Orchid::routeNamePrefix());
    }

    protected function warnAboutMissingTrait(): void
    {
        if (! $this->app->environment('local', 'testing')) {
            return;
        }

        try {
            $model = Orchid::userModel();
        } catch (UnsupportedGuardException) {
            return;
        }

        if (! in_array(HasTwoFactor::class, class_uses_recursive($model), true)) {
            Log::warning(sprintf(
                'nakipelo/orchid-2fa: the user model [%s] does not use the %s trait; '
                .'trusted devices are not reset when the password changes.',
                $model,
                HasTwoFactor::class,
            ));
        }
    }
}
