<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Nakipelo\Orchid2FA\Concerns\HasTwoFactor;
use Nakipelo\Orchid2FA\Console\ResetTwoFactorCommand;
use Nakipelo\Orchid2FA\Console\RotateRememberTokensCommand;
use Nakipelo\Orchid2FA\Exceptions\UnsupportedGuardException;
use Nakipelo\Orchid2FA\Http\Controllers\ChallengeController;
use Nakipelo\Orchid2FA\Http\Controllers\LoginController;
use Nakipelo\Orchid2FA\Listeners\LogTwoFactorEvents;
use Nakipelo\Orchid2FA\Screens\TwoFactorProfileScreen;
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
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'orchid-2fa');
        $this->loadTranslationsFrom(__DIR__.'/../lang', 'orchid-2fa');

        if (config('orchid-2fa.log.enabled')) {
            $this->app->make(Dispatcher::class)->subscribe(LogTwoFactorEvents::class);
        }

        if ($this->app->runningInConsole()) {
            $this->commands([
                ResetTwoFactorCommand::class,
                RotateRememberTokensCommand::class,
            ]);

            $this->publishes([
                __DIR__.'/../config/orchid-2fa.php' => config_path('orchid-2fa.php'),
            ], 'orchid-2fa-config');

            // Not publishesMigrations(): it renames the copy with the current timestamp, and the
            // migrator, which also loads the package's own file (loadMigrationsFrom), would run
            // both and fail on the existing table. Under the same name the published copy
            // replaces the package's file (migrations are keyed by name, the app's path wins).
            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'orchid-2fa-migrations');

            $this->publishes([
                __DIR__.'/../resources/views' => resource_path('views/vendor/orchid-2fa'),
            ], 'orchid-2fa-views');

            $this->publishes([
                __DIR__.'/../lang' => $this->app->langPath('vendor/orchid-2fa'),
            ], 'orchid-2fa-translations');
        }

        // Orchid loads its routes in a "booted" callback of its RouteServiceProvider,
        // i.e. while the application boots. Application "booted" callbacks run after
        // all providers have booted, so routes registered here come after Orchid's.
        $this->app->booted(function (): void {
            $this->ensureSessionGuard();
            $this->registerPermissions();
            $this->registerLoginRoute();
            $this->registerChallengeRoutes();
            $this->registerProfileRoutes();
            $this->registerMenu();
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
     * The code step routes (spec §5.3). Registered also when Orchid's own login routes are disabled.
     */
    protected function registerChallengeRoutes(): void
    {
        if ($this->app->routesAreCached()) {
            return;
        }

        Orchid::routeGroup(false, function (): void {
            $guest = Orchid::guestMiddleware();
            $throttle = $this->challengeThrottle();

            Route::get('two-factor', [ChallengeController::class, 'show'])
                ->middleware($guest)
                ->name($this->localRouteName(Orchid::challengeRoute()));

            Route::post('two-factor', [ChallengeController::class, 'verify'])
                ->middleware([$guest, $throttle])
                ->name($this->localRouteName(Orchid::verifyRoute()));

            Route::post('two-factor/resend', [ChallengeController::class, 'resend'])
                ->middleware([$guest, $throttle])
                ->name($this->localRouteName(Orchid::resendRoute()));

            Route::post('two-factor/cancel', [ChallengeController::class, 'cancel'])
                ->middleware($guest)
                ->name($this->localRouteName(Orchid::cancelRoute()));
        });
    }

    /**
     * Per-IP `throttle` from `routes.throttle` ("max,minutes"). The own prefix keeps its
     * counter apart from the `throttle:60,1` of `POST login`, which has the same IP signature.
     */
    protected function challengeThrottle(): string
    {
        $parts = array_map('trim', explode(',', (string) config('orchid-2fa.routes.throttle', '10,1')));

        $max = $parts[0] !== '' ? $parts[0] : '10';
        $minutes = ($parts[1] ?? '') !== '' ? $parts[1] : '1';

        return 'throttle:'.$max.','.$minutes.',orchid-2fa';
    }

    /**
     * The two-factor profile screen in the private Orchid group (spec §4.7, §5.3).
     */
    protected function registerProfileRoutes(): void
    {
        if ($this->app->routesAreCached()) {
            return;
        }

        Orchid::registerProfileScreen(
            'profile/two-factor',
            TwoFactorProfileScreen::class,
            Orchid::profileTwoFactorRoute(),
            static fn (): string => (string) __('orchid-2fa::messages.profile.title'),
        );
    }

    /**
     * The main menu item, only with `menu.enabled` (spec §4.7, §6): Orchid 14 has no profile menu.
     */
    protected function registerMenu(): void
    {
        if (! config('orchid-2fa.menu.enabled', false)) {
            return;
        }

        Orchid::registerMenu(
            (string) __('orchid-2fa::messages.profile.title'),
            Orchid::profileTwoFactorRoute(),
            'bs.shield-lock',
        );
    }

    protected function registerPermissions(): void
    {
        Orchid::registerPermissions((string) __('orchid-2fa::messages.permissions.group'), [
            Orchid::requiredPermission() => (string) __('orchid-2fa::messages.permissions.required'),
            Orchid::resetPermission() => (string) __('orchid-2fa::messages.permissions.reset'),
        ]);
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
