<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Support;

use Closure;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\Middleware\RedirectIfAuthenticated;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Nakipelo\Orchid2FA\Exceptions\UnsupportedGuardException;
use Orchid\Access\UserAccess;
use Orchid\Platform\Dashboard;
use Orchid\Platform\ItemPermission;
use Orchid\Platform\Models\User as OrchidUser;
use Orchid\Screen\Actions\Menu;
use Orchid\Support\Facades\Toast;
use Tabuna\Breadcrumbs\Trail;

/**
 * Adapter to Orchid (orchid/platform 14.x).
 *
 * The only place in the package where `platform.*` config keys / route names,
 * the `platform::` view namespace and `Orchid\…` classes are referenced.
 * Everything else talks to Orchid through this class.
 *
 * @internal
 */
final class Orchid
{
    private const CONFIG_ROOT = 'platform';

    private const ROUTE_NAME_PREFIX = 'platform.';

    /**
     * Permission that makes two-factor authentication mandatory for its holder (spec §8).
     */
    private const PERMISSION_REQUIRED = 'platform.2fa.required';

    /**
     * Permission to reset two-factor authentication of other users (spec §8).
     */
    private const PERMISSION_RESET = 'platform.systems.users.2fa-reset';

    /**
     * Full config key of an Orchid setting, e.g. `configKey('auth')` → `platform.auth`.
     */
    public static function configKey(string $key): string
    {
        return self::CONFIG_ROOT.'.'.$key;
    }

    public static function guardName(): string
    {
        $guard = config(self::configKey('guard'));

        return is_string($guard) && $guard !== '' ? $guard : (string) config('auth.defaults.guard', 'web');
    }

    /**
     * The Orchid guard. The package needs a session guard: it validates credentials
     * without logging in and logs the user in only after the second factor.
     *
     * @throws UnsupportedGuardException
     */
    public static function guard(): SessionGuard
    {
        $name = self::guardName();
        $guard = Auth::guard($name);

        if (! $guard instanceof SessionGuard) {
            throw new UnsupportedGuardException(sprintf(
                'nakipelo/orchid-2fa requires the Orchid guard to be an instance of %s, but guard [%s] (config [%s]) is %s.',
                SessionGuard::class,
                $name,
                self::configKey('guard'),
                get_debug_type($guard),
            ));
        }

        return $guard;
    }

    /**
     * Eloquent model class of the users served by the Orchid guard.
     *
     * @return class-string<Model>
     */
    public static function userModel(): string
    {
        $provider = self::guard()->getProvider();

        if (! $provider instanceof EloquentUserProvider) {
            throw new UnsupportedGuardException(sprintf(
                'nakipelo/orchid-2fa requires an Eloquent user provider for guard [%s], %s given.',
                self::guardName(),
                get_debug_type($provider),
            ));
        }

        /** @var class-string<Model> $model */
        $model = $provider->getModel();

        return $model;
    }

    public static function routeNamePrefix(): string
    {
        return self::ROUTE_NAME_PREFIX;
    }

    /**
     * Register routes in the same group Orchid uses for its own routes:
     * the Orchid domain and prefix, the `platform.` name prefix and the
     * public or private middleware stack.
     */
    public static function routeGroup(bool $private, Closure $routes): void
    {
        /** @var array<int, string>|string|null $middleware */
        $middleware = config(self::configKey($private ? 'middleware.private' : 'middleware.public'));

        Route::domain((string) config(self::configKey('domain')))
            ->prefix(Dashboard::prefix('/'))
            ->as(self::ROUTE_NAME_PREFIX)
            ->middleware($middleware ?? [])
            ->group($routes);
    }

    /**
     * URL path of the Orchid route prefix (`platform.prefix`), e.g. `/admin`; `/` without a prefix.
     */
    public static function pathPrefix(): string
    {
        return '/'.trim(Dashboard::prefix('/'), '/');
    }

    public static function loginRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'login';
    }

    public static function loginAuthRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'login.auth';
    }

    public static function loginLockRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'login.lock';
    }

    public static function indexUrl(): string
    {
        return route((string) config(self::configKey('index')));
    }

    public static function profileRoute(): string
    {
        return (string) config(self::configKey('profile'), self::ROUTE_NAME_PREFIX.'profile');
    }

    public static function authLayout(): string
    {
        return self::viewNamespace().'::auth';
    }

    public static function viewNamespace(): string
    {
        return 'platform';
    }

    /**
     * Name of the Orchid "lock" cookie. Repeats Orchid's `LoginController::nameForLock()`.
     */
    public static function lockCookieName(): string
    {
        return self::guard()->getName().'__orchid_lock';
    }

    /**
     * The `guest` middleware as Orchid applies it on its login routes, bound to the Orchid guard.
     */
    public static function guestMiddleware(): string
    {
        return RedirectIfAuthenticated::class.':'.self::guardName();
    }

    /**
     * Make `guestMiddleware()` redirect authenticated users to the Orchid index,
     * like Orchid's `LoginController` does in its constructor.
     */
    public static function redirectAuthenticatedToIndex(): void
    {
        RedirectIfAuthenticated::redirectUsing(static fn (): string => self::indexUrl());
    }

    /**
     * @param  array<string, string>  $permissions  permission key => label
     */
    public static function registerPermissions(string $group, array $permissions): void
    {
        $item = ItemPermission::group($group);

        foreach ($permissions as $key => $label) {
            $item->addPermission($key, $label);
        }

        app(Dashboard::class)->registerPermissions($item);
    }

    public static function registerMenu(string $name, string $route, ?string $icon = null, ?string $permission = null): void
    {
        // Menu::route() resolves the URL right away; a route named after it was added (as
        // `Route::screen(...)->name(...)` does) is found only after the name lookups are refreshed.
        Route::getRoutes()->refreshNameLookups();

        $menu = Menu::make($name)->route($route);

        if ($icon !== null) {
            $menu->icon($icon);
        }

        if ($permission !== null) {
            $menu->permission($permission);
        }

        app(Dashboard::class)->registerMenuElement($menu);
    }

    /**
     * Whether Orchid registers its own login routes (`platform.auth`).
     */
    public static function loginRoutesEnabled(): bool
    {
        return (bool) config(self::configKey('auth'), true);
    }

    public static function loginUrl(): string
    {
        return route(self::loginRoute());
    }

    /**
     * The message Orchid shows for wrong credentials (Orchid's `LoginController::login()`).
     * Translated with Orchid's JSON translations, so the response is identical to Orchid's.
     */
    public static function failedLoginMessage(): string
    {
        return (string) __('The details you entered did not match our records. Please double-check and try again.');
    }

    /**
     * Names of the package routes inside the Orchid route group (spec §5.3).
     */
    public static function challengeRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'two-factor.challenge';
    }

    public static function verifyRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'two-factor.verify';
    }

    public static function resendRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'two-factor.resend';
    }

    public static function cancelRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'two-factor.cancel';
    }

    /**
     * Routes of 0.2 (spec 0.2 §6.4): recovery code and e-mail fallback at the code step,
     * enrollment at the login and the recovery codes shown after it.
     */
    public static function recoveryRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'two-factor.recovery';
    }

    public static function fallbackRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'two-factor.fallback';
    }

    public static function enrollRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'two-factor.enroll';
    }

    public static function enrollConfirmRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'two-factor.enroll.confirm';
    }

    public static function recoveryCodesRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'two-factor.recovery-codes';
    }

    public static function recoveryCodesConfirmRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'two-factor.recovery-codes.confirm';
    }

    /**
     * Point `platform.index` (where the final login redirects) to a route (the conformance suite,
     * spec 0.2 §10.2).
     */
    public static function useIndexRoute(string $name): void
    {
        config([self::configKey('index') => $name]);
    }

    public static function requiredPermission(): string
    {
        return self::PERMISSION_REQUIRED;
    }

    public static function resetPermission(): string
    {
        return self::PERMISSION_RESET;
    }

    /**
     * The two-factor profile screen (spec §4.7, §5.3).
     */
    public static function profileTwoFactorRoute(): string
    {
        return self::ROUTE_NAME_PREFIX.'profile.two-factor';
    }

    /**
     * Register a screen in the private Orchid route group (`Route::screen` macro of Orchid),
     * with breadcrumbs "Home > Profile > {title}" (the profile step only if its route exists).
     *
     * @param  class-string  $screen
     * @param  list<string>  $middleware  extra middleware of the screen's route
     */
    public static function registerProfileScreen(string $uri, string $screen, string $name, Closure $title, array $middleware = []): void
    {
        self::routeGroup(true, static function () use ($uri, $screen, $name, $title, $middleware): void {
            Route::screen($uri, $screen)
                ->middleware($middleware)
                ->name(substr($name, strlen(self::ROUTE_NAME_PREFIX)))
                ->breadcrumbs(static function (Trail $trail) use ($title): Trail {
                    $trail->parent(self::ROUTE_NAME_PREFIX.'index');

                    if (Route::has(self::profileRoute())) {
                        $trail->push((string) __('Profile'), route(self::profileRoute()));
                    }

                    return $trail->push((string) $title());
                });
        });
    }

    /**
     * Flash an Orchid toast (`info`, `success`, `warning`, `error`).
     */
    public static function toast(string $message, string $level = 'info'): void
    {
        match ($level) {
            'success' => Toast::success($message),
            'warning' => Toast::warning($message),
            'error' => Toast::error($message),
            default => Toast::info($message),
        };
    }

    /**
     * Whether the user holds an Orchid permission (directly or through a role).
     * Users without Orchid's access trait hold no permissions.
     */
    public static function userHasPermission(Authenticatable $user, string $permission): bool
    {
        if ($user instanceof OrchidUser) {
            return $user->hasAccess($permission);
        }

        // A model with Orchid's access trait that does not extend Orchid's user model.
        if (in_array(UserAccess::class, class_uses_recursive($user), true)) {
            return (bool) call_user_func([$user, 'hasAccess'], $permission);
        }

        return false;
    }
}
