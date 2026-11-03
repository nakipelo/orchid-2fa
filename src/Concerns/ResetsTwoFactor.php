<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TwoFactorManager;

/**
 * Add to `UserEditScreen` together with `TwoFactorResetLayout` (spec §4.8, §6). The screen
 * method `resetTwoFactor` resets 2FA of the user of the route parameter `{user}`.
 *
 * The reset permission (`Orchid::resetPermission()`, spec §8) is checked on the server as well:
 * a request without it gets 403, whatever the UI shows.
 */
trait ResetsTwoFactor
{
    /**
     * @param  mixed  $user  the `{user}` route parameter: the bound model or its key
     */
    public function resetTwoFactor(TwoFactorManager $manager, mixed $user = null): void
    {
        $admin = Orchid::guard()->user();

        abort_unless($admin !== null && Orchid::userHasPermission($admin, Orchid::resetPermission()), 403);

        if (! $user instanceof Authenticatable) {
            $user = is_int($user) || (is_string($user) && $user !== '')
                ? Orchid::guard()->getProvider()->retrieveById($user)
                : null;
        }

        abort_if($user === null, 404);

        $manager->reset($user);

        Orchid::toast((string) __('orchid-2fa::messages.reset.done'), 'success');
    }
}
