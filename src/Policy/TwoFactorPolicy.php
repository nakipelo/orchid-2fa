<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Policy;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Support\Orchid;

/**
 * Who has to pass the second factor (spec §3).
 */
class TwoFactorPolicy
{
    public function __construct(protected Repository $config) {}

    /**
     * Enforced: `enforce_all` or the "2fa.required" Orchid permission.
     */
    public function isEnforced(Authenticatable $user): bool
    {
        return (bool) $this->config->get('orchid-2fa.enforce_all', false)
            || Orchid::userHasPermission($user, Orchid::requiredPermission());
    }

    /**
     * Voluntary: enabled by the user (`enabled_at` is set).
     */
    public function isEnabled(Authenticatable $user): bool
    {
        return $this->record($user)?->isEnabled() ?? false;
    }

    public function requires(Authenticatable $user): bool
    {
        return $this->isEnforced($user) || $this->isEnabled($user);
    }

    /**
     * The current address was confirmed with a code (spec §4.9).
     */
    public function isConfirmed(Authenticatable $user): bool
    {
        return $this->record($user)?->confirmed_at !== null;
    }

    /**
     * Status shown in the UI (spec §6): `required` (enforced), `enabled` (voluntary) or `disabled`.
     *
     * @return 'required'|'enabled'|'disabled'
     */
    public function status(Authenticatable $user): string
    {
        return match (true) {
            $this->isEnforced($user) => 'required',
            $this->isEnabled($user) => 'enabled',
            default => 'disabled',
        };
    }

    public function record(Authenticatable $user): ?TwoFactorAuthentication
    {
        return TwoFactorAuthentication::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->first();
    }
}
