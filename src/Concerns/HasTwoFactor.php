<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;

/**
 * Add to the user model of the Orchid guard (`App\Models\User`).
 *
 * Model listeners (password → trusted devices version, e-mail change → §4.9)
 * are added in later stages.
 *
 * @mixin Model
 */
trait HasTwoFactor
{
    /**
     * @return HasOne<TwoFactorAuthentication, $this>
     */
    public function twoFactor(): HasOne
    {
        return $this->hasOne(TwoFactorAuthentication::class, 'user_id');
    }

    /**
     * The existing record or a new unsaved one bound to this user.
     */
    public function twoFactorRecord(): TwoFactorAuthentication
    {
        return $this->twoFactor()->firstOrNew();
    }

    /**
     * Whether the user enabled two-factor authentication voluntarily (`enabled_at` is set).
     */
    public function hasTwoFactorEnabled(): bool
    {
        return $this->twoFactor()->whereNotNull('enabled_at')->exists();
    }

    /**
     * Invalidate all trusted device cookies of the user.
     *
     * Without a record no trusted device cookie can exist, so nothing is created.
     */
    public function bumpTrustedDevicesVersion(): void
    {
        $this->twoFactor()->increment('trusted_devices_version');

        $this->unsetRelation('twoFactor');
    }
}
