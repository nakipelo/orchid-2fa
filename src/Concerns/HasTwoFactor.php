<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;

/**
 * Add to the user model of the Orchid guard (`App\Models\User`).
 *
 * A password change invalidates the trusted devices of the user (spec §4.4, §5.5).
 * The e-mail change listener (§4.9) is added in a later stage.
 *
 * @mixin Model
 */
trait HasTwoFactor
{
    /**
     * Any `save()` that changes the password (profile, UserEditScreen, password reset)
     * invalidates the trusted device cookies. Mass updates through the query builder
     * fire no model events.
     */
    public static function bootHasTwoFactor(): void
    {
        static::updating(static function (Model $user): void {
            if ($user->isDirty('password')) {
                TwoFactorAuthentication::bumpTrustedDevicesVersionFor($user->getKey());
                $user->unsetRelation('twoFactor');
            }
        });
    }

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
     * Invalidate all trusted device cookies of the user ("sign out of all trusted devices").
     *
     * Without a record no trusted device cookie can exist, so nothing is created.
     */
    public function bumpTrustedDevicesVersion(): void
    {
        TwoFactorAuthentication::bumpTrustedDevicesVersionFor($this->getKey());

        $this->unsetRelation('twoFactor');
    }
}
