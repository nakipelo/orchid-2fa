<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\TwoFactorManager;

/**
 * Add to the user model of the Orchid guard (`App\Models\User`).
 *
 * A password change invalidates the trusted devices of the user (spec §4.4, §5.5); an e-mail
 * change sends a notice to the old address and makes the next login confirm the new one (§4.9).
 *
 * @mixin Model
 */
trait HasTwoFactor
{
    /**
     * Any `save()` that changes the password (profile, UserEditScreen, password reset)
     * invalidates the trusted device cookies; any `save()` that changes the address
     * (`channels.email.attribute`) is handled by TwoFactorManager::addressChanged().
     * Mass updates through the query builder fire no model events.
     */
    public static function bootHasTwoFactor(): void
    {
        static::updating(static function (Model $user): void {
            if ($user->isDirty('password')) {
                TwoFactorAuthentication::bumpTrustedDevicesVersionFor($user->getKey());
                $user->unsetRelation('twoFactor');
            }
        });

        static::updated(static function (Model $user): void {
            $attribute = (string) config('orchid-2fa.channels.email.attribute', 'email');

            if (! $user instanceof Authenticatable || ! $user->wasChanged($attribute)) {
                return;
            }

            $old = $user->getOriginal($attribute);

            app(TwoFactorManager::class)->addressChanged($user, is_string($old) ? trim($old) : '');
            $user->unsetRelation('twoFactor');
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
