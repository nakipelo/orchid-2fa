<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Nakipelo\Orchid2FA\Support\Orchid;

/**
 * Two-factor state of a user. Created lazily (spec §4.7).
 *
 * @property int $id
 * @property int $user_id
 * @property string $channel
 * @property Carbon|null $enabled_at voluntary enablement
 * @property Carbon|null $confirmed_at the current address was confirmed with a code
 * @property int $trusted_devices_version
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class TwoFactorAuthentication extends Model
{
    protected $table = 'two_factor_authentications';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'user_id',
        'channel',
        'enabled_at',
        'confirmed_at',
        'trusted_devices_version',
    ];

    /**
     * @var array<string, mixed>
     */
    protected $attributes = [
        'channel' => 'email',
        'trusted_devices_version' => 1,
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'user_id' => 'integer',
            'enabled_at' => 'datetime',
            'confirmed_at' => 'datetime',
            'trusted_devices_version' => 'integer',
        ];
    }

    /**
     * @return BelongsTo<Model, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(Orchid::userModel(), 'user_id');
    }

    public function isEnabled(): bool
    {
        return $this->enabled_at !== null;
    }

    /**
     * Invalidate all trusted device cookies of the user (spec §4.4): "sign out of all
     * trusted devices", password change, disabling and resetting 2FA. Works without the
     * HasTwoFactor trait. Without a record no trusted device cookie can exist, so nothing is created.
     */
    public static function bumpTrustedDevicesVersionFor(int|string $userId): void
    {
        static::query()->where('user_id', $userId)->increment('trusted_devices_version');
    }
}
