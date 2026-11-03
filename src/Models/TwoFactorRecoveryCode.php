<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A recovery code of a user (spec 0.2 §4.7): only the hash of the application hasher.
 *
 * @property int $id
 * @property int $user_id
 * @property string $code_hash
 * @property Carbon|null $used_at
 * @property Carbon|null $created_at
 */
class TwoFactorRecoveryCode extends Model
{
    public const UPDATED_AT = null;

    protected $table = 'two_factor_recovery_codes';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'user_id',
        'code_hash',
        'used_at',
    ];

    /**
     * @var list<string>
     */
    protected $hidden = [
        'code_hash',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'user_id' => 'integer',
            'used_at' => 'datetime',
        ];
    }
}
