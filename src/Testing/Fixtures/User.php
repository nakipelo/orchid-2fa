<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Fixtures;

use Nakipelo\Orchid2FA\Concerns\HasTwoFactor;
use Orchid\Platform\Models\User as OrchidUser;

/**
 * The user model of the conformance suite (spec 0.2 §10.2): Orchid's user with HasTwoFactor.
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property string|null $remember_token
 */
class User extends OrchidUser
{
    use HasTwoFactor;

    protected $table = 'users';

    /**
     * @var list<string>
     */
    protected $fillable = ['name', 'email', 'password'];

    /**
     * @var array<string, string>
     */
    protected $casts = [
        'permissions' => 'array',
        'email_verified_at' => 'datetime',
    ];
}
