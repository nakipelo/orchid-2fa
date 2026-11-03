<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Events;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The user issued a new set of recovery codes in the profile (spec 0.2 §5.9, §8.2).
 */
final class RecoveryCodesRegenerated extends TwoFactorEvent
{
    public function __construct(
        Authenticatable $user,
        string $guard,
        public readonly string $channel,
        public readonly int $count,
    ) {
        parent::__construct($user, $guard);
    }
}
