<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Events;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * A recovery code was accepted (spec 0.2 §4.7, §8.2), at the login or in the profile.
 */
final class RecoveryCodeUsed extends TwoFactorEvent
{
    public const CONTEXT_LOGIN = 'login';

    public const CONTEXT_PROFILE = 'profile';

    public function __construct(
        Authenticatable $user,
        string $guard,
        public readonly string $channel,
        public readonly int $remaining,
        public readonly string $context,
    ) {
        parent::__construct($user, $guard);
    }
}
