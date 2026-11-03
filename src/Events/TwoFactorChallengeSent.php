<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Events;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * A code was issued and handed over to the channel.
 */
final class TwoFactorChallengeSent extends TwoFactorEvent
{
    public const CONTEXT_LOGIN = 'login';

    public const CONTEXT_ENABLE = 'enable';

    public const CONTEXT_DISABLE = 'disable';

    public function __construct(
        Authenticatable $user,
        string $guard,
        public readonly string $channel,
        public readonly string $maskedDestination,
        public readonly string $context,
    ) {
        parent::__construct($user, $guard);
    }
}
