<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Events;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * A code was issued and handed over to a delivery channel (a verifier channel sends nothing,
 * spec 0.2 §4.6).
 */
final class TwoFactorChallengeSent extends TwoFactorEvent
{
    public const CONTEXT_LOGIN = 'login';

    public const CONTEXT_ENABLE = 'enable';

    public const CONTEXT_DISABLE = 'disable';

    public const CONTEXT_SWITCH = 'switch';

    public const CONTEXT_REBIND = 'rebind';

    public const CONTEXT_REGENERATE = 'regenerate';

    public const CONTEXT_ENROLL = 'enroll';

    public const CONTEXT_FALLBACK = 'fallback';

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
