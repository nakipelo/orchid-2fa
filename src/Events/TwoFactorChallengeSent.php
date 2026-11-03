<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Nakipelo\Orchid2FA\Challenge\Context;

/**
 * A code was issued and handed over to a delivery channel (a verifier channel sends nothing,
 * spec 0.2 §4.6). `context` — why the code was issued (Challenge\Context).
 */
final class TwoFactorChallengeSent extends TwoFactorEvent
{
    /**
     * @deprecated 0.2 Use Challenge\Context::LOGIN; removed in 0.3.
     */
    public const CONTEXT_LOGIN = Context::LOGIN;

    /**
     * @deprecated 0.2 Use Challenge\Context::ENABLE; removed in 0.3.
     */
    public const CONTEXT_ENABLE = Context::ENABLE;

    /**
     * @deprecated 0.2 Use Challenge\Context::DISABLE; removed in 0.3.
     */
    public const CONTEXT_DISABLE = Context::DISABLE;

    /**
     * @param  string  $context  a Challenge\Context value
     */
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
