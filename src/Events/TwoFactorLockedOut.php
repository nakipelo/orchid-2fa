<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Events;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The attempts of a code or the send limits are exhausted; for verifier channels and recovery
 * codes also the attempts of the user in the window or in the day (spec 0.2 §4.4).
 */
final class TwoFactorLockedOut extends TwoFactorEvent
{
    public const ATTEMPTS_EXCEEDED = 'attempts_exceeded';

    public const SEND_LIMIT = 'send_limit';

    /**
     * `verify.user_max_attempts` per `verify.user_decay` exhausted.
     */
    public const USER_ATTEMPTS_EXCEEDED = 'user_attempts_exceeded';

    /**
     * `verify.user_max_per_day` exhausted.
     */
    public const USER_DAILY_ATTEMPTS_EXCEEDED = 'user_daily_attempts_exceeded';

    /**
     * @param  int  $availableIn  seconds until a new code can be sent or, for the user limits, until they are over
     * @param  string  $channel  name of the channel of the challenge (0.2)
     */
    public function __construct(
        Authenticatable $user,
        string $guard,
        public readonly string $reason,
        public readonly int $availableIn,
        public readonly string $channel,
    ) {
        parent::__construct($user, $guard);
    }
}
