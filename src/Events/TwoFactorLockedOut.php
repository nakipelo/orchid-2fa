<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Events;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The attempts of a code or the send limits are exhausted.
 */
final class TwoFactorLockedOut extends TwoFactorEvent
{
    public const ATTEMPTS_EXCEEDED = 'attempts_exceeded';

    public const SEND_LIMIT = 'send_limit';

    /**
     * @param  int  $availableIn  seconds until a new code can be sent
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
