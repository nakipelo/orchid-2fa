<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Events;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * A code was refused or could not be delivered. `channel` (0.2) is the name of the channel of
 * the challenge.
 */
final class TwoFactorFailed extends TwoFactorEvent
{
    public const INVALID_CODE = 'invalid_code';

    /**
     * No valid code for the pending login: expired, used, superseded or bound to another address.
     */
    public const EXPIRED = 'expired';

    public const DELIVERY_FAILED = 'delivery_failed';

    /**
     * A wrong recovery code (spec 0.2 §4.7).
     */
    public const INVALID_RECOVERY_CODE = 'invalid_recovery_code';

    /**
     * The driver of the user's method is not registered (spec 0.2 §4.5 item 3) or no channel is
     * allowed (§4.3): the login fails closed.
     */
    public const CHANNEL_UNAVAILABLE = 'channel_unavailable';

    public function __construct(
        Authenticatable $user,
        string $guard,
        public readonly string $reason,
        public readonly string $channel,
    ) {
        parent::__construct($user, $guard);
    }
}
