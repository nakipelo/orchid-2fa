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

    public function __construct(
        Authenticatable $user,
        string $guard,
        public readonly string $reason,
        public readonly string $channel,
    ) {
        parent::__construct($user, $guard);
    }
}
