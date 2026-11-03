<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Events;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The second factor was passed; the final login follows. `channel` (0.2) is the name of the
 * user's channel.
 */
final class TwoFactorPassed extends TwoFactorEvent
{
    public const VIA_CODE = 'code';

    public const VIA_TRUSTED_DEVICE = 'trusted_device';

    public function __construct(
        Authenticatable $user,
        string $guard,
        public readonly string $via,
        public readonly bool $trustedDeviceIssued,
        public readonly string $channel,
    ) {
        parent::__construct($user, $guard);
    }
}
