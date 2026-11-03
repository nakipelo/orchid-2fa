<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Events;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The method of the user changed (spec 0.2 §8.2): enrolled, switched, rebound, disabled or reset.
 */
final class TwoFactorChannelChanged extends TwoFactorEvent
{
    public const ENROLLED = 'enrolled';

    public const SWITCHED = 'switched';

    public const REBOUND = 'rebound';

    public const DISABLED = 'disabled';

    public const RESET = 'reset';

    public function __construct(
        Authenticatable $user,
        string $guard,
        public readonly ?string $from,
        public readonly ?string $to,
        public readonly string $reason,
    ) {
        parent::__construct($user, $guard);
    }
}
