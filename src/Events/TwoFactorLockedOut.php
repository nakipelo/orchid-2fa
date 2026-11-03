<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Events;

use Illuminate\Contracts\Auth\Authenticatable;

final class TwoFactorLockedOut extends TwoFactorEvent
{
    public const ATTEMPTS_EXCEEDED = 'attempts_exceeded';

    public const SEND_LIMIT = 'send_limit';

    /**
     * @param  int  $availableIn  seconds until a new code can be sent
     */
    public function __construct(
        Authenticatable $user,
        string $guard,
        public readonly string $reason,
        public readonly int $availableIn,
    ) {
        parent::__construct($user, $guard);
    }
}
