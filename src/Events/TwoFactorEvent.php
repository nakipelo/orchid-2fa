<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Events;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Common part of the package events (spec §5.7): the user and the guard name.
 */
abstract class TwoFactorEvent
{
    public function __construct(
        public readonly Authenticatable $user,
        public readonly string $guard,
    ) {}
}
