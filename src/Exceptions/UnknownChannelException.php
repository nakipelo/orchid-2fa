<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Exceptions;

use InvalidArgumentException;

/**
 * No driver is registered under the channel name (spec 0.2 §4.3).
 */
class UnknownChannelException extends InvalidArgumentException
{
    public static function named(string $name): self
    {
        return new self(sprintf(
            'The two-factor channel [%s] is not registered: set [orchid-2fa.channels.%s.driver] or call TwoFactor::extend().',
            $name,
            $name,
        ));
    }
}
