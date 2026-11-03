<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Exceptions;

use RuntimeException;

/**
 * The resend cooldown or the hourly send limit of the user is exhausted (spec §4.11).
 */
class SendLimitExceededException extends RuntimeException
{
    public function __construct(public readonly int $availableIn)
    {
        parent::__construct(sprintf('Two-factor code send limit exceeded, available in %d s.', $availableIn));
    }
}
