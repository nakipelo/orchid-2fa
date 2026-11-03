<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

/**
 * Outcome of ChallengeManager::verify().
 */
enum VerificationResult: string
{
    /** The code is correct and has been consumed. */
    case Passed = 'passed';

    /** Wrong code, attempts are left. */
    case Invalid = 'invalid';

    /** No valid code for this challenge (expired, used, superseded, address changed). */
    case Expired = 'expired';

    /** Wrong code and the attempts are exhausted: the code has been annulled. */
    case LockedOut = 'locked_out';
}
