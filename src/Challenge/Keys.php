<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

/**
 * Rate limiter keys of the codes (spec §5.9 of 0.1, unchanged in 0.2 §4.2): one active method per
 * user, so delivery channels share them.
 *
 * @internal
 */
final class Keys
{
    /**
     * Wrong attempts of one challenge, counted by the ChallengeManager for every channel.
     */
    public static function verify(int|string $userId, string $challengeId): string
    {
        return 'orchid-2fa:verify:'.$userId.':'.$challengeId;
    }

    /**
     * Sends of the last hour.
     */
    public static function send(int|string $userId): string
    {
        return 'orchid-2fa:send:'.$userId;
    }

    /**
     * Cooldown between sends.
     */
    public static function cooldown(int|string $userId): string
    {
        return 'orchid-2fa:cooldown:'.$userId;
    }

    /**
     * Wrong codes of a verifier channel and wrong recovery codes of the user in the window
     * `verify.user_decay` (spec 0.2 §4.4).
     */
    public static function verifierWindow(int|string $userId): string
    {
        return 'orchid-2fa:verifier:'.$userId;
    }

    /**
     * The same attempts in a fixed 24 h window (spec 0.2 §4.4).
     */
    public static function verifierDay(int|string $userId): string
    {
        return 'orchid-2fa:verifier-day:'.$userId;
    }

    /**
     * Marker of the last `attempts_exceeded` security notification (spec 0.2 §4.4, §8.3).
     */
    public static function alert(int|string $userId): string
    {
        return 'orchid-2fa:alert:'.$userId;
    }
}
