<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Channels;

use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;

/**
 * The method of a user as the registry resolves it (spec 0.2 §4.5): `TwoFactor::methodFor($user)`.
 * Public API: a driver or an application may read it, e.g. to tell "no method yet" from "the driver
 * of the method is gone".
 *
 * - `active`: the enrolled and allowed method (item 1) or the default channel (item 4);
 * - `proof`: an enrolled method that is no longer allowed: used once as the proof, then an allowed
 *   method has to be enrolled (item 2, §5.4 B);
 * - `unavailable`: the driver of the recorded method is not registered or cannot be created
 *   (item 3): fail closed;
 * - `none`: no method, enrollment at the login (item 4, §5.4 A).
 *
 * `channel` is set for `active` and `proof` (the same channel TwoFactor::for() returns) and null
 * otherwise; `recorded` is the raw `two_factor_authentications.channel` (null — none), also for a
 * channel whose driver is gone.
 */
final readonly class UserMethod
{
    public const ACTIVE = 'active';

    public const PROOF = 'proof';

    public const UNAVAILABLE = 'unavailable';

    public const NONE = 'none';

    /**
     * @param  self::*  $state
     * @param  string|null  $recorded  `two_factor_authentications.channel`
     */
    public function __construct(
        public string $state,
        public ?TwoFactorChannel $channel,
        public ?string $recorded,
    ) {}

    /**
     * The user has to enroll an allowed method at the login: `proof` (after the proof) or `none`.
     */
    public function needsEnrollment(): bool
    {
        return $this->state === self::PROOF || $this->state === self::NONE;
    }
}
