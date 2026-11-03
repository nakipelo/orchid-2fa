<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

/**
 * Why a challenge was issued (spec 0.2 §4.1): the value of `Challenge::$context`, of the `$context`
 * of `TwoFactorChannel::issue()`, of `EnrollmentState::$context` and of `TwoFactorChallengeSent::$context`.
 *
 * Plain string constants, not an enum: the context crosses the driver contract
 * (`issue(Authenticatable, string $context)`) and the public string properties of `Challenge` and of
 * the events (0.1 listeners compare `$event->context` with strings), it is stored as a string in the
 * session (pending login, enrollment state) and in the cache (the stored code), and the actions of the
 * profile double as contexts. An enum would need `->value` at each of those boundaries or a breaking
 * change of their types.
 */
final class Context
{
    /**
     * The code step of the login.
     */
    public const LOGIN = 'login';

    /**
     * Enabling in the profile (the enrollment step of the chosen channel).
     */
    public const ENABLE = 'enable';

    /**
     * Disabling in the profile (the confirmation with the current method).
     */
    public const DISABLE = 'disable';

    /**
     * Changing the method in the profile (the confirmation and the enrollment of the new channel).
     */
    public const SWITCH = 'switch';

    /**
     * Setting the method up again in the profile (the confirmation and the new enrollment).
     */
    public const REBIND = 'rebind';

    /**
     * New recovery codes in the profile (the confirmation with the current method).
     */
    public const REGENERATE = 'regenerate';

    /**
     * The enrollment at the login (spec 0.2 §5.4).
     */
    public const ENROLL = 'enroll';

    /**
     * The e-mail code instead of the code of a verifier channel (spec 0.2 §13).
     */
    public const FALLBACK = 'fallback';

    /**
     * Every context.
     *
     * @var list<string>
     */
    public const ALL = [
        self::LOGIN,
        self::ENABLE,
        self::DISABLE,
        self::SWITCH,
        self::REBIND,
        self::REGENERATE,
        self::ENROLL,
        self::FALLBACK,
    ];

    private function __construct() {}
}
