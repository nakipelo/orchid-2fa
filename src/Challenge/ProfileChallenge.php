<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

use Illuminate\Contracts\Session\Session;

/**
 * A code sent from the profile screen to enable or disable two-factor authentication
 * (spec §4.7): kept in the server session under `orchid-2fa.profile`. The code confirms only
 * the action it was requested for, and only for the user who requested it.
 */
final class ProfileChallenge
{
    public const SESSION_KEY = 'orchid-2fa.profile';

    public const ENABLE = 'enable';

    public const DISABLE = 'disable';

    /**
     * @param  self::ENABLE|self::DISABLE  $action
     */
    public function __construct(
        public readonly int|string $userId,
        public readonly string $action,
        public readonly string $challengeId,
    ) {}

    /**
     * The challenge of the user, if any.
     */
    public static function fromSession(Session $session, int|string $userId): ?self
    {
        $data = $session->get(self::SESSION_KEY);

        if (! is_array($data)
            || ! (is_int($data['user_id'] ?? null) || is_string($data['user_id'] ?? null))
            || (string) $data['user_id'] !== (string) $userId
            || ! in_array($data['action'] ?? null, [self::ENABLE, self::DISABLE], true)
            || ! is_string($data['challenge_id'] ?? null)) {
            return null;
        }

        return new self($data['user_id'], $data['action'], $data['challenge_id']);
    }

    public static function forget(Session $session): void
    {
        $session->forget(self::SESSION_KEY);
    }

    public function store(Session $session): void
    {
        $session->put(self::SESSION_KEY, [
            'user_id' => $this->userId,
            'action' => $this->action,
            'challenge_id' => $this->challengeId,
        ]);
    }
}
