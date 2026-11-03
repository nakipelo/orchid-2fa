<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

use Illuminate\Contracts\Session\Session;

/**
 * "Password is correct, waiting for the code" (spec §3): kept in the server session
 * under `orchid-2fa.pending`. The user stays a guest until the final login.
 */
final class PendingLogin
{
    public const SESSION_KEY = 'orchid-2fa.pending';

    public function __construct(
        public readonly int|string $userId,
        public readonly bool $remember,
        public readonly int $createdAt,
        public readonly string $challengeId,
    ) {}

    public static function fromSession(Session $session): ?self
    {
        $data = $session->get(self::SESSION_KEY);

        if (! is_array($data)
            || ! (is_int($data['user_id'] ?? null) || is_string($data['user_id'] ?? null))
            || ! is_bool($data['remember'] ?? null)
            || ! is_int($data['created_at'] ?? null)
            || ! is_string($data['challenge_id'] ?? null)) {
            return null;
        }

        return new self($data['user_id'], $data['remember'], $data['created_at'], $data['challenge_id']);
    }

    public static function forget(Session $session): void
    {
        $session->forget(self::SESSION_KEY);
    }

    public function store(Session $session): void
    {
        $session->put(self::SESSION_KEY, [
            'user_id' => $this->userId,
            'remember' => $this->remember,
            'created_at' => $this->createdAt,
            'challenge_id' => $this->challengeId,
        ]);
    }

    public function withChallenge(string $challengeId): self
    {
        return new self($this->userId, $this->remember, $this->createdAt, $challengeId);
    }

    public function isExpired(int $ttl): bool
    {
        return $this->createdAt + $ttl <= now()->getTimestamp();
    }
}
