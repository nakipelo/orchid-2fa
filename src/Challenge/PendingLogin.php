<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;

/**
 * "Password is correct, waiting for the code" (spec §3): kept in the server session
 * under `orchid-2fa.pending`. The user stays a guest until the final login.
 *
 * `passwordHash` is a fingerprint of the user's password hash (an HMAC with the app key, as
 * Laravel's AuthenticateSession keeps it), not the hash itself: a password change while the
 * code step is pending ends the pending login (spec §4.2).
 */
final class PendingLogin
{
    public const SESSION_KEY = 'orchid-2fa.pending';

    public function __construct(
        public readonly int|string $userId,
        public readonly bool $remember,
        public readonly int $createdAt,
        public readonly string $challengeId,
        public readonly string $passwordHash,
    ) {}

    /**
     * A new pending login of the user, bound to the current password.
     */
    public static function for(Authenticatable $user, bool $remember, string $challengeId): self
    {
        return new self(
            $user->getAuthIdentifier(),
            $remember,
            now()->getTimestamp(),
            $challengeId,
            self::passwordFingerprint($user),
        );
    }

    public static function fromSession(Session $session): ?self
    {
        $data = $session->get(self::SESSION_KEY);

        if (! is_array($data)
            || ! (is_int($data['user_id'] ?? null) || is_string($data['user_id'] ?? null))
            || ! is_bool($data['remember'] ?? null)
            || ! is_int($data['created_at'] ?? null)
            || ! is_string($data['challenge_id'] ?? null)
            || ! is_string($data['password_hash'] ?? null)) {
            return null;
        }

        return new self($data['user_id'], $data['remember'], $data['created_at'], $data['challenge_id'], $data['password_hash']);
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
            'password_hash' => $this->passwordHash,
        ]);
    }

    public function withChallenge(string $challengeId): self
    {
        return new self($this->userId, $this->remember, $this->createdAt, $challengeId, $this->passwordHash);
    }

    /**
     * The password of the user has not changed since the password step.
     */
    public function matchesPassword(Authenticatable $user): bool
    {
        return hash_equals($this->passwordHash, self::passwordFingerprint($user));
    }

    protected static function passwordFingerprint(Authenticatable $user): string
    {
        return hash_hmac('sha256', (string) $user->getAuthPassword(), (string) config('app.key'));
    }

    public function isExpired(int $ttl): bool
    {
        return $this->createdAt + $ttl <= now()->getTimestamp();
    }
}
