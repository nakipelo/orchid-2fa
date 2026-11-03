<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Str;

/**
 * The server-side state of one enrollment step (spec 0.2 §4.1, §4.6): kept in the session under
 * `orchid-2fa.enrollment`, bound to the user, the channel and the context. A driver keeps its
 * step data here (for example a TOTP secret before it is confirmed); it never leaves the server
 * session and is erased when the step is completed or cancelled.
 *
 * It lives `enrollment_ttl` at the login and `profile.confirmation_ttl` in the profile
 * (spec 0.2 §4.1); the caller passes the lifetime to fromSession().
 */
final class EnrollmentState
{
    public const SESSION_KEY = 'orchid-2fa.enrollment';

    /**
     * @param  array<string, mixed>  $data
     */
    private function __construct(
        private readonly Session $session,
        public readonly int|string $userId,
        public readonly string $channel,
        public readonly string $context,
        private readonly string $id,
        public readonly int $startedAt,
        private array $data = [],
    ) {}

    /**
     * A new state with a new id, replacing any previous one.
     */
    public static function start(Session $session, Authenticatable $user, string $channel, string $context): self
    {
        $state = new self($session, $user->getAuthIdentifier(), $channel, $context, Str::random(40), now()->getTimestamp());
        $state->store();

        return $state;
    }

    /**
     * The state of this user, channel and context, unless it is older than `$ttl` seconds.
     */
    public static function fromSession(Session $session, Authenticatable $user, string $channel, string $context, int $ttl): ?self
    {
        $raw = $session->get(self::SESSION_KEY);

        if (! is_array($raw)
            || ! (is_int($raw['user_id'] ?? null) || is_string($raw['user_id'] ?? null))
            || (string) $raw['user_id'] !== (string) $user->getAuthIdentifier()
            || ($raw['channel'] ?? null) !== $channel
            || ($raw['context'] ?? null) !== $context
            || ! is_string($raw['id'] ?? null)
            || ! is_int($raw['started_at'] ?? null)
            || ! is_array($raw['data'] ?? null)
            || now()->getTimestamp() >= $raw['started_at'] + $ttl) {
            return null;
        }

        /** @var array<string, mixed> $data */
        $data = $raw['data'];

        return new self($session, $raw['user_id'], $channel, $context, $raw['id'], $raw['started_at'], $data);
    }

    /**
     * Erase the state (step completed or cancelled).
     */
    public static function forget(Session $session): void
    {
        $session->forget(self::SESSION_KEY);
    }

    /**
     * The id of this enrollment step.
     */
    public function challengeId(): string
    {
        return $this->id;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function put(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
        $this->store();
    }

    private function store(): void
    {
        $this->session->put(self::SESSION_KEY, [
            'user_id' => $this->userId,
            'channel' => $this->channel,
            'context' => $this->context,
            'id' => $this->id,
            'started_at' => $this->startedAt,
            'data' => $this->data,
        ]);
    }
}
