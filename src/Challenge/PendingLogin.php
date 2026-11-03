<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;

/**
 * "Password is correct, waiting for the code" (spec §3): kept in the server session
 * under `orchid-2fa.pending`. The user stays a guest until the final login.
 *
 * `passwordHash` is a fingerprint of the user's password hash (an HMAC with the app key, as
 * Laravel's AuthenticateSession keeps it), not the hash itself: a password change while the
 * code step is pending ends the pending login (spec §4.2).
 *
 * 0.2 (spec 0.2 §4.9): `channel` and `context` of the challenge; `stage` — `challenge` (the code
 * step), `enroll` (enrollment at the login, §5.4) or `recovery_codes` (showing the new codes);
 * `via` — how the challenge before the enrollment was passed (`code` | `recovery_code`, null for
 * an enrollment without a method); `stageStartedAt` — the start of the enrollment, from which
 * `enrollment_ttl` counts instead of `pending_ttl`. A pending login of 0.1.1 or of stage 1 of 0.2
 * without them is not accepted.
 *
 * @internal
 */
final class PendingLogin
{
    public const SESSION_KEY = 'orchid-2fa.pending';

    public const STAGE_CHALLENGE = 'challenge';

    public const STAGE_ENROLL = 'enroll';

    public const STAGE_RECOVERY_CODES = 'recovery_codes';

    public const VIA_CODE = 'code';

    public const VIA_RECOVERY_CODE = 'recovery_code';

    /**
     * @param  self::STAGE_*  $stage
     * @param  self::VIA_*|null  $via
     */
    public function __construct(
        public readonly int|string $userId,
        public readonly bool $remember,
        public readonly int $createdAt,
        public readonly string $challengeId,
        public readonly string $passwordHash,
        public readonly string $channel,
        public readonly string $context = TwoFactorChallengeSent::CONTEXT_LOGIN,
        public readonly string $stage = self::STAGE_CHALLENGE,
        public readonly ?string $via = null,
        public readonly ?int $stageStartedAt = null,
    ) {}

    /**
     * A new pending login of the user at the code step, bound to the current password.
     */
    public static function for(Authenticatable $user, bool $remember, string $challengeId, string $channel): self
    {
        return new self(
            $user->getAuthIdentifier(),
            $remember,
            now()->getTimestamp(),
            $challengeId,
            self::passwordFingerprint($user),
            $channel,
        );
    }

    /**
     * A new pending login that starts with the enrollment (the user has no method, spec 0.2 §5.4 A).
     */
    public static function forEnrollment(Authenticatable $user, bool $remember): self
    {
        return (new self(
            $user->getAuthIdentifier(),
            $remember,
            now()->getTimestamp(),
            '',
            self::passwordFingerprint($user),
            '',
        ))->toEnrollment(null);
    }

    public static function fromSession(Session $session): ?self
    {
        $data = $session->get(self::SESSION_KEY);

        if (! is_array($data)
            || ! (is_int($data['user_id'] ?? null) || is_string($data['user_id'] ?? null))
            || ! is_bool($data['remember'] ?? null)
            || ! is_int($data['created_at'] ?? null)
            || ! is_string($data['challenge_id'] ?? null)
            || ! is_string($data['password_hash'] ?? null)
            || ! is_string($data['channel'] ?? null)
            || ! is_string($data['context'] ?? null)
            || ! in_array($data['stage'] ?? null, [self::STAGE_CHALLENGE, self::STAGE_ENROLL, self::STAGE_RECOVERY_CODES], true)
            || ! in_array($data['via'] ?? null, [null, self::VIA_CODE, self::VIA_RECOVERY_CODE], true)
            || ! (is_int($data['stage_started_at'] ?? null) || ($data['stage_started_at'] ?? null) === null)
            || ($data['stage'] !== self::STAGE_CHALLENGE && ! is_int($data['stage_started_at']))) {
            return null;
        }

        return new self(
            $data['user_id'],
            $data['remember'],
            $data['created_at'],
            $data['challenge_id'],
            $data['password_hash'],
            $data['channel'],
            $data['context'],
            $data['stage'],
            $data['via'],
            $data['stage_started_at'],
        );
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
            'channel' => $this->channel,
            'context' => $this->context,
            'stage' => $this->stage,
            'via' => $this->via,
            'stage_started_at' => $this->stageStartedAt,
        ]);
    }

    /**
     * The same pending login with another challenge (resend, e-mail fallback); `$channel` — when
     * the challenge belongs to another channel.
     */
    public function withChallenge(string $challengeId, ?string $channel = null, string $context = TwoFactorChallengeSent::CONTEXT_LOGIN): self
    {
        return new self(
            $this->userId,
            $this->remember,
            $this->createdAt,
            $challengeId,
            $this->passwordHash,
            $channel ?? $this->channel,
            $context,
            $this->stage,
            $this->via,
            $this->stageStartedAt,
        );
    }

    /**
     * The enrollment step starts now (spec 0.2 §5.4 item 7).
     *
     * @param  self::VIA_*|null  $via
     */
    public function toEnrollment(?string $via): self
    {
        return new self(
            $this->userId,
            $this->remember,
            $this->createdAt,
            $this->challengeId,
            $this->passwordHash,
            $this->channel,
            $this->context,
            self::STAGE_ENROLL,
            $via,
            now()->getTimestamp(),
        );
    }

    /**
     * The new recovery codes are shown (spec 0.2 §5.4 item 6); the enrollment deadline stays.
     */
    public function toRecoveryCodes(string $channel): self
    {
        return new self(
            $this->userId,
            $this->remember,
            $this->createdAt,
            $this->challengeId,
            $this->passwordHash,
            $channel,
            $this->context,
            self::STAGE_RECOVERY_CODES,
            $this->via,
            $this->stageStartedAt,
        );
    }

    /**
     * The challenge of the code step.
     */
    public function challenge(): Challenge
    {
        return new Challenge($this->challengeId, $this->channel, $this->context);
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

    /**
     * The code step expires `$ttl` seconds after the password step; the enrollment and the
     * recovery codes `$enrollmentTtl` seconds after the enrollment started (spec 0.2 §5.4 item 7).
     */
    public function isExpired(int $ttl, ?int $enrollmentTtl = null): bool
    {
        if ($this->stage !== self::STAGE_CHALLENGE && $enrollmentTtl !== null) {
            return ($this->stageStartedAt ?? 0) + $enrollmentTtl <= now()->getTimestamp();
        }

        return $this->createdAt + $ttl <= now()->getTimestamp();
    }
}
