<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

use Illuminate\Contracts\Session\Session;

/**
 * A pending change of the profile screen (spec §4.7, 0.2 §4.9, §5.5–§5.9): kept in the server
 * session under `orchid-2fa.profile`, bound to the user, the action and the target channel.
 *
 * - `step = confirm_current`: the current method (and the password) confirms the action; the
 *   challenge is `challengeId` of `channel`;
 * - `step = enroll`: the target channel is being enrolled (its EnrollmentState); `confirmedAt` is
 *   when the current method confirmed the action (null for enabling, which needs no confirmation);
 * - `step = show_codes`: the new recovery codes are shown once.
 *
 * The password is never kept here: it is checked in the confirming request and dropped.
 *
 * @internal
 */
final class ProfileChallenge
{
    public const SESSION_KEY = 'orchid-2fa.profile';

    public const ENABLE = 'enable';

    public const DISABLE = 'disable';

    public const SWITCH = 'switch';

    public const REBIND = 'rebind';

    public const REGENERATE = 'regenerate';

    public const STEP_CONFIRM_CURRENT = 'confirm_current';

    public const STEP_ENROLL = 'enroll';

    public const STEP_SHOW_CODES = 'show_codes';

    private const ACTIONS = [self::ENABLE, self::DISABLE, self::SWITCH, self::REBIND, self::REGENERATE];

    private const STEPS = [self::STEP_CONFIRM_CURRENT, self::STEP_ENROLL, self::STEP_SHOW_CODES];

    /**
     * @param  self::ENABLE|self::DISABLE|self::SWITCH|self::REBIND|self::REGENERATE  $action
     * @param  self::STEP_*  $step
     */
    public function __construct(
        public readonly int|string $userId,
        public readonly string $action,
        public readonly string $challengeId,
        public readonly string $channel,
        public readonly ?string $target = null,
        public readonly string $step = self::STEP_CONFIRM_CURRENT,
        public readonly ?int $confirmedAt = null,
    ) {}

    /**
     * The pending change of the user, if any.
     */
    public static function fromSession(Session $session, int|string $userId): ?self
    {
        $data = $session->get(self::SESSION_KEY);

        if (! is_array($data)
            || ! (is_int($data['user_id'] ?? null) || is_string($data['user_id'] ?? null))
            || (string) $data['user_id'] !== (string) $userId
            || ! in_array($data['action'] ?? null, self::ACTIONS, true)
            || ! is_string($data['challenge_id'] ?? null)
            || ! is_string($data['channel'] ?? null)
            || ! (is_string($data['target'] ?? null) || ($data['target'] ?? null) === null)
            || ! in_array($data['step'] ?? null, self::STEPS, true)
            || ! (is_int($data['confirmed_at'] ?? null) || ($data['confirmed_at'] ?? null) === null)) {
            return null;
        }

        return new self(
            $data['user_id'],
            $data['action'],
            $data['challenge_id'],
            $data['channel'],
            $data['target'],
            $data['step'],
            $data['confirmed_at'],
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
            'action' => $this->action,
            'challenge_id' => $this->challengeId,
            'channel' => $this->channel,
            'target' => $this->target,
            'step' => $this->step,
            'confirmed_at' => $this->confirmedAt,
        ]);
    }

    /**
     * The same change at another step.
     *
     * @param  self::STEP_*  $step
     */
    public function withStep(string $step, string $challengeId, string $channel, ?int $confirmedAt = null): self
    {
        return new self($this->userId, $this->action, $challengeId, $channel, $this->target, $step, $confirmedAt ?? $this->confirmedAt);
    }

    /**
     * The challenge of the confirmation with the current method; its context is the action.
     */
    public function challenge(): Challenge
    {
        return new Challenge($this->challengeId, $this->channel, $this->action);
    }

    /**
     * The confirmation with the current method is younger than `$ttl` seconds.
     */
    public function isConfirmed(int $ttl): bool
    {
        return $this->confirmedAt !== null && $this->confirmedAt + $ttl > now()->getTimestamp();
    }
}
