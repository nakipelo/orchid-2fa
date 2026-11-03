<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Log\LogManager;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\DeliveryChannel;
use Nakipelo\Orchid2FA\Channels\VerifierChannel;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Nakipelo\Orchid2FA\Events\RecoveryCodeUsed;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Nakipelo\Orchid2FA\Exceptions\UnknownChannelException;
use Nakipelo\Orchid2FA\Notifications\SecurityNotifier;
use Nakipelo\Orchid2FA\Notifications\TwoFactorSecurityNotification;
use Nakipelo\Orchid2FA\Recovery\RecoveryCodes;
use Nakipelo\Orchid2FA\Support\Orchid;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * The orchestrator of challenges (spec 0.2 §4.4): the entry point of the controllers and the
 * profile screen. Generating, storing and sending the code belong to the channel; the
 * orchestrator does what has to hold for any channel: picks the user's channel, refuses a
 * challenge of another channel, counts the attempts before calling the channel and fires all
 * the events.
 *
 * Counters: every challenge has `code.max_attempts` (`orchid-2fa:verify:{uid}:{challenge_id}`);
 * the codes of verifier channels, recovery codes and the enrollment of a verifier channel also count
 * against the window of the user (`verify.user_max_attempts` per `verify.user_decay`) and the daily
 * ceiling (`verify.user_max_per_day`). When the window or the ceiling is exhausted the user gets a
 * security notice `attempts_exceeded`, at most once per window.
 */
class ChallengeManager
{
    /**
     * The last lockout of this instance: reason and seconds until it is over.
     *
     * @var array{reason: string, available_in: int}|null
     */
    protected ?array $lockout = null;

    public function __construct(
        protected Repository $config,
        protected ChannelRegistry $channels,
        protected CodeStore $codes,
        protected RateLimiter $limiter,
        protected Dispatcher $events,
        protected LogManager $log,
        protected RecoveryCodes $recoveryCodes,
        protected SecurityNotifier $notifier,
    ) {}

    /**
     * The channel of the user (spec 0.2 §4.5).
     *
     * @throws UnknownChannelException the user has no method: its driver is gone or none is enrolled
     */
    public function channelFor(Authenticatable $user): TwoFactorChannel
    {
        $method = $this->channels->methodFor($user);

        return $method->channel
            ?? throw UnknownChannelException::named($method->recorded ?? $this->channels->defaultName());
    }

    /**
     * Start a challenge (spec 0.2 §4.6): the active code of a delivery channel is reused,
     * otherwise a new challenge is issued.
     *
     * @throws SendLimitExceededException
     * @throws DeliveryFailedException
     */
    public function start(Authenticatable $user, string $context, ?TwoFactorChannel $channel = null): Challenge
    {
        $channel ??= $this->channelFor($user);

        return $this->activeChallenge($user, $channel) ?? $this->issue($user, $context, $channel);
    }

    /**
     * Issue a new challenge (a delivery channel annuls the previous code and sends a new one).
     * Fires `TwoFactorChallengeSent` (delivery only), `TwoFactorLockedOut` (send limit) or
     * `TwoFactorFailed` (delivery failed). An unexpected exception of the channel counts as a
     * failed delivery (fail-closed).
     *
     * @throws SendLimitExceededException
     * @throws DeliveryFailedException
     */
    public function issue(
        Authenticatable $user,
        string $context = TwoFactorChallengeSent::CONTEXT_LOGIN,
        ?TwoFactorChannel $channel = null,
    ): Challenge {
        $channel ??= $this->channelFor($user);

        try {
            $challenge = $channel->issue($user, $context);
        } catch (SendLimitExceededException $e) {
            $this->events->dispatch(new TwoFactorLockedOut(
                $user,
                Orchid::guardName(),
                TwoFactorLockedOut::SEND_LIMIT,
                $e->availableIn,
                $channel->name(),
            ));

            throw $e;
        } catch (Throwable $e) {
            $failure = $e instanceof DeliveryFailedException
                ? $e
                : new DeliveryFailedException('The two-factor channel failed to issue a challenge: '.$e->getMessage(), 0, $e);

            $this->logger()->error('nakipelo/orchid-2fa: the two-factor code could not be sent.', [
                'user_id' => $user->getAuthIdentifier(),
                'channel' => $channel->name(),
                'exception' => $failure,
            ]);

            $this->events->dispatch(new TwoFactorFailed($user, Orchid::guardName(), TwoFactorFailed::DELIVERY_FAILED, $channel->name()));

            throw $failure;
        }

        if ($channel instanceof DeliveryChannel) {
            $this->events->dispatch(new TwoFactorChallengeSent(
                $user,
                Orchid::guardName(),
                $channel->name(),
                $channel->maskedDestination($user),
                $context,
            ));
        }

        return $challenge;
    }

    /**
     * Check a code of the challenge. The attempts are counted before the channel is asked, which
     * closes parallel guessing; a challenge of another channel than the user's is `Expired`
     * (except the e-mail fallback of a verifier channel, spec 0.2 §13).
     */
    public function verify(Authenticatable $user, Challenge $challenge, string $code): VerificationResult
    {
        $this->lockout = null;
        $channel = $this->challengeChannel($user, $challenge);

        if ($channel === null) {
            // The method changed or was reset while the challenge was pending.
            $this->events->dispatch(new TwoFactorFailed($user, Orchid::guardName(), TwoFactorFailed::EXPIRED, $challenge->channel));

            return VerificationResult::Expired;
        }

        return $this->attempt(
            $user,
            $channel,
            $challenge,
            ! $channel->requiresDelivery(),
            TwoFactorFailed::INVALID_CODE,
            static fn (): VerificationResult => $channel->verify($user, $challenge, $code),
        );
    }

    /**
     * Check a recovery code instead of the code of the challenge (spec 0.2 §4.7): the challenge
     * must belong to the user's channel; the attempt counts against the challenge, the window and the
     * daily ceiling. A correct code is consumed, `RecoveryCodeUsed` is fired and the user gets a
     * security notice.
     */
    public function verifyRecoveryCode(Authenticatable $user, Challenge $challenge, string $code): VerificationResult
    {
        $this->lockout = null;
        $channel = $this->channelOrNull($user);

        if ($channel === null || $challenge->channel !== $channel->name()) {
            $this->events->dispatch(new TwoFactorFailed($user, Orchid::guardName(), TwoFactorFailed::EXPIRED, $challenge->channel));

            return VerificationResult::Expired;
        }

        $result = $this->attempt(
            $user,
            $channel,
            $challenge,
            true,
            TwoFactorFailed::INVALID_RECOVERY_CODE,
            fn (): VerificationResult => $this->recoveryCodes->consume($user, $code) ? VerificationResult::Passed : VerificationResult::Invalid,
        );

        if ($result === VerificationResult::Passed) {
            $remaining = $this->recoveryCodes->remaining($user);
            $context = $challenge->context === TwoFactorChallengeSent::CONTEXT_LOGIN
                ? RecoveryCodeUsed::CONTEXT_LOGIN
                : RecoveryCodeUsed::CONTEXT_PROFILE;

            $this->events->dispatch(new RecoveryCodeUsed($user, Orchid::guardName(), $channel->name(), $remaining, $context));
            $this->notifier->send($user, TwoFactorSecurityNotification::RECOVERY_CODE_USED, [
                'remaining' => $remaining,
                'context' => $context,
            ]);
        }

        return $result;
    }

    /**
     * Count a failed attempt that never reaches the channel, e.g. a wrong current password in a
     * profile confirmation (spec 0.2 §5.6 item 6): it counts like a wrong code of the challenge
     * (with `$userCounters`, also against the window and the daily ceiling). Returns `Invalid` or
     * `LockedOut`.
     */
    public function rejectAttempt(Authenticatable $user, Challenge $challenge, bool $userCounters): VerificationResult
    {
        $this->lockout = null;
        $channel = $this->channelOrNull($user);

        if ($channel === null || ($challenge->channel !== $channel->name() && ! $this->channels->has($challenge->channel))) {
            return VerificationResult::Expired;
        }

        if ($challenge->channel !== $channel->name()) {
            $channel = $this->channels->channel($challenge->channel);
        }

        return $this->attempt($user, $channel, $challenge, $userCounters, null, static fn (): VerificationResult => VerificationResult::Invalid);
    }

    /**
     * Start the enrollment of a channel (spec 0.2 §4.6). A delivery channel issues its code through
     * this orchestrator (limits, events, fail-closed).
     *
     * @throws SendLimitExceededException
     * @throws DeliveryFailedException
     */
    public function startEnrollment(Authenticatable $user, TwoFactorChannel $channel, EnrollmentState $state): void
    {
        $channel->startEnrollment($user, $state);
    }

    /**
     * Confirm the enrollment with the first code under the counters of spec 0.2 §4.4: the challenge
     * of the step (a delivery channel: its code), for a verifier channel also the window and the daily
     * ceiling of the user. The driver stores its data only when the code is correct.
     */
    public function confirmEnrollment(Authenticatable $user, TwoFactorChannel $channel, EnrollmentState $state, string $code): VerificationResult
    {
        $this->lockout = null;

        return $this->attempt(
            $user,
            $channel,
            $this->enrollmentChallenge($channel, $state),
            ! $channel->requiresDelivery(),
            TwoFactorFailed::INVALID_CODE,
            static fn (): VerificationResult => $channel->confirmEnrollment($user, $state, $code),
        );
    }

    /**
     * The challenge whose attempts the enrollment step counts.
     */
    public function enrollmentChallenge(TwoFactorChannel $channel, EnrollmentState $state): Challenge
    {
        $id = $state->get('challenge_id');

        return new Challenge(is_string($id) && $id !== '' ? $id : $state->challengeId(), $channel->name(), $state->context);
    }

    /**
     * Wrong attempts left for the challenge: the minimum of the applicable counters.
     */
    public function attemptsLeft(Authenticatable $user, Challenge $challenge, ?bool $userCounters = null): int
    {
        $left = $this->maxAttempts() - (int) $this->limiter->attempts($this->attemptsKey($user, $challenge));

        if ($userCounters ?? $this->usesUserCounters($challenge)) {
            $userId = $user->getAuthIdentifier();
            $left = min(
                $left,
                $this->userMaxAttempts() - (int) $this->limiter->attempts(Keys::verifierWindow($userId)),
                $this->userMaxPerDay() - (int) $this->limiter->attempts(Keys::verifierDay($userId)),
            );
        }

        return max(0, $left);
    }

    /**
     * The last lockout of this instance (`TwoFactorLockedOut::*` reason and seconds until it is
     * over), set by verify(), verifyRecoveryCode(), rejectAttempt() and confirmEnrollment().
     *
     * @return array{reason: string, available_in: int}|null
     */
    public function lockout(): ?array
    {
        return $this->lockout;
    }

    /**
     * Seconds until the next code can be sent to the user (0 — now; always 0 for a verifier
     * channel). Feeds the countdown of the "send again" button (spec §4.11 of 0.1).
     */
    public function sendAvailableIn(Authenticatable $user, ?TwoFactorChannel $channel = null): int
    {
        $channel ??= $this->channelOrNull($user);

        return $channel instanceof DeliveryChannel ? $channel->sendAvailableIn($user) : 0;
    }

    /**
     * The user's active code of a delivery channel, if any: not expired, attempts left, bound
     * to the current destination. Such a code is reused instead of sending a new one.
     */
    public function activeChallenge(Authenticatable $user, ?TwoFactorChannel $channel = null): ?Challenge
    {
        $channel ??= $this->channelOrNull($user);
        $challenge = $channel instanceof DeliveryChannel ? $channel->activeChallenge($user) : null;

        if ($challenge === null
            || $this->limiter->tooManyAttempts($this->attemptsKey($user, $challenge), $this->maxAttempts())) {
            return null;
        }

        return $challenge;
    }

    /**
     * The e-mail channel that may send a fallback code to a user of a verifier channel
     * (spec 0.2 §13): the verifier channel allows it, `email` is registered, allowed and a
     * delivery channel. Null otherwise.
     */
    public function fallbackChannel(Authenticatable $user): ?DeliveryChannel
    {
        $channel = $this->channelOrNull($user);

        if (! $channel instanceof VerifierChannel || ! $this->channels->isAllowed('email')) {
            return null;
        }

        try {
            if (! $channel->allowsEmailFallback($user)) {
                return null;
            }

            $email = $this->channels->channel('email');
        } catch (Throwable) {
            return null;
        }

        return $email instanceof DeliveryChannel ? $email : null;
    }

    /**
     * Annul the active code of the user, whatever its channel (e-mail change, spec §4.9 of 0.1).
     * The limits stay.
     */
    public function annul(Authenticatable $user): void
    {
        $this->codes->forget($user->getAuthIdentifier());
    }

    /**
     * Annul the active code and clear the counters: wrong attempts of the code, the hourly
     * send limit, the cooldown, the window and the daily ceiling of the user and the marker of the
     * `attempts_exceeded` notice (reset by an administrator, spec §4.8 of 0.1, §5.10 of 0.2). Does not
     * depend on the channel: the keys are shared (spec 0.2 §4.2).
     */
    public function clear(Authenticatable $user): void
    {
        $userId = $user->getAuthIdentifier();
        $stored = $this->codes->get($userId);

        if ($stored !== null) {
            $this->limiter->clear(Keys::verify($userId, $stored->challengeId));
        }

        $this->codes->forget($userId);

        foreach ([Keys::send($userId), Keys::cooldown($userId), Keys::verifierWindow($userId), Keys::verifierDay($userId), Keys::alert($userId)] as $key) {
            $this->limiter->clear($key);
        }
    }

    /**
     * Count the attempt and ask the channel (`$check`): the counters are incremented before, and
     * the channel is not asked when any of them is exhausted.
     *
     * @param  string|null  $invalidReason  the reason of `TwoFactorFailed` for a wrong code; null — no event
     * @param  Closure(): VerificationResult  $check
     */
    protected function attempt(
        Authenticatable $user,
        TwoFactorChannel $channel,
        Challenge $challenge,
        bool $userCounters,
        ?string $invalidReason,
        Closure $check,
    ): VerificationResult {
        $userId = $user->getAuthIdentifier();
        $windowKey = Keys::verifierWindow($userId);
        $dayKey = Keys::verifierDay($userId);

        // The user limits: an exhausted counter refuses the attempt without counting it again.
        if ($userCounters && ($blocked = $this->userLimit($userId, 0)) !== null) {
            return $this->lockedOut($user, $channel, $blocked);
        }

        $attemptsKey = $this->attemptsKey($user, $challenge);
        $attempts = $this->limiter->hit($attemptsKey, $this->codeTtl());

        if ($userCounters) {
            $this->limiter->hit($windowKey, $this->userDecay());
            $this->limiter->hit($dayKey, 86400);

            // Parallel requests racing past the last attempt.
            if (($blocked = $this->userLimit($userId, 1)) !== null) {
                return $this->lockedOut($user, $channel, $blocked);
            }
        }

        if ($attempts > $this->maxAttempts()) {
            // Exhausted already: only reachable by parallel requests racing past the last attempt
            // or by a challenge that was locked out before.
            $this->annulChannelCode($user, $channel);

            return $this->fail($user, $channel, TwoFactorFailed::EXPIRED, VerificationResult::Expired);
        }

        $result = $check();

        if ($result === VerificationResult::Passed) {
            $this->limiter->clear($attemptsKey);

            if ($userCounters) {
                // Only wrong attempts count against the user limits.
                $this->limiter->decrement($windowKey, $this->userDecay());
                $this->limiter->decrement($dayKey, 86400);
            }

            return $result;
        }

        if ($result === VerificationResult::Expired) {
            return $this->fail($user, $channel, TwoFactorFailed::EXPIRED, $result);
        }

        if ($result === VerificationResult::Invalid) {
            if ($invalidReason !== null) {
                $this->events->dispatch(new TwoFactorFailed($user, Orchid::guardName(), $invalidReason, $channel->name()));
            }

            if ($userCounters && ($exhausted = $this->userLimit($userId, 0)) !== null) {
                return $this->lockedOut($user, $channel, $exhausted);
            }

            if ($attempts < $this->maxAttempts()) {
                return $result;
            }
        }

        $this->annulChannelCode($user, $channel);

        return $this->lockedOut($user, $channel, TwoFactorLockedOut::ATTEMPTS_EXCEEDED);
    }

    /**
     * The exhausted user limit, if any: the daily ceiling first, then the window. `$over` = 1
     * means "more than the limit" (after incrementing), 0 — "the limit is reached".
     */
    protected function userLimit(int|string $userId, int $over): ?string
    {
        if ((int) $this->limiter->attempts(Keys::verifierDay($userId)) >= $this->userMaxPerDay() + $over) {
            return TwoFactorLockedOut::USER_DAILY_ATTEMPTS_EXCEEDED;
        }

        if ((int) $this->limiter->attempts(Keys::verifierWindow($userId)) >= $this->userMaxAttempts() + $over) {
            return TwoFactorLockedOut::USER_ATTEMPTS_EXCEEDED;
        }

        return null;
    }

    protected function lockedOut(Authenticatable $user, TwoFactorChannel $channel, string $reason): VerificationResult
    {
        $userId = $user->getAuthIdentifier();

        $availableIn = match ($reason) {
            TwoFactorLockedOut::USER_DAILY_ATTEMPTS_EXCEEDED => $this->limiter->availableIn(Keys::verifierDay($userId)),
            TwoFactorLockedOut::USER_ATTEMPTS_EXCEEDED => $this->limiter->availableIn(Keys::verifierWindow($userId)),
            default => $this->sendAvailableIn($user, $channel),
        };

        $availableIn = max(0, $availableIn);
        $this->lockout = ['reason' => $reason, 'available_in' => $availableIn];

        $this->events->dispatch(new TwoFactorLockedOut($user, Orchid::guardName(), $reason, $availableIn, $channel->name()));

        if ($reason === TwoFactorLockedOut::USER_ATTEMPTS_EXCEEDED || $reason === TwoFactorLockedOut::USER_DAILY_ATTEMPTS_EXCEEDED) {
            $this->alert($user, $channel, $reason === TwoFactorLockedOut::USER_DAILY_ATTEMPTS_EXCEEDED ? 'day' : 'window', $availableIn);
        }

        return VerificationResult::LockedOut;
    }

    /**
     * "Someone entered your password and is guessing the code" (spec 0.2 §4.4, §8.3): at most once
     * per `verify.user_decay` per user.
     */
    protected function alert(Authenticatable $user, TwoFactorChannel $channel, string $limit, int $availableIn): void
    {
        $key = Keys::alert($user->getAuthIdentifier());

        if ($this->limiter->tooManyAttempts($key, 1)) {
            return;
        }

        $this->limiter->hit($key, $this->userDecay());

        $this->notifier->send($user, TwoFactorSecurityNotification::ATTEMPTS_EXCEEDED, [
            'channel' => $channel->name(),
            'limit' => $limit,
            'available_in' => $availableIn,
        ]);
    }

    /**
     * The channel that verifies the challenge: the user's channel, or the e-mail channel for a
     * fallback challenge of a verifier user; null for a challenge of another channel.
     */
    protected function challengeChannel(Authenticatable $user, Challenge $challenge): ?TwoFactorChannel
    {
        $channel = $this->channelOrNull($user);

        if ($channel === null) {
            return null;
        }

        if ($challenge->channel === $channel->name()) {
            return $channel;
        }

        if ($challenge->context === TwoFactorChallengeSent::CONTEXT_FALLBACK) {
            $fallback = $this->fallbackChannel($user);

            return $fallback !== null && $fallback->name() === $challenge->channel ? $fallback : null;
        }

        return null;
    }

    protected function channelOrNull(Authenticatable $user): ?TwoFactorChannel
    {
        return $this->channels->for($user);
    }

    /**
     * Whether the user limits apply to a challenge: those of a verifier channel.
     */
    protected function usesUserCounters(Challenge $challenge): bool
    {
        try {
            return $this->channels->has($challenge->channel) && ! $this->channels->channel($challenge->channel)->requiresDelivery();
        } catch (Throwable) {
            return false;
        }
    }

    protected function annulChannelCode(Authenticatable $user, TwoFactorChannel $channel): void
    {
        if ($channel instanceof DeliveryChannel) {
            $channel->annul($user);
        }
    }

    protected function fail(Authenticatable $user, TwoFactorChannel $channel, string $reason, VerificationResult $result): VerificationResult
    {
        $this->events->dispatch(new TwoFactorFailed($user, Orchid::guardName(), $reason, $channel->name()));

        return $result;
    }

    protected function attemptsKey(Authenticatable $user, Challenge $challenge): string
    {
        return Keys::verify($user->getAuthIdentifier(), $challenge->id);
    }

    protected function maxAttempts(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.code.max_attempts', 5));
    }

    protected function codeTtl(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.code.ttl', 600));
    }

    protected function userMaxAttempts(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.verify.user_max_attempts', 10));
    }

    protected function userDecay(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.verify.user_decay', 600));
    }

    protected function userMaxPerDay(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.verify.user_max_per_day', 30));
    }

    protected function logger(): LoggerInterface
    {
        $channel = $this->config->get('orchid-2fa.log.channel');

        return $this->log->channel(is_string($channel) && $channel !== '' ? $channel : null);
    }
}
