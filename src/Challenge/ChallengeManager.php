<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Log\LogManager;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\DeliveryChannel;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Nakipelo\Orchid2FA\Exceptions\UnknownChannelException;
use Nakipelo\Orchid2FA\Support\Orchid;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * The orchestrator of challenges (spec 0.2 §4.4): the entry point of the controllers and the
 * profile screen. Generating, storing and sending the code belong to the channel; the
 * orchestrator does what has to hold for any channel: picks the user's channel, refuses a
 * challenge of another channel, counts the attempts before calling the channel and fires all
 * the events.
 */
class ChallengeManager
{
    public function __construct(
        protected Repository $config,
        protected ChannelRegistry $channels,
        protected CodeStore $codes,
        protected RateLimiter $limiter,
        protected Dispatcher $events,
        protected LogManager $log,
    ) {}

    /**
     * The channel of the user (spec 0.2 §4.5).
     *
     * @throws UnknownChannelException neither the user's nor the default channel is registered
     */
    public function channelFor(Authenticatable $user): TwoFactorChannel
    {
        return $this->channels->for($user)
            ?? throw UnknownChannelException::named($this->channels->defaultName());
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
     * Check a code of the challenge. The attempt is counted before the channel is asked, which
     * closes parallel guessing; a challenge of another channel than the user's is `Expired`.
     */
    public function verify(Authenticatable $user, Challenge $challenge, string $code): VerificationResult
    {
        $channel = $this->channelFor($user);

        if ($challenge->channel !== $channel->name()) {
            // The method changed or was reset while the challenge was pending.
            $this->events->dispatch(new TwoFactorFailed($user, Orchid::guardName(), TwoFactorFailed::EXPIRED, $challenge->channel));

            return VerificationResult::Expired;
        }

        $attemptsKey = $this->attemptsKey($user, $challenge);
        $attempts = $this->limiter->hit($attemptsKey, $this->codeTtl());

        if ($attempts > $this->maxAttempts()) {
            // Exhausted already: only reachable by parallel requests racing past the last attempt
            // or by a challenge that was locked out before.
            $this->annulChannelCode($user, $channel);

            return $this->fail($user, $channel, TwoFactorFailed::EXPIRED, VerificationResult::Expired);
        }

        $result = $channel->verify($user, $challenge, $code);

        if ($result === VerificationResult::Passed) {
            $this->limiter->clear($attemptsKey);

            return $result;
        }

        if ($result === VerificationResult::Expired) {
            return $this->fail($user, $channel, TwoFactorFailed::EXPIRED, $result);
        }

        if ($result === VerificationResult::Invalid) {
            $this->events->dispatch(new TwoFactorFailed($user, Orchid::guardName(), TwoFactorFailed::INVALID_CODE, $channel->name()));

            if ($attempts < $this->maxAttempts()) {
                return $result;
            }
        }

        $this->annulChannelCode($user, $channel);
        $this->events->dispatch(new TwoFactorLockedOut(
            $user,
            Orchid::guardName(),
            TwoFactorLockedOut::ATTEMPTS_EXCEEDED,
            $this->sendAvailableIn($user, $channel),
            $channel->name(),
        ));

        return VerificationResult::LockedOut;
    }

    /**
     * Wrong attempts left for the challenge.
     */
    public function attemptsLeft(Authenticatable $user, Challenge $challenge): int
    {
        return max(0, $this->maxAttempts() - (int) $this->limiter->attempts($this->attemptsKey($user, $challenge)));
    }

    /**
     * Seconds until the next code can be sent to the user (0 — now; always 0 for a verifier
     * channel). Feeds the countdown of the "send again" button (spec §4.11 of 0.1).
     */
    public function sendAvailableIn(Authenticatable $user, ?TwoFactorChannel $channel = null): int
    {
        $channel ??= $this->channelFor($user);

        return $channel instanceof DeliveryChannel ? $channel->sendAvailableIn($user) : 0;
    }

    /**
     * The user's active code of a delivery channel, if any: not expired, attempts left, bound
     * to the current destination. Such a code is reused instead of sending a new one.
     */
    public function activeChallenge(Authenticatable $user, ?TwoFactorChannel $channel = null): ?Challenge
    {
        $channel ??= $this->channelFor($user);
        $challenge = $channel instanceof DeliveryChannel ? $channel->activeChallenge($user) : null;

        if ($challenge === null
            || $this->limiter->tooManyAttempts($this->attemptsKey($user, $challenge), $this->maxAttempts())) {
            return null;
        }

        return $challenge;
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
     * send limit and the cooldown (reset by an administrator, spec §4.8 of 0.1). Does not depend
     * on the channel: the keys are shared (spec 0.2 §4.2).
     */
    public function clear(Authenticatable $user): void
    {
        $userId = $user->getAuthIdentifier();
        $stored = $this->codes->get($userId);

        if ($stored !== null) {
            $this->limiter->clear(Keys::verify($userId, $stored->challengeId));
        }

        $this->codes->forget($userId);
        $this->limiter->clear(Keys::send($userId));
        $this->limiter->clear(Keys::cooldown($userId));
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

    protected function logger(): LoggerInterface
    {
        $channel = $this->config->get('orchid-2fa.log.channel');

        return $this->log->channel(is_string($channel) && $channel !== '' ? $channel : null);
    }
}
