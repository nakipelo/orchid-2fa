<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Log\LogManager;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Nakipelo\Orchid2FA\Support\Orchid;
use Psr\Log\LoggerInterface;

/**
 * Issues, sends and verifies one-time codes; enforces the limits (spec §4.2, §4.10, §4.11, §5.9).
 * Channel-agnostic: delivery is delegated to the configured TwoFactorChannel.
 */
class ChallengeManager
{
    protected ?TwoFactorChannel $channel = null;

    public function __construct(
        protected Container $container,
        protected Repository $config,
        protected CodeStore $codes,
        protected RateLimiter $limiter,
        protected Dispatcher $events,
        protected LogManager $log,
    ) {}

    public function channel(): TwoFactorChannel
    {
        if ($this->channel !== null) {
            return $this->channel;
        }

        $name = (string) $this->config->get('orchid-2fa.channel', 'email');
        $class = $this->config->get('orchid-2fa.channels.'.$name.'.class');

        if (! is_string($class) || ! is_subclass_of($class, TwoFactorChannel::class)) {
            throw new InvalidArgumentException(sprintf(
                '[orchid-2fa.channels.%s.class] must implement %s.',
                $name,
                TwoFactorChannel::class,
            ));
        }

        /** @var TwoFactorChannel $channel */
        $channel = $this->container->make($class);

        return $this->channel = $channel;
    }

    /**
     * The challenge id of the user's active code, if any: not expired, attempts left,
     * bound to the current destination. Such a code is reused instead of sending a new one.
     */
    public function activeChallenge(Authenticatable $user): ?string
    {
        $code = $this->codes->get($user->getAuthIdentifier());

        if ($code === null
            || ! hash_equals($code->destinationHash, $this->destinationHash($user))
            || $this->limiter->tooManyAttempts($this->attemptsKey($user, $code->challengeId), $this->maxAttempts())) {
            return null;
        }

        return $code->challengeId;
    }

    /**
     * Issue a new code (annulling the previous one) and send it.
     *
     * @return string the challenge id of the new code
     *
     * @throws SendLimitExceededException
     * @throws DeliveryFailedException
     */
    public function issue(Authenticatable $user, string $context = TwoFactorChallengeSent::CONTEXT_LOGIN): string
    {
        $availableIn = $this->sendAvailableIn($user);

        if ($availableIn > 0) {
            $this->events->dispatch(new TwoFactorLockedOut($user, Orchid::guardName(), TwoFactorLockedOut::SEND_LIMIT, $availableIn));

            throw new SendLimitExceededException($availableIn);
        }

        // Every send counts, a failed one too (spec §4.10).
        if ($this->cooldown() > 0) {
            $this->limiter->hit($this->cooldownKey($user), $this->cooldown());
        }

        $this->limiter->hit($this->sendKey($user), 3600);

        $channel = $this->channel();
        $code = $this->generateCode();
        $challengeId = Str::random(40);
        $expiresAt = now()->addSeconds($this->codeTtl());

        $this->codes->put($user->getAuthIdentifier(), new StoredCode(
            $this->codes->hashCode($code, $challengeId),
            $challengeId,
            $this->destinationHash($user),
            $expiresAt->getTimestamp(),
        ));

        try {
            $channel->send($user, $code, $expiresAt);
        } catch (DeliveryFailedException $e) {
            // Fail-closed (spec §4.10): no code that might not have arrived stays valid.
            $this->codes->forget($user->getAuthIdentifier());

            $this->logger()->error('nakipelo/orchid-2fa: the two-factor code could not be sent.', [
                'user_id' => $user->getAuthIdentifier(),
                'channel' => $channel->name(),
                'exception' => $e,
            ]);

            $this->events->dispatch(new TwoFactorFailed($user, Orchid::guardName(), TwoFactorFailed::DELIVERY_FAILED));

            throw $e;
        }

        $this->events->dispatch(new TwoFactorChallengeSent(
            $user,
            Orchid::guardName(),
            $channel->name(),
            $channel->maskedDestination($user),
            $context,
        ));

        return $challengeId;
    }

    /**
     * Check a code of the given challenge. The attempt is counted before the comparison,
     * which closes parallel guessing; a correct code is consumed atomically.
     */
    public function verify(Authenticatable $user, string $challengeId, string $code): VerificationResult
    {
        $userId = $user->getAuthIdentifier();
        $stored = $this->codes->get($userId);

        if ($stored === null || ! hash_equals($stored->challengeId, $challengeId)) {
            return $this->fail($user, TwoFactorFailed::EXPIRED, VerificationResult::Expired);
        }

        if (! hash_equals($stored->destinationHash, $this->destinationHash($user))) {
            $this->codes->forget($userId);

            return $this->fail($user, TwoFactorFailed::EXPIRED, VerificationResult::Expired);
        }

        $attemptsKey = $this->attemptsKey($user, $challengeId);
        $attempts = $this->limiter->hit($attemptsKey, $this->codeTtl());

        if ($attempts > $this->maxAttempts()) {
            // Only reachable by parallel requests racing past the last attempt.
            $this->codes->forget($userId);

            return $this->fail($user, TwoFactorFailed::EXPIRED, VerificationResult::Expired);
        }

        if (! hash_equals($stored->hash, $this->codes->hashCode($this->normalize($code), $challengeId))) {
            $this->events->dispatch(new TwoFactorFailed($user, Orchid::guardName(), TwoFactorFailed::INVALID_CODE));

            if ($attempts < $this->maxAttempts()) {
                return VerificationResult::Invalid;
            }

            $this->codes->forget($userId);
            $this->events->dispatch(new TwoFactorLockedOut(
                $user,
                Orchid::guardName(),
                TwoFactorLockedOut::ATTEMPTS_EXCEEDED,
                $this->sendAvailableIn($user),
            ));

            return VerificationResult::LockedOut;
        }

        if (! $this->codes->claim($userId, $stored)) {
            return $this->fail($user, TwoFactorFailed::EXPIRED, VerificationResult::Expired);
        }

        $this->codes->forget($userId);
        $this->limiter->clear($attemptsKey);

        return VerificationResult::Passed;
    }

    /**
     * Wrong attempts left for the challenge.
     */
    public function attemptsLeft(Authenticatable $user, string $challengeId): int
    {
        return max(0, $this->maxAttempts() - (int) $this->limiter->attempts($this->attemptsKey($user, $challengeId)));
    }

    /**
     * Seconds until the next code can be sent to the user (0 — now). Feeds the
     * countdown of the "send again" button (spec §4.11).
     */
    public function sendAvailableIn(Authenticatable $user): int
    {
        $availableIn = 0;

        if ($this->limiter->tooManyAttempts($this->cooldownKey($user), 1)) {
            $availableIn = $this->limiter->availableIn($this->cooldownKey($user));
        }

        if ($this->limiter->tooManyAttempts($this->sendKey($user), $this->maxPerHour())) {
            $availableIn = max($availableIn, $this->limiter->availableIn($this->sendKey($user)));
        }

        return max(0, $availableIn);
    }

    /**
     * Annul the active code of the user (e-mail change, spec §4.9). The limits stay.
     */
    public function annul(Authenticatable $user): void
    {
        $this->codes->forget($user->getAuthIdentifier());
    }

    /**
     * Annul the active code and clear the counters: wrong attempts of the code, the hourly
     * send limit and the cooldown (reset by an administrator, spec §4.8).
     */
    public function clear(Authenticatable $user): void
    {
        $stored = $this->codes->get($user->getAuthIdentifier());

        if ($stored !== null) {
            $this->limiter->clear($this->attemptsKey($user, $stored->challengeId));
        }

        $this->codes->forget($user->getAuthIdentifier());
        $this->limiter->clear($this->sendKey($user));
        $this->limiter->clear($this->cooldownKey($user));
    }

    public function codeLength(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.code.length', 6));
    }

    protected function fail(Authenticatable $user, string $reason, VerificationResult $result): VerificationResult
    {
        $this->events->dispatch(new TwoFactorFailed($user, Orchid::guardName(), $reason));

        return $result;
    }

    protected function generateCode(): string
    {
        $code = '';

        for ($i = 0, $length = $this->codeLength(); $i < $length; $i++) {
            $code .= (string) random_int(0, 9);
        }

        return $code;
    }

    /**
     * Users may paste the code with spaces or dashes.
     */
    protected function normalize(string $code): string
    {
        return (string) preg_replace('/[\s-]+/u', '', $code);
    }

    protected function destinationHash(Authenticatable $user): string
    {
        return $this->codes->hashDestination($this->channel()->destination($user));
    }

    protected function attemptsKey(Authenticatable $user, string $challengeId): string
    {
        return 'orchid-2fa:verify:'.$user->getAuthIdentifier().':'.$challengeId;
    }

    protected function sendKey(Authenticatable $user): string
    {
        return 'orchid-2fa:send:'.$user->getAuthIdentifier();
    }

    protected function cooldownKey(Authenticatable $user): string
    {
        return 'orchid-2fa:cooldown:'.$user->getAuthIdentifier();
    }

    protected function maxAttempts(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.code.max_attempts', 5));
    }

    protected function maxPerHour(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.resend.max_per_hour', 5));
    }

    protected function cooldown(): int
    {
        return max(0, (int) $this->config->get('orchid-2fa.resend.cooldown', 60));
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
