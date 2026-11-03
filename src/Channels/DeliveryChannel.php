<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Channels;

use Carbon\CarbonInterface;
use Illuminate\Cache\RateLimiter;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Nakipelo\Orchid2FA\Challenge\Challenge;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\CodeInput;
use Nakipelo\Orchid2FA\Challenge\CodeStore;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\Keys;
use Nakipelo\Orchid2FA\Challenge\StoredCode;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Channels\Concerns\ConfiguresChannel;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Throwable;

/**
 * Base class of the channels whose code the server generates and delivers: e-mail, SMS,
 * messengers (spec 0.2 §4.2).
 *
 * A driver implements destination() and send(); the base class generates the code, keeps only
 * its HMAC in the cache (`orchid-2fa:code:{user_id}`), applies the cooldown and the hourly send
 * limit and checks the code (spec §4.2, §4.10, §4.11, §5.9 of 0.1). issue() and verify() are final:
 * the security of the code does not depend on the driver.
 *
 * The attempts of a code are counted by the ChallengeManager before verify() is called; the
 * events are fired by the ChallengeManager as well.
 */
abstract class DeliveryChannel implements TwoFactorChannel
{
    use ConfiguresChannel;

    /**
     * The raw destination the code is bound to (an address, a phone number); '' if the user has none.
     */
    abstract public function destination(Authenticatable $user): string;

    /**
     * Deliver the code.
     *
     * @throws DeliveryFailedException
     */
    abstract public function send(Authenticatable $user, string $code, CarbonInterface $expiresAt): void;

    final public function requiresDelivery(): bool
    {
        return true;
    }

    public function needsRecoveryCodes(): bool
    {
        return false;
    }

    /**
     * The user has a destination.
     */
    public function isAvailableFor(Authenticatable $user): bool
    {
        return $this->destination($user) !== '';
    }

    /**
     * The destination as shown to the user; by default the e-mail mask (`e***@gmail.com`).
     */
    public function maskedDestination(Authenticatable $user): string
    {
        return EmailChannel::mask($this->destination($user));
    }

    /**
     * Check the send limits, generate a code, store its HMAC and send it. A code that could not
     * be sent is removed (fail-closed, spec §4.10 of 0.1). Every send counts against the limits,
     * a failed one too.
     *
     * @throws SendLimitExceededException
     * @throws DeliveryFailedException
     */
    final public function issue(Authenticatable $user, string $context): Challenge
    {
        $availableIn = $this->sendAvailableIn($user);

        if ($availableIn > 0) {
            throw new SendLimitExceededException($availableIn);
        }

        $userId = $user->getAuthIdentifier();

        if ($this->cooldown() > 0) {
            $this->limiter()->hit(Keys::cooldown($userId), $this->cooldown());
        }

        $this->limiter()->hit(Keys::send($userId), 3600);

        $code = $this->generateCode();
        $expiresAt = now()->addSeconds($this->codeTtl());
        $challenge = Challenge::make($this->name(), $context, $expiresAt->getTimestamp());

        $this->codes()->put($userId, new StoredCode(
            $this->codes()->hashCode($code, $challenge->id),
            $challenge->id,
            $this->destinationHash($user),
            $expiresAt->getTimestamp(),
            $this->name(),
            $context,
        ));

        try {
            $this->send($user, $code, $expiresAt);
        } catch (Throwable $e) {
            // Fail-closed: no code that might not have arrived stays valid.
            $this->codes()->forget($userId);

            throw $e;
        }

        return $challenge;
    }

    /**
     * Check the code of the challenge: the active code must belong to this challenge and to the
     * current destination; a correct code is consumed atomically (a parallel or repeated
     * verification gets `Expired`). Never returns `LockedOut`: the attempts are the
     * ChallengeManager's.
     */
    final public function verify(Authenticatable $user, Challenge $challenge, string $code): VerificationResult
    {
        $userId = $user->getAuthIdentifier();
        $stored = $this->codes()->get($userId);

        if ($stored === null || ! hash_equals($stored->challengeId, $challenge->id)) {
            return VerificationResult::Expired;
        }

        if (! hash_equals($stored->destinationHash, $this->destinationHash($user))) {
            $this->codes()->forget($userId);

            return VerificationResult::Expired;
        }

        if (! hash_equals($stored->hash, $this->codes()->hashCode($this->normalize($code), $challenge->id))) {
            return VerificationResult::Invalid;
        }

        if (! $this->codes()->claim($userId, $stored)) {
            return VerificationResult::Expired;
        }

        $this->codes()->forget($userId);

        return VerificationResult::Passed;
    }

    /**
     * The user's active code of this channel bound to the current destination, as a challenge
     * (reused instead of sending a new code, spec §4.2 item 3 of 0.1). Whether its attempts are
     * left is checked by the ChallengeManager.
     */
    public function activeChallenge(Authenticatable $user): ?Challenge
    {
        $stored = $this->codes()->get($user->getAuthIdentifier());

        if ($stored === null
            || ($stored->channel !== null && $stored->channel !== $this->name())
            || ! hash_equals($stored->destinationHash, $this->destinationHash($user))) {
            return null;
        }

        return new Challenge($stored->challengeId, $this->name(), $stored->context, $stored->expiresAt);
    }

    /**
     * Seconds until the next code can be sent to the user (0 — now): the cooldown and the
     * hourly limit (spec §4.11 of 0.1).
     */
    public function sendAvailableIn(Authenticatable $user): int
    {
        $userId = $user->getAuthIdentifier();
        $availableIn = 0;

        if ($this->limiter()->tooManyAttempts(Keys::cooldown($userId), 1)) {
            $availableIn = $this->limiter()->availableIn(Keys::cooldown($userId));
        }

        if ($this->limiter()->tooManyAttempts(Keys::send($userId), $this->maxPerHour())) {
            $availableIn = max($availableIn, $this->limiter()->availableIn(Keys::send($userId)));
        }

        return max(0, $availableIn);
    }

    /**
     * Annul the active code of the user; the limits stay.
     */
    public function annul(Authenticatable $user): void
    {
        $this->codes()->forget($user->getAuthIdentifier());
    }

    /**
     * Annul the active code and clear its attempts, the hourly send limit and the cooldown.
     * The channel keeps no other data.
     */
    public function forget(Authenticatable $user): void
    {
        $userId = $user->getAuthIdentifier();
        $stored = $this->codes()->get($userId);

        if ($stored !== null) {
            $this->limiter()->clear(Keys::verify($userId, $stored->challengeId));
        }

        $this->codes()->forget($userId);
        $this->limiter()->clear(Keys::send($userId));
        $this->limiter()->clear(Keys::cooldown($userId));
    }

    public function prompt(Authenticatable $user): string
    {
        return (string) __('orchid-2fa::messages.challenge.sent_to', ['destination' => $this->maskedDestination($user)]);
    }

    public function codeInput(): CodeInput
    {
        return CodeInput::digits($this->codeLength());
    }

    public function challengeView(): ?string
    {
        return null;
    }

    /**
     * A code to the destination, issued through the ChallengeManager (send limits, events,
     * fail-closed, spec 0.2 §4.6) with the context of the state; its challenge id is kept in the
     * state under `challenge_id`. Calling it again sends a new code ("send again").
     *
     * @throws SendLimitExceededException
     * @throws DeliveryFailedException
     */
    public function startEnrollment(Authenticatable $user, EnrollmentState $state): void
    {
        $challenge = Container::getInstance()->make(ChallengeManager::class)->issue($user, $state->context, $this);

        $state->put('challenge_id', $challenge->id);
    }

    /**
     * Check the code of the step. Called by ChallengeManager::confirmEnrollment(), which counts the
     * attempt before.
     */
    public function confirmEnrollment(Authenticatable $user, EnrollmentState $state, string $code): VerificationResult
    {
        $challengeId = $state->get('challenge_id');

        if (! is_string($challengeId)) {
            return VerificationResult::Expired;
        }

        return $this->verify($user, new Challenge($challengeId, $this->name(), $state->context), $code);
    }

    /**
     * No step but the code; a driver that asks for the destination (SMS) overrides it.
     */
    public function enrollmentView(): ?string
    {
        return null;
    }

    /**
     * @return array<string, mixed>
     */
    public function enrollmentData(Authenticatable $user, EnrollmentState $state): array
    {
        return [];
    }

    /**
     * `code.length` random digits (`random_int`).
     */
    protected function generateCode(): string
    {
        $code = '';

        for ($i = 0, $length = $this->codeLength(); $i < $length; $i++) {
            $code .= (string) random_int(0, 9);
        }

        return $code;
    }

    protected function codeLength(): int
    {
        return max(1, (int) $this->config()->get('orchid-2fa.code.length', 6));
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
        return $this->codes()->hashDestination($this->destination($user));
    }

    protected function codes(): CodeStore
    {
        return Container::getInstance()->make(CodeStore::class);
    }

    protected function limiter(): RateLimiter
    {
        return Container::getInstance()->make(RateLimiter::class);
    }

    protected function maxPerHour(): int
    {
        return max(1, (int) $this->config()->get('orchid-2fa.resend.max_per_hour', 5));
    }

    protected function cooldown(): int
    {
        return max(0, (int) $this->config()->get('orchid-2fa.resend.cooldown', 60));
    }

    protected function codeTtl(): int
    {
        return max(1, (int) $this->config()->get('orchid-2fa.code.ttl', 600));
    }
}
