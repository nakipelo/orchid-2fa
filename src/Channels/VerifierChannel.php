<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Channels;

use Illuminate\Contracts\Auth\Authenticatable;
use Nakipelo\Orchid2FA\Challenge\Challenge;
use Nakipelo\Orchid2FA\Challenge\CodeInput;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Channels\Concerns\ConfiguresChannel;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Throwable;

/**
 * Base class of the channels whose code the user generates: TOTP, in future WebAuthn
 * (spec 0.2 §4.2). The server only verifies the code; nothing is sent.
 *
 * A driver implements verifyCode() (with replay protection, atomic under parallel requests),
 * isAvailableFor(), the enrollment methods and forget(). issue() and verify() are final.
 *
 * Skeleton of stage 1: the verifier flows (per-user limits, recovery codes, enrollment) come
 * in stage 2.
 */
abstract class VerifierChannel implements TwoFactorChannel
{
    use ConfiguresChannel;

    /**
     * Whether the code is correct for the user. Must refuse a code that was already accepted
     * (replay) and be atomic under parallel requests.
     */
    abstract protected function verifyCode(Authenticatable $user, string $code): bool;

    final public function requiresDelivery(): bool
    {
        return false;
    }

    public function needsRecoveryCodes(): bool
    {
        return true;
    }

    /**
     * Whether the code screen offers "Send a code by e-mail" (spec 0.2 §13).
     */
    public function allowsEmailFallback(Authenticatable $user): bool
    {
        return false;
    }

    /**
     * A new id, without side effects: nothing is sent.
     */
    final public function issue(Authenticatable $user, string $context): Challenge
    {
        return Challenge::make($this->name(), $context);
    }

    /**
     * Normalize the code (spaces, dashes) and ask the driver. An exception of the driver is
     * logged and refuses the code (fail-closed).
     */
    final public function verify(Authenticatable $user, Challenge $challenge, string $code): VerificationResult
    {
        $code = (string) preg_replace('/[\s-]+/u', '', $code);

        if ($code === '') {
            return VerificationResult::Invalid;
        }

        try {
            return $this->verifyCode($user, $code) ? VerificationResult::Passed : VerificationResult::Invalid;
        } catch (Throwable $e) {
            $this->logger()->error('nakipelo/orchid-2fa: the two-factor channel failed to verify a code.', [
                'user_id' => $user->getAuthIdentifier(),
                'channel' => $this->name(),
                'exception' => $e,
            ]);

            return VerificationResult::Invalid;
        }
    }

    public function prompt(Authenticatable $user): string
    {
        return (string) __('orchid-2fa::messages.challenge.app_prompt');
    }

    public function codeInput(): CodeInput
    {
        return CodeInput::digits(6);
    }

    public function challengeView(): ?string
    {
        return null;
    }
}
