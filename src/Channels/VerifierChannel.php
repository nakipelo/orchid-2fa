<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Channels;

use Illuminate\Contracts\Auth\Authenticatable;
use Nakipelo\Orchid2FA\Challenge\Challenge;
use Nakipelo\Orchid2FA\Challenge\CodeInput;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Channels\Concerns\ConfiguresChannel;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Throwable;

/**
 * Base class of the channels whose code the user generates: TOTP, in future WebAuthn
 * (spec 0.2 §4.2). The server only verifies the code; nothing is sent.
 *
 * A driver implements verifyCode() (with replay protection, atomic under parallel requests),
 * isAvailableFor(), startEnrollment(), confirmEnrollment() and forget(); enrollmentView() and
 * enrollmentData() default to "no partial" (null and []) as in DeliveryChannel. issue() and verify()
 * are final.
 *
 * The ChallengeManager counts every code of a verifier channel (and its enrollment) against the
 * challenge, the window of the user and the daily ceiling before the driver is asked
 * (spec 0.2 §4.4); a user of a verifier channel gets recovery codes unless needsRecoveryCodes()
 * is overridden.
 */
abstract class VerifierChannel implements TwoFactorChannel
{
    use ConfiguresChannel;

    /**
     * Whether the code is correct for the user. Must refuse a code that was already accepted
     * (replay) and be atomic under parallel requests.
     */
    abstract protected function verifyCode(Authenticatable $user, #[\SensitiveParameter] string $code): bool;

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
    final public function verify(Authenticatable $user, Challenge $challenge, #[\SensitiveParameter] string $code): VerificationResult
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

    /**
     * No partial: the enrollment step is only the code. A driver with a QR code or a key to show
     * overrides it.
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
}
