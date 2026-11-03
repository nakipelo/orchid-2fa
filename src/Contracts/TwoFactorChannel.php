<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nakipelo\Orchid2FA\Challenge\Challenge;
use Nakipelo\Orchid2FA\Challenge\CodeInput;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;

/**
 * A method of the second factor (a channel, a driver), spec 0.2 §4.1: the channel issues a
 * challenge and verifies its code.
 *
 * Do not implement it directly: extend Channels\DeliveryChannel (the server generates and
 * delivers the code: e-mail, SMS) or Channels\VerifierChannel (the user generates the code:
 * TOTP). The registry accepts only subclasses of those two (spec 0.2 §4.2) and registers a channel
 * under its name with `channels.<name>.driver` or `TwoFactor::extend()` (§4.3).
 *
 * The ChallengeManager, not the channel, counts the attempts (before calling verify()), fires
 * the events and does the final login, the trusted device cookie and the remember token
 * rotation (spec 0.2 §4.4, §9).
 */
interface TwoFactorChannel
{
    /**
     * The registry key of the channel, e.g. `email`, `totp`; stored in
     * `two_factor_authentications.channel`.
     */
    public function name(): string;

    /**
     * Translated name of the method for the UI, e.g. "E-mail", "Authenticator app".
     */
    public function label(): string;

    /**
     * True for a delivery channel (the server sends the code), false for a verifier channel.
     * Final in the base classes.
     */
    public function requiresDelivery(): bool;

    /**
     * Whether the method comes with recovery codes (e-mail: false, TOTP: true).
     */
    public function needsRecoveryCodes(): bool;

    /**
     * The method is enrolled and can serve the user now (e-mail: the user has an address;
     * TOTP: a confirmed secret).
     */
    public function isAvailableFor(Authenticatable $user): bool;

    /**
     * Issue a challenge. A delivery channel checks the send limits, generates, stores and sends
     * a code; a verifier channel only returns a new id, without side effects.
     *
     * @param  string  $context  a `Challenge\Context` value
     *
     * @throws SendLimitExceededException
     * @throws DeliveryFailedException
     */
    public function issue(Authenticatable $user, string $context): Challenge;

    /**
     * Check a code of the challenge. The attempt has already been counted by the
     * ChallengeManager (spec 0.2 §4.4); a replayed code is `Invalid` (or `Expired` for a used
     * delivery code).
     */
    public function verify(Authenticatable $user, Challenge $challenge, #[\SensitiveParameter] string $code): VerificationResult;

    /**
     * The line of the code screen, e.g. "We have sent a code to e***@example.com." or
     * "Enter the code from your authenticator app."
     */
    public function prompt(Authenticatable $user): string;

    /**
     * Attributes of the code field.
     */
    public function codeInput(): CodeInput;

    /**
     * A Blade partial of the code screen instead of the common one (spec 0.2 §6.2), or null.
     */
    public function challengeView(): ?string;

    /**
     * Start enrolling the method (spec 0.2 §4.6): e.g. generate a secret into the state or send
     * a code to the address.
     */
    public function startEnrollment(Authenticatable $user, EnrollmentState $state): void;

    /**
     * Confirm the enrollment with the first code. The driver stores its data only when the
     * code is correct.
     */
    public function confirmEnrollment(Authenticatable $user, EnrollmentState $state, #[\SensitiveParameter] string $code): VerificationResult;

    /**
     * A Blade partial of the enrollment step (no `@extends`, no forms, no external resources),
     * or null when the step is only the code.
     */
    public function enrollmentView(): ?string;

    /**
     * Data of the enrollment partial.
     *
     * @return array<string, mixed>
     */
    public function enrollmentData(Authenticatable $user, EnrollmentState $state): array;

    /**
     * Reset hook: erase the driver's data of the user. Idempotent.
     */
    public function forget(Authenticatable $user): void;
}
