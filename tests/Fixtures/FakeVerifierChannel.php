<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Channels\VerifierChannel;
use Nakipelo\Orchid2FA\Facades\TwoFactor;

/**
 * The verifier channel of the package tests and the workbench (spec 0.2 §10.1): name `fake`, its own
 * table `two_factor_fake` (tests/Fixtures/database/migrations), deterministic 6-digit codes per 30 s
 * step (an HMAC of the step with the user's secret, ±1 step), replay protection (only a step greater
 * than the last accepted one, atomic conditional UPDATE), recovery codes.
 *
 * Not an algorithm to use: a stand-in for TOTP.
 */
class FakeVerifierChannel extends VerifierChannel
{
    public const TABLE = 'two_factor_fake';

    public const STEP = 30;

    /**
     * Whether allowsEmailFallback() is true (spec 0.2 §13).
     */
    public static bool $emailFallback = false;

    /**
     * Thrown by verifyCode() when set.
     */
    public static ?\Throwable $failWith = null;

    public static function register(): void
    {
        self::$emailFallback = false;
        self::$failWith = null;

        TwoFactor::extend('fake', fn () => new self);
    }

    public function label(): string
    {
        return 'Fake authenticator';
    }

    public function allowsEmailFallback(Authenticatable $user): bool
    {
        return self::$emailFallback;
    }

    public function isAvailableFor(Authenticatable $user): bool
    {
        return DB::table(self::TABLE)
            ->where('user_id', $user->getAuthIdentifier())
            ->whereNotNull('confirmed_at')
            ->exists();
    }

    protected function verifyCode(Authenticatable $user, string $code): bool
    {
        if (self::$failWith !== null) {
            throw self::$failWith;
        }

        $row = DB::table(self::TABLE)
            ->where('user_id', $user->getAuthIdentifier())
            ->whereNotNull('confirmed_at')
            ->first(['secret']);

        if ($row === null) {
            return false;
        }

        $step = self::matchingStep((string) $row->secret, $code);

        if ($step === null) {
            return false;
        }

        // Replay protection: only a step after the last accepted one, atomically.
        return DB::table(self::TABLE)
            ->where('user_id', $user->getAuthIdentifier())
            ->where(fn ($query) => $query->whereNull('last_step')->orWhere('last_step', '<', $step))
            ->update(['last_step' => $step, 'updated_at' => now()]) === 1;
    }

    public function startEnrollment(Authenticatable $user, EnrollmentState $state): void
    {
        $state->put('secret', Str::random(32));
    }

    public function confirmEnrollment(Authenticatable $user, EnrollmentState $state, string $code): VerificationResult
    {
        $secret = $state->get('secret');

        if (! is_string($secret)) {
            return VerificationResult::Expired;
        }

        $step = self::matchingStep($secret, (string) preg_replace('/[\s-]+/u', '', $code));

        if ($step === null) {
            return VerificationResult::Invalid;
        }

        // Upsert: a leftover row (a reset without the driver) is replaced entirely.
        DB::table(self::TABLE)->updateOrInsert(
            ['user_id' => $user->getAuthIdentifier()],
            ['secret' => $secret, 'confirmed_at' => now(), 'last_step' => $step, 'created_at' => now(), 'updated_at' => now()],
        );

        return VerificationResult::Passed;
    }

    public function enrollmentView(): ?string
    {
        return 'orchid-2fa-fake::enroll';
    }

    /**
     * @return array<string, mixed>
     */
    public function enrollmentData(Authenticatable $user, EnrollmentState $state): array
    {
        $secret = $state->get('secret');

        return [
            'fakeSecret' => is_string($secret) ? $secret : '',
            'fakeCode' => is_string($secret) ? self::codeFor($secret) : '',
        ];
    }

    public function forget(Authenticatable $user): void
    {
        DB::table(self::TABLE)->where('user_id', $user->getAuthIdentifier())->delete();
    }

    /**
     * Enroll the user directly (tests).
     */
    public static function enrollUser(Authenticatable $user, ?string $secret = null): string
    {
        $secret ??= Str::random(32);

        DB::table(self::TABLE)->updateOrInsert(
            ['user_id' => $user->getAuthIdentifier()],
            ['secret' => $secret, 'confirmed_at' => now(), 'last_step' => null, 'created_at' => now(), 'updated_at' => now()],
        );

        return $secret;
    }

    /**
     * The current code of an enrolled user.
     */
    public static function currentCode(Authenticatable $user, int $offset = 0): string
    {
        $secret = DB::table(self::TABLE)->where('user_id', $user->getAuthIdentifier())->value('secret');

        if (! is_string($secret)) {
            throw new \RuntimeException('The user has no fake authenticator.');
        }

        return self::codeFor($secret, self::currentStep() + $offset);
    }

    public static function codeFor(string $secret, ?int $step = null): string
    {
        $step ??= self::currentStep();

        return str_pad((string) (hexdec(substr(hash_hmac('sha256', (string) $step, $secret), 0, 8)) % 1000000), 6, '0', STR_PAD_LEFT);
    }

    public static function currentStep(): int
    {
        return intdiv(now()->getTimestamp(), self::STEP);
    }

    protected static function matchingStep(string $secret, string $code): ?int
    {
        $current = self::currentStep();

        foreach ([$current, $current - 1, $current + 1] as $step) {
            if (hash_equals(self::codeFor($secret, $step), $code)) {
                return $step;
            }
        }

        return null;
    }
}
