<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Facades\TwoFactor;
use RuntimeException;

/**
 * The `fake` channel whose verifyCode() / confirmEnrollment() throw from inside the call (the trace
 * covers the core's frames), for the trace leak test. #[\SensitiveParameter] is not inherited, so the
 * driver marks its own parameters, as a real driver should (README "Writing a channel").
 */
class ThrowingFakeVerifierChannel extends FakeVerifierChannel
{
    public static bool $throw = false;

    public static function register(): void
    {
        parent::register();
        self::$throw = false;

        TwoFactor::extend('fake', fn () => new self);
    }

    protected function verifyCode(Authenticatable $user, #[\SensitiveParameter] string $code): bool
    {
        if (self::$throw) {
            throw new RuntimeException('driver is down (verify)');
        }

        return parent::verifyCode($user, $code);
    }

    public function confirmEnrollment(Authenticatable $user, EnrollmentState $state, #[\SensitiveParameter] string $code): VerificationResult
    {
        if (self::$throw) {
            throw new RuntimeException('driver is down (enroll)');
        }

        return parent::confirmEnrollment($user, $state, $code);
    }
}
