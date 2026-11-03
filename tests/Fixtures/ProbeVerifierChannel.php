<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Channels\VerifierChannel;
use Throwable;

/**
 * A minimal verifier channel of the stage 1 tests: the fixed code `424242`, counts the calls
 * of verifyCode(). The full FakeVerifierChannel (spec 0.2 §10.1) comes in stage 2.
 */
class ProbeVerifierChannel extends VerifierChannel
{
    public int $calls = 0;

    public ?Throwable $failWith = null;

    protected function verifyCode(Authenticatable $user, string $code): bool
    {
        $this->calls++;

        if ($this->failWith !== null) {
            throw $this->failWith;
        }

        return $code === '424242';
    }

    public function isAvailableFor(Authenticatable $user): bool
    {
        return true;
    }

    public function startEnrollment(Authenticatable $user, EnrollmentState $state): void {}

    public function confirmEnrollment(Authenticatable $user, EnrollmentState $state, string $code): VerificationResult
    {
        return VerificationResult::Invalid;
    }

    public function enrollmentView(): ?string
    {
        return null;
    }

    public function enrollmentData(Authenticatable $user, EnrollmentState $state): array
    {
        return [];
    }

    public function forget(Authenticatable $user): void {}
}
