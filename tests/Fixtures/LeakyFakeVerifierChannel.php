<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;

/**
 * A naive `fake` channel for the conformance suite (spec 0.2 §10.2): a new enrollment keeps the old
 * secret valid as well (the old device keeps working after a rebind), and enrollmentData() writes the
 * secret to the log. Everything else is the honest FakeVerifierChannel.
 */
class LeakyFakeVerifierChannel extends FakeVerifierChannel
{
    /**
     * Secrets replaced by a new enrollment, per user id.
     *
     * @var array<int|string, list<string>>
     */
    public static array $oldSecrets = [];

    public function confirmEnrollment(Authenticatable $user, EnrollmentState $state, string $code): VerificationResult
    {
        $old = DB::table(self::TABLE)->where('user_id', $user->getAuthIdentifier())->value('secret');
        $result = parent::confirmEnrollment($user, $state, $code);

        if ($result === VerificationResult::Passed && is_string($old)) {
            self::$oldSecrets[$user->getAuthIdentifier()][] = $old;
        }

        return $result;
    }

    protected function verifyCode(Authenticatable $user, string $code): bool
    {
        if (parent::verifyCode($user, $code)) {
            return true;
        }

        foreach (self::$oldSecrets[$user->getAuthIdentifier()] ?? [] as $secret) {
            if (self::matchingStep($secret, $code) !== null) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, mixed>
     */
    public function enrollmentData(Authenticatable $user, EnrollmentState $state): array
    {
        $data = parent::enrollmentData($user, $state);
        Log::info('fake enrollment', ['secret' => $data['fakeSecret']]);

        return $data;
    }

    public function forget(Authenticatable $user): void
    {
        parent::forget($user);
        unset(self::$oldSecrets[$user->getAuthIdentifier()]);
    }
}
