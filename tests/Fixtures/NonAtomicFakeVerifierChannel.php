<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;

/**
 * A broken `fake` channel for the race test of the conformance suite: the replay protection reads
 * the last accepted step, compares it in PHP and then writes without a condition. Verified one after
 * another, a code still passes only once; two interleaved verifications both pass.
 */
class NonAtomicFakeVerifierChannel extends FakeVerifierChannel
{
    protected function verifyCode(Authenticatable $user, string $code): bool
    {
        $row = DB::table(self::TABLE)
            ->where('user_id', $user->getAuthIdentifier())
            ->whereNotNull('confirmed_at')
            ->first(['secret', 'last_step']);

        if ($row === null) {
            return false;
        }

        $step = self::matchingStep((string) $row->secret, $code);

        if ($step === null || ($row->last_step !== null && (int) $row->last_step >= $step)) {
            return false;
        }

        $this->interleave();

        DB::table(self::TABLE)
            ->where('user_id', $user->getAuthIdentifier())
            ->update(['last_step' => $step, 'updated_at' => now()]);

        return true;
    }
}
