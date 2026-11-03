<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Conformance;

use Closure;
use Nakipelo\Orchid2FA\Channels\VerifierChannel;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\SkippedTest;

/**
 * A verifier driver without racingChannel() (spec 0.2 §10.2): the race test fails with "Override
 * racingChannel() or skipsRaceTest()" instead of being skipped; skipsRaceTest() is the explicit
 * opt-out that skips it. The rest of the suite runs as for the `fake` driver.
 */
class WithoutRacingChannelConformanceTest extends FakeVerifierChannelConformanceTest
{
    private bool $optOut = false;

    protected function racingChannel(Closure $between): ?VerifierChannel
    {
        return null;
    }

    protected function skipsRaceTest(): bool
    {
        return $this->optOut;
    }

    public function test_interleaved_verifications_of_a_code_let_only_one_pass(): void
    {
        try {
            parent::test_interleaved_verifications_of_a_code_let_only_one_pass();
            $this->fail('The race test passed a verifier channel without racingChannel().');
        } catch (SkippedTest) {
            $this->fail('The race test was skipped for a verifier channel without racingChannel(); it must fail.');
        } catch (AssertionFailedError $e) {
            $this->assertStringContainsString('Override racingChannel() or skipsRaceTest()', $e->getMessage());
        }
    }

    public function test_skips_race_test_opts_out_explicitly(): void
    {
        $this->optOut = true;

        try {
            parent::test_interleaved_verifications_of_a_code_let_only_one_pass();
        } catch (SkippedTest $e) {
            $this->assertStringContainsString('skipsRaceTest()', $e->getMessage());

            return;
        }

        $this->fail('skipsRaceTest() did not skip the race test.');
    }
}
