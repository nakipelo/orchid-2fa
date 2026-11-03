<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Conformance;

use Closure;
use Nakipelo\Orchid2FA\Channels\VerifierChannel;
use Nakipelo\Orchid2FA\Facades\TwoFactor;
use Nakipelo\Orchid2FA\Tests\Fixtures\NonAtomicFakeVerifierChannel;
use PHPUnit\Framework\AssertionFailedError;

/**
 * The race test of the conformance suite catches a replay protection that is not atomic
 * (spec 0.2 §4.2, §10.2): the driver `fake` with a read-compare-write verifyCode() passes every
 * other test of the suite, including a code verified twice one after another, and fails only
 * test_interleaved_verifications_of_a_code_let_only_one_pass().
 */
class NonAtomicFakeVerifierChannelConformanceTest extends FakeVerifierChannelConformanceTest
{
    protected function setUp(): void
    {
        parent::setUp();

        TwoFactor::extend('fake', fn () => new NonAtomicFakeVerifierChannel);
    }

    protected function racingChannel(Closure $between): ?VerifierChannel
    {
        $channel = new NonAtomicFakeVerifierChannel;
        $channel->between = $between;

        return $channel;
    }

    public function test_the_registered_channel_is_the_non_atomic_one(): void
    {
        $this->assertInstanceOf(NonAtomicFakeVerifierChannel::class, $this->channel());
    }

    public function test_interleaved_verifications_of_a_code_let_only_one_pass(): void
    {
        try {
            parent::test_interleaved_verifications_of_a_code_let_only_one_pass();
        } catch (AssertionFailedError $e) {
            $this->assertStringContainsString('got Passed (outer) and Passed (inner)', $e->getMessage());

            return;
        }

        $this->fail('The race test let a channel without an atomic replay protection pass.');
    }
}
