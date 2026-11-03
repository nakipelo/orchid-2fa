<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Conformance;

use Closure;
use Nakipelo\Orchid2FA\Channels\VerifierChannel;
use Nakipelo\Orchid2FA\Facades\TwoFactor;
use Nakipelo\Orchid2FA\Tests\Fixtures\LeakyFakeVerifierChannel;
use PHPUnit\Framework\AssertionFailedError;

/**
 * The conformance suite catches a naive driver (spec 0.2 §10.2): `fake` whose new enrollment keeps
 * the old secret valid and whose enrollmentData() logs the secret passes every other test of the
 * suite and fails only test_a_new_enrollment_replaces_the_old_binding() and
 * test_no_codes_or_secrets_reach_the_logs_or_the_events() (the overrides expect these failures; the
 * inherited test with coinciding codes runs the first one through its override).
 */
class LeakyFakeVerifierChannelConformanceTest extends FakeVerifierChannelConformanceTest
{
    protected function setUp(): void
    {
        parent::setUp();

        LeakyFakeVerifierChannel::$oldSecrets = [];
        TwoFactor::extend('fake', fn () => new LeakyFakeVerifierChannel);
    }

    protected function racingChannel(Closure $between): ?VerifierChannel
    {
        $channel = new LeakyFakeVerifierChannel;
        $channel->between = $between;

        return $channel;
    }

    public function test_the_registered_channel_is_the_leaky_one(): void
    {
        $this->assertInstanceOf(LeakyFakeVerifierChannel::class, $this->channel());
    }

    public function test_a_new_enrollment_replaces_the_old_binding(): void
    {
        $this->expectSuiteFailure(fn () => parent::test_a_new_enrollment_replaces_the_old_binding(), 'the old secret or device stays valid');
    }

    public function test_no_codes_or_secrets_reach_the_logs_or_the_events(): void
    {
        $this->expectSuiteFailure(fn () => parent::test_no_codes_or_secrets_reach_the_logs_or_the_events(), 'fake enrollment');
    }

    /**
     * @param  Closure(): void  $test
     */
    private function expectSuiteFailure(Closure $test, string $message): void
    {
        try {
            $test();
        } catch (AssertionFailedError $e) {
            $this->assertStringContainsString($message, $e->getMessage());

            return;
        }

        $this->fail('The conformance suite let the leaky channel pass.');
    }
}
