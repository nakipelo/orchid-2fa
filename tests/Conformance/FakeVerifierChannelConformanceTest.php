<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Conformance;

use Closure;
use Illuminate\Support\Facades\DB;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Channels\VerifierChannel;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;
use Nakipelo\Orchid2FA\Testing\Fixtures\User;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierChannel;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierServiceProvider;
use Nakipelo\Orchid2FA\Tests\Fixtures\RegisterFakeVerifierProvider;

/**
 * The test driver `fake` passes the conformance suite (spec 0.2 §10.1, §10.2).
 */
class FakeVerifierChannelConformanceTest extends ChannelConformanceTestCase
{
    protected function channelName(): string
    {
        return 'fake';
    }

    protected function channelProviders(): array
    {
        return [FakeVerifierServiceProvider::class, RegisterFakeVerifierProvider::class];
    }

    /**
     * Secrets for the next enrollments, in this order (then random again).
     *
     * @var list<string>
     */
    private array $secrets = [];

    protected function enroll(User $user): void
    {
        FakeVerifierChannel::enrollUser($user, array_shift($this->secrets));
    }

    protected function validCode(User $user): string
    {
        return FakeVerifierChannel::currentCode($user);
    }

    protected function invalidCode(User $user, ?EnrollmentState $state = null): string
    {
        try {
            $valid = [FakeVerifierChannel::currentCode($user, -1), FakeVerifierChannel::currentCode($user), FakeVerifierChannel::currentCode($user, 1)];
        } catch (\RuntimeException) {
            $valid = []; // not enrolled yet
        }

        // The codes of the secret of the enrollment step.
        $secret = $state?->get('secret');

        if (is_string($secret)) {
            $step = FakeVerifierChannel::currentStep();
            array_push($valid, FakeVerifierChannel::codeFor($secret, $step - 1), FakeVerifierChannel::codeFor($secret, $step), FakeVerifierChannel::codeFor($secret, $step + 1));
        }

        foreach (['000000', '111111', '222222', '333333'] as $code) {
            if (! in_array($code, $valid, true)) {
                return $code;
            }
        }

        return '444444';
    }

    protected function nextCodeWindow(): void
    {
        $this->travel(FakeVerifierChannel::STEP)->seconds();
    }

    protected function racingChannel(Closure $between): ?VerifierChannel
    {
        $channel = new FakeVerifierChannel;
        $channel->between = $between;

        return $channel;
    }

    protected function completeEnrollmentCode(User $user, EnrollmentState $state): string
    {
        return FakeVerifierChannel::codeFor((string) $state->get('secret'));
    }

    /**
     * Both users get the same secret, so the same code: the suite enrolls the other user again
     * (a new secret) instead of skipping the test.
     */
    public function test_a_code_of_another_user_is_refused_when_the_codes_coincide(): void
    {
        $this->secrets = [str_repeat('s', 32), str_repeat('s', 32)];

        $this->test_a_code_of_another_user_is_refused();

        $this->assertSame([], $this->secrets);
        $this->assertNotSame(
            DB::table(FakeVerifierChannel::TABLE)->where('user_id', User::query()->where('email', 'other@example.com')->value('id'))->value('secret'),
            str_repeat('s', 32),
        );
    }

    /**
     * The new enrollment gets the secret of the old binding, so the old code is valid again: the suite
     * enrolls once more (a new secret) instead of skipping the check.
     */
    public function test_a_new_enrollment_replaces_the_old_binding_when_the_codes_coincide(): void
    {
        $this->secrets = [str_repeat('o', 32)];
        FakeVerifierChannel::$enrollmentSecrets = [str_repeat('o', 32)];

        $this->test_a_new_enrollment_replaces_the_old_binding();

        $this->assertSame([], FakeVerifierChannel::$enrollmentSecrets);
        $this->assertNotSame(str_repeat('o', 32), DB::table(FakeVerifierChannel::TABLE)->value('secret'));
    }
}
