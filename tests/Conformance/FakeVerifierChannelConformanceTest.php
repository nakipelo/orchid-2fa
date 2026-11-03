<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Conformance;

use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
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

    protected function enroll(User $user): void
    {
        FakeVerifierChannel::enrollUser($user);
    }

    protected function validCode(User $user): string
    {
        return FakeVerifierChannel::currentCode($user);
    }

    protected function invalidCode(User $user): string
    {
        try {
            $valid = [FakeVerifierChannel::currentCode($user, -1), FakeVerifierChannel::currentCode($user), FakeVerifierChannel::currentCode($user, 1)];
        } catch (\RuntimeException) {
            $valid = []; // not enrolled yet
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

    protected function completeEnrollmentCode(User $user, EnrollmentState $state): string
    {
        return FakeVerifierChannel::codeFor((string) $state->get('secret'));
    }
}
