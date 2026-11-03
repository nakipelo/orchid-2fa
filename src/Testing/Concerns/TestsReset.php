<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;

/**
 * The reset hook (spec 0.2 §4.1, §5.10): forget() erases the enrollment, is idempotent, and a new
 * enrollment works over leftover data of the driver.
 *
 * @mixin ChannelConformanceTestCase
 */
trait TestsReset
{
    public function test_forget_erases_the_enrollment_and_is_idempotent(): void
    {
        $user = $this->enrolledUser();
        $this->assertTrue($this->channel()->isAvailableFor($user));

        $this->channel()->forget($user);
        $this->channel()->forget($user);

        if ($this->channel()->enrollmentView() !== null || ! $this->isDelivery()) {
            $this->assertFalse($this->channel()->isAvailableFor($user));
        }
    }

    public function test_an_enrollment_works_over_leftover_data(): void
    {
        $user = $this->enrolledUser();

        // A reset without the driver leaves its data behind; a new enrollment must replace them.
        $this->nextCodeWindow();
        $state = EnrollmentState::start($this->application()->make('session.store'), $user, $this->channelName(), TwoFactorChallengeSent::CONTEXT_ENROLL);
        $this->challenges()->startEnrollment($user, $this->channel(), $state);

        $result = $this->challenges()->confirmEnrollment($user, $this->channel(), $state, $this->completeEnrollmentCode($user, $state));

        $this->assertSame(VerificationResult::Passed, $result);
        $this->assertTrue($this->channel()->isAvailableFor($user));
    }
}
