<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Nakipelo\Orchid2FA\Challenge\Context;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;

/**
 * The reset hook (spec 0.2 §4.1, §5.10): forget() erases the enrollment, is idempotent, a new
 * enrollment works over leftover data of the driver and replaces the previous binding: a code of the
 * old binding (the old secret, the old device) is refused afterwards (rebind, §5.7).
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
        $state = EnrollmentState::start($this->application()->make('session.store'), $user, $this->channelName(), Context::ENROLL);
        $this->challenges()->startEnrollment($user, $this->channel(), $state);

        $result = $this->challenges()->confirmEnrollment($user, $this->channel(), $state, $this->completeEnrollmentCode($user, $state));

        $this->assertSame(VerificationResult::Passed, $result);
        $this->assertTrue($this->channel()->isAvailableFor($user));
    }

    public function test_a_new_enrollment_replaces_the_old_binding(): void
    {
        $user = $this->enrolledUser();
        $session = $this->application()->make('session.store');

        // A code of the old binding in the window of the new enrollment (delivery: a code sent for a
        // login challenge, which the new enrollment's code replaces).
        $this->nextCodeWindow();
        $old = $this->challenges()->issue($user, Context::LOGIN, $this->channel());
        $oldCode = $this->validCode($user);

        if ($this->isDelivery()) {
            // The enrollment sends a code too: past the cooldown of "send again".
            $this->travel((int) config('orchid-2fa.resend.cooldown', 60) + 1)->seconds();
        }

        for ($attempt = 1; ; $attempt++) {
            $state = EnrollmentState::start($session, $user, $this->channelName(), Context::REBIND);
            $this->challenges()->startEnrollment($user, $this->channel(), $state);

            $this->assertSame(VerificationResult::Passed, $this->challenges()->confirmEnrollment(
                $user,
                $this->channel(),
                $state,
                $this->completeEnrollmentCode($user, $state),
            ));

            // The new binding gives the old code by chance (a verifier channel, ~10⁻⁶): enroll again
            // instead of skipping the check.
            if ($this->isDelivery() || $oldCode !== $this->validCode($user)) {
                break;
            }

            if ($attempt >= 5) {
                $this->fail('The channel gives a new enrollment the code of the old binding again and again.');
            }
        }

        $challenge = $this->isDelivery() ? $old : $this->challenges()->issue($user, Context::LOGIN, $this->channel());

        $this->assertNotSame(
            VerificationResult::Passed,
            $this->challenges()->verify($user, $challenge, $oldCode),
            'A code of the binding replaced by a new enrollment must be refused: the old secret or device stays valid.',
        );
    }
}
