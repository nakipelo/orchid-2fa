<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;

/**
 * Enrollment (spec 0.2 §4.6, §5.4): no data without a correct code, a cancelled step leaves no
 * state, the enrollment at the login of a user without a method.
 *
 * @mixin ChannelConformanceTestCase
 */
trait TestsEnrollment
{
    public function test_a_wrong_enrollment_code_stores_nothing(): void
    {
        $user = $this->makeUser();
        $state = EnrollmentState::start($this->application()->make('session.store'), $user, $this->channelName(), TwoFactorChallengeSent::CONTEXT_ENROLL);
        $this->challenges()->startEnrollment($user, $this->channel(), $state);

        $result = $this->challenges()->confirmEnrollment($user, $this->channel(), $state, $this->invalidCode($user));

        $this->assertSame(VerificationResult::Invalid, $result);

        if (! $this->isDelivery() || $this->channel()->enrollmentView() !== null) {
            $this->assertFalse($this->channel()->isAvailableFor($user));
        }

        $this->assertSame(VerificationResult::Passed, $this->challenges()->confirmEnrollment(
            $user,
            $this->channel(),
            $state,
            $this->completeEnrollmentCode($user, $state),
        ));
        $this->assertTrue($this->channel()->isAvailableFor($user));
    }

    public function test_a_cancelled_enrollment_leaves_no_state(): void
    {
        $user = $this->makeUser();
        $session = $this->application()->make('session.store');
        $state = EnrollmentState::start($session, $user, $this->channelName(), TwoFactorChallengeSent::CONTEXT_ENROLL);
        $this->challenges()->startEnrollment($user, $this->channel(), $state);

        EnrollmentState::forget($session);

        $this->assertNull(EnrollmentState::fromSession($session, $user, $this->channelName(), TwoFactorChallengeSent::CONTEXT_ENROLL, 900));
        $this->assertNull($session->get(EnrollmentState::SESSION_KEY));
    }

    public function test_a_user_without_a_method_enrolls_at_the_login(): void
    {
        if ($this->isDelivery() && $this->channel()->enrollmentView() === null) {
            $this->markTestSkipped('A delivery channel without an enrollment step is the default method, nothing to enroll.');
        }

        $user = $this->makeUser();
        $this->login($user)->assertRedirect(route(Orchid::enrollRoute()));

        $this->get(route(Orchid::enrollRoute(), ['channel' => $this->channelName()]))->assertOk();
        $state = EnrollmentState::fromSession($this->application()->make('session.store'), $user, $this->channelName(), TwoFactorChallengeSent::CONTEXT_ENROLL, 900);
        $this->assertNotNull($state);

        $response = $this->post(route(Orchid::enrollConfirmRoute(), ['channel' => $this->channelName()]), [
            'code' => $this->completeEnrollmentCode($user, $state),
        ]);

        if ($this->channel()->needsRecoveryCodes()) {
            $response->assertRedirect(route(Orchid::recoveryCodesRoute()));
            $this->get(route(Orchid::recoveryCodesRoute()))->assertOk();
            $response = $this->post(route(Orchid::recoveryCodesConfirmRoute()));
        }

        $response->assertRedirect($this->homeUrl());
        $this->assertAuthenticatedAs($user);
        $this->assertSame($this->channelName(), TwoFactorAuthentication::query()->where('user_id', $user->getKey())->value('channel'));
    }
}
