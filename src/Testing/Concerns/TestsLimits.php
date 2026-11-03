<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Illuminate\Support\Facades\Event;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;

/**
 * The limits (spec 0.2 §4.4): attempts of a challenge for every channel; the window of the user and
 * the daily ceiling for a verifier channel; the cooldown and the hourly limit for a delivery channel.
 *
 * @mixin ChannelConformanceTestCase
 */
trait TestsLimits
{
    public function test_the_attempts_of_a_challenge_are_limited(): void
    {
        $user = $this->enrolledUser();
        $this->login($user);
        $wrong = $this->invalidCode($user);

        for ($i = 0; $i < 5; $i++) {
            $this->verifyCode($wrong);
        }

        $code = $this->validCode($user);
        $this->verifyCode($code);
        $this->assertGuest();
    }

    public function test_the_attempts_of_the_user_are_limited_across_challenges(): void
    {
        if ($this->isDelivery()) {
            $this->markTestSkipped('The window of the user applies to verifier channels.');
        }

        Event::fake([TwoFactorLockedOut::class]);
        $user = $this->enrolledUser();
        $wrong = $this->invalidCode($user);

        // A new challenge does not reset the window: 4 + 4 + 2 wrong codes.
        foreach ([4, 4, 2] as $count) {
            $challenge = $this->challenges()->issue($user, TwoFactorChallengeSent::CONTEXT_LOGIN, $this->channel());

            for ($i = 0; $i < $count; $i++) {
                $this->challenges()->verify($user, $challenge, $wrong);
            }
        }

        $challenge = $this->challenges()->issue($user, TwoFactorChallengeSent::CONTEXT_LOGIN, $this->channel());

        $this->assertSame(VerificationResult::LockedOut, $this->challenges()->verify($user, $challenge, $this->validCode($user)));
        Event::assertDispatched(TwoFactorLockedOut::class, fn (TwoFactorLockedOut $event): bool => $event->reason === TwoFactorLockedOut::USER_ATTEMPTS_EXCEEDED
            && $event->availableIn > 0);
    }

    public function test_the_attempts_of_the_user_have_a_daily_ceiling(): void
    {
        if ($this->isDelivery()) {
            $this->markTestSkipped('The daily ceiling applies to verifier channels.');
        }

        Event::fake([TwoFactorLockedOut::class]);
        config(['orchid-2fa.verify.user_max_attempts' => 1000]);
        $user = $this->enrolledUser();
        $wrong = $this->invalidCode($user);

        for ($i = 0; $i < 30; $i += 3) {
            $challenge = $this->challenges()->issue($user, TwoFactorChallengeSent::CONTEXT_LOGIN, $this->channel());

            for ($j = 0; $j < 3; $j++) {
                $this->challenges()->verify($user, $challenge, $wrong);
            }
        }

        $challenge = $this->challenges()->issue($user, TwoFactorChallengeSent::CONTEXT_LOGIN, $this->channel());

        $this->assertSame(VerificationResult::LockedOut, $this->challenges()->verify($user, $challenge, $this->validCode($user)));
        Event::assertDispatched(TwoFactorLockedOut::class, fn (TwoFactorLockedOut $event): bool => $event->reason === TwoFactorLockedOut::USER_DAILY_ATTEMPTS_EXCEEDED
            && $event->availableIn > 3600);
    }

    public function test_sending_is_limited(): void
    {
        if (! $this->isDelivery()) {
            $this->markTestSkipped('A verifier channel sends nothing.');
        }

        $user = $this->enrolledUser();
        $this->login($user);

        $this->post(route(Orchid::resendRoute()))->assertRedirect(route(Orchid::challengeRoute()));
        $this->assertNotNull(session('orchid-2fa.error'));
        $this->assertGreaterThan(0, $this->challenges()->sendAvailableIn($user, $this->channel()));
    }
}
