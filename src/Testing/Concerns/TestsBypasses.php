<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Nakipelo\Orchid2FA\Challenge\Challenge;
use Nakipelo\Orchid2FA\Challenge\Context;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;

/**
 * Bypasses (spec §9 of 0.1, 0.2 §9): no pending login, a user id in the body, a replayed code in
 * another session, a code verified twice one after another and two verifications of a code that
 * interleave (the latter needs ChannelConformanceTestCase::racingChannel() of a verifier driver,
 * or an explicit opt-out with skipsRaceTest()).
 *
 * @mixin ChannelConformanceTestCase
 */
trait TestsBypasses
{
    public function test_verify_without_a_pending_login_signs_nobody_in(): void
    {
        $user = $this->enrolledUser();
        $this->challenges()->start($user, Context::LOGIN, $this->channel());

        $this->verifyCode($this->validCode($user), ['user_id' => $user->getKey()])->assertRedirect(Orchid::loginUrl());
        $this->assertGuest();
    }

    public function test_a_user_id_in_the_body_does_not_select_the_user(): void
    {
        $victim = $this->enrolledUser('victim@example.com');
        $user = $this->enrolledUser();
        $this->login($user);

        $this->verifyCode($this->validCode($user), ['user_id' => $victim->getKey()])->assertRedirect($this->homeUrl());
        $this->assertAuthenticatedAs($user);
    }

    public function test_a_used_code_is_refused_in_another_session(): void
    {
        $user = $this->enrolledUser();
        $this->login($user);
        $code = $this->validCode($user);
        $this->verifyCode($code)->assertRedirect($this->homeUrl());

        $this->newBrowser();
        $this->login($user);

        if (! $this->isDelivery()) {
            $this->verifyCode($code)->assertSessionHasErrors('code');
            $this->assertGuest();

            return;
        }

        // A delivery channel sent a new code: the used one is gone.
        if ($code !== $this->validCode($user)) {
            $this->verifyCode($code)->assertSessionHasErrors('code');
            $this->assertGuest();
        }
    }

    /**
     * The same code verified twice, one request after the other. This does not prove atomicity: a
     * driver that reads and then writes without a condition passes it; see the next test.
     */
    public function test_a_code_is_accepted_only_once(): void
    {
        $user = $this->enrolledUser();
        $first = $this->challenges()->issue($user, Context::LOGIN, $this->channel());
        $code = $this->validCode($user);
        // The second request carries the same challenge (delivery) or its own one (verifier).
        $second = $this->isDelivery() ? $first : $this->challenges()->issue($user, Context::LOGIN, $this->channel());

        $this->assertSame(VerificationResult::Passed, $this->challenges()->verify($user, $first, $code));
        $this->assertNotSame(VerificationResult::Passed, $this->challenges()->verify($user, $second, $code));
    }

    /**
     * Two verifications of the same code that interleave: the second one runs entirely between the
     * read and the write of the first (ChannelConformanceTestCase::racingChannel()). Exactly one of
     * them passes: the replay protection of a verifier driver must be atomic (spec 0.2 §4.2).
     */
    public function test_interleaved_verifications_of_a_code_let_only_one_pass(): void
    {
        if ($this->isDelivery()) {
            $this->markTestSkipped('A delivery channel is verified by the final DeliveryChannel::verify(), which claims the code atomically.');
        }

        $user = $this->enrolledUser();
        $code = $this->validCode($user);
        $second = null;

        $racing = $this->racingChannel(function () use (&$second, $user, $code): void {
            $channel = $this->channel();
            $second = $channel->verify($user, Challenge::make($channel->name(), Context::LOGIN), $code);
        });

        if ($racing === null) {
            if ($this->skipsRaceTest()) {
                $this->markTestSkipped('The driver opted out of the race test with skipsRaceTest(); its own tests prove the atomic replay protection.');
            }

            $this->fail('Override racingChannel() or skipsRaceTest(): a verifier channel must show that its replay protection is atomic (two interleaved verifications of one code let only one pass).');
        }

        $racing->bootChannel($this->channelName(), (array) config('orchid-2fa.channels.'.$this->channelName(), []));
        $this->assertNotSame($this->channel(), $racing, 'racingChannel() must return a new instance, not the one of the registry.');

        $first = $racing->verify($user, Challenge::make($this->channelName(), Context::LOGIN), $code);

        $this->assertNotNull($second, 'The channel of racingChannel() did not call the callback while verifying the code.');
        $this->assertSame(
            1,
            count(array_filter([$first, $second], fn (VerificationResult $result): bool => $result === VerificationResult::Passed)),
            sprintf('Two interleaved verifications of one code must let exactly one pass; got %s (outer) and %s (inner).', $first->name, $second->name),
        );
    }
}
