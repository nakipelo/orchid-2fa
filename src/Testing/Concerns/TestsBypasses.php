<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;

/**
 * Bypasses (spec §9 of 0.1, 0.2 §9): no pending login, a user id in the body, a replayed code in
 * another session, a code verified twice.
 *
 * @mixin ChannelConformanceTestCase
 */
trait TestsBypasses
{
    public function test_verify_without_a_pending_login_signs_nobody_in(): void
    {
        $user = $this->enrolledUser();
        $this->challenges()->start($user, TwoFactorChallengeSent::CONTEXT_LOGIN, $this->channel());

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

    public function test_a_code_is_accepted_only_once(): void
    {
        $user = $this->enrolledUser();
        $first = $this->challenges()->issue($user, TwoFactorChallengeSent::CONTEXT_LOGIN, $this->channel());
        $code = $this->validCode($user);
        // The parallel request carries the same challenge (delivery) or its own one (verifier).
        $second = $this->isDelivery() ? $first : $this->challenges()->issue($user, TwoFactorChallengeSent::CONTEXT_LOGIN, $this->channel());

        $this->assertSame(VerificationResult::Passed, $this->challenges()->verify($user, $first, $code));
        $this->assertNotSame(VerificationResult::Passed, $this->challenges()->verify($user, $second, $code));
    }
}
