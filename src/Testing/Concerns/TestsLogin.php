<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Nakipelo\Orchid2FA\Challenge\Challenge;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;
use Nakipelo\Orchid2FA\Testing\Fixtures\User;

/**
 * The login with the channel (spec 0.2 §5.1, §5.2): a correct code signs in; a wrong, empty or
 * foreign code and a challenge of another channel do not.
 *
 * @mixin ChannelConformanceTestCase
 */
trait TestsLogin
{
    public function test_a_valid_code_signs_in(): void
    {
        $user = $this->enrolledUser();

        $this->login($user)->assertRedirect(route(Orchid::challengeRoute()));
        $this->assertGuest();

        $this->get(route(Orchid::challengeRoute()))->assertOk()->assertSee($this->channel()->prompt($user), false);

        $this->verifyCode($this->validCode($user))->assertRedirect($this->homeUrl());
        $this->assertAuthenticatedAs($user);
    }

    public function test_a_wrong_code_is_refused(): void
    {
        $user = $this->enrolledUser();
        $this->login($user);

        $this->verifyCode($this->invalidCode($user))->assertSessionHasErrors('code');
        $this->assertGuest();
    }

    public function test_an_empty_code_is_refused(): void
    {
        $user = $this->enrolledUser();
        $this->login($user);

        $this->verifyCode('')->assertSessionHasErrors('code');
        $this->verifyCode(' - ')->assertSessionHasErrors('code');
        $this->assertGuest();
    }

    public function test_a_code_of_another_user_is_refused(): void
    {
        $other = $this->enrolledUser('other@example.com');
        $user = $this->enrolledUser();
        $this->login($user);
        $foreign = $this->codeOfAnotherUser($other);

        // The codes of two users may coincide by chance (1 in 10^6 for 6 digits): then the other user
        // gets a new code (a delivery channel sends one, a verifier channel is enrolled again with a
        // new secret) instead of skipping the test.
        for ($attempt = 1; $foreign === $this->validCode($user); $attempt++) {
            $this->assertLessThan(5, $attempt, 'The channel keeps giving two users the same code.');
            $foreign = $this->codeOfAnotherUser($other, renew: true);
        }

        $this->verifyCode($foreign)->assertSessionHasErrors('code');
        $this->assertGuest();
    }

    /**
     * A code the channel accepts for `$user` now, without signing anybody in: a delivery channel
     * sends one (with `$renew`, a new one in place of the active code), a verifier channel gives the
     * current one (with `$renew`, after enrolling the user again).
     */
    private function codeOfAnotherUser(User $user, bool $renew = false): string
    {
        if ($this->isDelivery()) {
            if ($renew) {
                $this->challenges()->clear($user);
            }

            $this->challenges()->start($user, TwoFactorChallengeSent::CONTEXT_LOGIN, $this->channel());
        } elseif ($renew) {
            $this->enroll($user);
        }

        return $this->validCode($user);
    }

    public function test_a_challenge_of_another_channel_is_refused(): void
    {
        $user = $this->enrolledUser();
        $challenge = $this->challenges()->start($user, TwoFactorChallengeSent::CONTEXT_LOGIN, $this->channel());
        $code = $this->validCode($user);

        $foreign = new Challenge($challenge->id, $this->channelName().'-other', $challenge->context);

        $this->assertSame(VerificationResult::Expired, $this->challenges()->verify($user, $foreign, $code));
        $this->assertSame(VerificationResult::Passed, $this->challenges()->verify($user, $challenge, $code));
    }
}
