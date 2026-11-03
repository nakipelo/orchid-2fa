<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Nakipelo\Orchid2FA\Challenge\Challenge;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;

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
        $this->login($other);
        $foreign = $this->validCode($other);
        $this->newBrowser();

        $user = $this->enrolledUser();
        $this->login($user);

        if ($foreign === $this->validCode($user)) {
            $this->markTestSkipped('The codes of the two users happen to be equal.');
        }

        $this->verifyCode($foreign)->assertSessionHasErrors('code');
        $this->assertGuest();
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
