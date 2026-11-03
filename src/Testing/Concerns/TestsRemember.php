<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Nakipelo\Orchid2FA\Events\TwoFactorChannelChanged;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;
use Nakipelo\Orchid2FA\TwoFactorManager;

/**
 * Remember me (spec §4.5 of 0.1): the cookie only after the second factor; the token is rotated by
 * an enrollment and a reset.
 *
 * @mixin ChannelConformanceTestCase
 */
trait TestsRemember
{
    public function test_the_remember_cookie_is_issued_only_after_the_second_factor(): void
    {
        $user = $this->enrolledUser();
        $recaller = Orchid::guard()->getRecallerName();

        $this->login($user, ['remember' => '1'])->assertCookieMissing($recaller);

        $this->verifyCode($this->validCode($user))->assertCookie($recaller);
        $this->assertAuthenticatedAs($user);
    }

    public function test_an_enrollment_and_a_reset_rotate_the_remember_token(): void
    {
        $user = $this->enrolledUser();
        $user->forceFill(['remember_token' => 'old-token'])->save();
        $manager = $this->application()->make(TwoFactorManager::class);

        $manager->commitEnrollment($user, $this->channel(), TwoFactorChannelChanged::ENROLLED);
        $rotated = $user->refresh()->remember_token;
        $this->assertNotSame('old-token', $rotated);

        $manager->reset($user);
        $this->assertNotSame($rotated, $user->refresh()->remember_token);
    }
}
