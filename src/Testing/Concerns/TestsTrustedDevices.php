<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Nakipelo\Orchid2FA\Events\TwoFactorChannelChanged;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;
use Nakipelo\Orchid2FA\TwoFactorManager;

/**
 * Trusted devices (spec §4.4 of 0.1): the cookie replaces the code; a new binding of the method
 * signs out of all trusted devices.
 *
 * @mixin ChannelConformanceTestCase
 */
trait TestsTrustedDevices
{
    public function test_a_trusted_device_skips_the_code(): void
    {
        $user = $this->enrolledUser();
        $this->login($user);
        $name = $this->application()->make(TrustedDeviceCookie::class)->name($user->getKey());

        $cookie = $this->verifyCode($this->validCode($user), ['trust_device' => '1'])->getCookie($name);
        $this->assertNotNull($cookie);

        $this->newBrowser();
        $this->withCookie($name, (string) $cookie->getValue());
        $this->login($user)->assertRedirect($this->homeUrl());
        $this->assertAuthenticatedAs($user);
    }

    public function test_a_new_binding_of_the_method_signs_out_of_trusted_devices(): void
    {
        $user = $this->enrolledUser();
        $this->login($user);
        $name = $this->application()->make(TrustedDeviceCookie::class)->name($user->getKey());
        $cookie = $this->verifyCode($this->validCode($user), ['trust_device' => '1'])->getCookie($name);
        $this->assertNotNull($cookie);

        $this->application()->make(TwoFactorManager::class)->commitEnrollment($user, $this->channel(), TwoFactorChannelChanged::REBOUND);

        $this->newBrowser();
        $this->withCookie($name, (string) $cookie->getValue());
        $this->login($user)->assertRedirect(route(Orchid::challengeRoute()));
        $this->assertGuest();
    }
}
