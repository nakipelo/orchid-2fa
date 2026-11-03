<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Nakipelo\Orchid2FA\Recovery\RecoveryCodes;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;

/**
 * Recovery codes (spec 0.2 §4.7, §5.3) of a channel with needsRecoveryCodes(): the login with a
 * recovery code issues no trusted device cookie; a used code is refused.
 *
 * @mixin ChannelConformanceTestCase
 */
trait TestsRecoveryCodes
{
    public function test_a_recovery_code_signs_in_without_a_trusted_device_cookie(): void
    {
        if (! $this->channel()->needsRecoveryCodes()) {
            $this->markTestSkipped('The channel has no recovery codes.');
        }

        $user = $this->enrolledUser();
        $codes = $this->application()->make(RecoveryCodes::class)->generate($user);
        $name = $this->application()->make(TrustedDeviceCookie::class)->name($user->getKey());

        $this->login($user);
        $response = $this->post(route(Orchid::recoveryRoute()), ['recovery_code' => strtoupper($codes[0]), 'trust_device' => '1']);

        $response->assertRedirect($this->homeUrl())->assertCookieMissing($name);
        $this->assertAuthenticatedAs($user);

        $this->newBrowser();
        $this->login($user);
        $this->post(route(Orchid::recoveryRoute()), ['recovery_code' => $codes[0]])->assertSessionHasErrors('recovery_code');
        $this->assertGuest();
    }
}
