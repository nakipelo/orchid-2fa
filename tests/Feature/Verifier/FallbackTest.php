<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierChannel;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §6.2, §6.4, §13: the core mechanism of "send a code by e-mail" for a verifier method.
 */
beforeEach(function () {
    Notification::fake();
    tfUseFake();
});

it('sends an e-mail code instead when the verifier channel allows it, and accepts it', function () {
    Event::fake([TwoFactorChallengeSent::class, TwoFactorPassed::class]);
    FakeVerifierChannel::$emailFallback = true;
    $user = tfFakeUser();
    tfLogin();

    $this->get(route('platform.two-factor.challenge'))->assertSee(route('platform.two-factor.fallback'), false);

    $this->post(route('platform.two-factor.fallback'))
        ->assertRedirect(route('platform.two-factor.challenge'))
        ->assertSessionHas('orchid-2fa.status', 'A code has been sent to your e-mail address.');
    Event::assertDispatched(TwoFactorChallengeSent::class, fn ($event) => $event->context === 'fallback' && $event->channel === 'email');

    $this->get(route('platform.two-factor.challenge'))
        ->assertSee('We have sent a code to e***@example.com.')
        ->assertSee(route('platform.two-factor.resend'), false);

    tfVerify(tfLastCode())->assertRedirect(route('platform.main'));
    $this->assertAuthenticatedAs($user);
    Event::assertDispatched(TwoFactorPassed::class, fn ($event) => $event->channel === 'email');
});

it('refuses the fallback when the channel does not allow it or e-mail is not allowed', function () {
    tfFakeUser();
    tfLogin();

    $this->get(route('platform.two-factor.challenge'))->assertDontSee(route('platform.two-factor.fallback'), false);
    $this->post(route('platform.two-factor.fallback'))
        ->assertSessionHas('orchid-2fa.error', 'A code by e-mail is not available for your account.');

    FakeVerifierChannel::$emailFallback = true;
    config(['orchid-2fa.channels.allowed' => ['fake']]);
    $this->post(route('platform.two-factor.fallback'))
        ->assertSessionHas('orchid-2fa.error', 'A code by e-mail is not available for your account.');

    expect(tfSentCodes())->toBe([]);
});

it('does not accept a fallback code once the fallback is no longer available', function () {
    FakeVerifierChannel::$emailFallback = true;
    tfFakeUser();
    tfLogin();
    $this->post(route('platform.two-factor.fallback'));

    FakeVerifierChannel::$emailFallback = false;

    tfVerify(tfLastCode())->assertRedirect(route('platform.login'));
    $this->assertGuest();
});
