<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Notifications\TwoFactorEmailChangedNotification;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §5.11, §10.1: an e-mail change of a user of a verifier method.
 */
beforeEach(function () {
    Notification::fake();
    tfUseFake();
});

it('notifies the old address and keeps the method, its confirmation and the trusted devices', function () {
    $user = tfFakeUser();
    tfLogin();
    $name = app(TrustedDeviceCookie::class)->name($user->id);
    $cookie = tfVerify(tfFakeCode($user), ['trust_device' => '1'])->getCookie($name)?->getValue();
    $this->newBrowser();

    $user->forceFill(['email' => 'new@example.com'])->save();

    Notification::assertSentOnDemand(TwoFactorEmailChangedNotification::class, fn ($notification, $channels, $notifiable) => $notifiable->routes['mail'] === 'enforced@example.com');

    $record = TwoFactorAuthentication::query()->where('user_id', $user->id)->first();
    expect($record->channel)->toBe('fake')
        ->and($record->confirmed_at)->not->toBeNull()
        ->and($record->trusted_devices_version)->toBe(1);

    // The trusted device still works: the address takes no part in the second factor.
    $this->withCookie($name, (string) $cookie);
    tfLogin('new@example.com')->assertRedirect(route('platform.main'));
});

it('annuls an active e-mail code (the fallback) on an e-mail change', function () {
    $user = tfFakeUser();
    app(ChallengeManager::class)->issue($user, 'fallback', app(ChannelRegistry::class)->channel('email'));
    expect(cache()->has('orchid-2fa:code:'.$user->id))->toBeTrue();

    $user->forceFill(['email' => 'new@example.com'])->save();

    expect(cache()->has('orchid-2fa:code:'.$user->id))->toBeFalse();
});
