<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Conformance;

use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;
use Nakipelo\Orchid2FA\Testing\Fixtures\User;

/**
 * The e-mail channel passes the conformance suite (spec 0.2 §10.2).
 */
class EmailChannelConformanceTest extends ChannelConformanceTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Notification::fake();
    }

    protected function channelName(): string
    {
        return 'email';
    }

    protected function channelProviders(): array
    {
        return [];
    }

    protected function enroll(User $user): void
    {
        // The address is the enrollment.
    }

    protected function validCode(User $user): string
    {
        $codes = Notification::sent(
            new AnonymousNotifiable,
            TwoFactorCodeNotification::class,
            fn ($notification, $channels, $notifiable): bool => $notifiable->routes['mail'] === $user->email,
        )->map(fn (TwoFactorCodeNotification $notification): string => $notification->code)->values()->all();

        $this->assertNotEmpty($codes, 'No code has been sent to the user.');

        return (string) end($codes);
    }

    protected function invalidCode(User $user): string
    {
        $codes = Notification::sent(new AnonymousNotifiable, TwoFactorCodeNotification::class)
            ->map(fn (TwoFactorCodeNotification $notification): string => $notification->code)->all();

        return in_array('000000', $codes, true) ? '111111' : '000000';
    }

    protected function nextCodeWindow(): void {}

    protected function completeEnrollmentCode(User $user, EnrollmentState $state): string
    {
        return $this->validCode($user);
    }
}
