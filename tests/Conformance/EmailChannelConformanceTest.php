<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Conformance;

use Illuminate\Contracts\Bus\Dispatcher as BusDispatcher;
use Illuminate\Contracts\Notifications\Dispatcher as NotificationDispatcher;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\EmailChannel;
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

    protected function invalidCode(User $user, ?EnrollmentState $state = null): string
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

    /**
     * The first two codes are equal (the user's and the other user's): the suite sends the other
     * user a new code instead of skipping the test.
     */
    public function test_a_code_of_another_user_is_refused_when_the_codes_coincide(): void
    {
        $app = $this->application();
        $app->bind(EmailChannel::class, fn ($app) => new class($app['config'], $app->make(NotificationDispatcher::class), $app->make(BusDispatcher::class)) extends EmailChannel
        {
            private int $sent = 0;

            protected function generateCode(): string
            {
                return ++$this->sent <= 2 ? '123456' : parent::generateCode();
            }
        });
        $app->make(ChannelRegistry::class)->forgetChannels();

        $this->test_a_code_of_another_user_is_refused();

        $codes = Notification::sent(new AnonymousNotifiable, TwoFactorCodeNotification::class)
            ->map(fn (TwoFactorCodeNotification $notification): string => $notification->code)->values()->all();

        $this->assertCount(3, $codes);
        $this->assertSame(['123456', '123456'], array_slice($codes, 0, 2));
        $this->assertNotSame('123456', $codes[2]);
    }
}
