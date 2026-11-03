<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\Queue;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;

uses(RefreshDatabase::class);

/**
 * Spec §4.10, §5.8: notification.queue sends the code through the queue.
 */
it('queues the code with the configured connection and queue', function () {
    Queue::fake();
    config([
        'orchid-2fa.notification.queue' => true,
        'orchid-2fa.notification.connection' => 'redis',
        'orchid-2fa.notification.queue_name' => 'mail',
    ]);
    tfEnforcedUser();

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));

    Queue::assertPushedOn('mail', SendQueuedNotifications::class, function (SendQueuedNotifications $job) {
        return $job->connection === 'redis'
            && $job->notification instanceof TwoFactorCodeNotification
            && $job->notifiables->first()->routes === ['mail' => 'enforced@example.com'];
    });
    $this->get(route('platform.two-factor.challenge'))->assertDontSee('We could not send the code');
});

it('sends synchronously by default', function () {
    Queue::fake();
    config(['mail.default' => 'array']);
    tfEnforcedUser();

    tfLogin();

    Queue::assertNothingPushed();
    expect(app('mail.manager')->mailer('array')->getSymfonyTransport()->messages())->toHaveCount(1);
});
