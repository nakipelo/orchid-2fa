<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\ChannelManager;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification as BaseNotification;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Channels\EmailChannel;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Notifications\TwoFactorEmailChangedNotification;
use Orchid\Support\Facades\Dashboard;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mailer\Transport\AbstractTransport;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

/**
 * Spec §4.9, §5.8, §10: the e-mail change of a user with two-factor authentication.
 */
beforeEach(function () {
    Notification::fake();
});

function ecEnabledUser(string $email = 'old@example.com'): User
{
    $user = tfUser($email);
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'enabled_at' => now(), 'confirmed_at' => now()]);

    return $user;
}

function ecRecord(User $user): ?TwoFactorAuthentication
{
    return TwoFactorAuthentication::query()->where('user_id', $user->id)->first();
}

/**
 * Notices sent to the address, as the masked new addresses they carry.
 *
 * @return list<string>
 */
function ecNotices(string $to): array
{
    return Notification::sent(
        new AnonymousNotifiable,
        TwoFactorEmailChangedNotification::class,
        fn ($notification, $channels, $notifiable) => $notifiable->routes['mail'] === $to,
    )->map(fn (TwoFactorEmailChangedNotification $notification) => $notification->maskedNewAddress)->values()->all();
}

class CustomEmailChangedNotification extends BaseNotification
{
    public function __construct(public readonly string $maskedNewAddress) {}

    /**
     * @return list<string>
     */
    public function via(mixed $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(mixed $notifiable): MailMessage
    {
        return (new MailMessage)->line('custom '.$this->maskedNewAddress);
    }
}

/**
 * The e-mail channel of an application (`channels.email.driver`) that records the notices it sends.
 */
class RecordingEmailChannel extends EmailChannel
{
    /**
     * @var list<string>
     */
    public static array $sent = [];

    public function notify(string $address, BaseNotification $notification): void
    {
        self::$sent[] = $address;

        parent::notify($address, $notification);
    }
}

it('notifies the old address, keeps 2FA and requires the new address to be confirmed', function () {
    $user = ecEnabledUser();
    app(ChallengeManager::class)->issue($user);

    $user->email = 'new@example.org';
    $user->save();

    expect(ecNotices('old@example.com'))->toBe(['n***@example.org'])
        ->and(ecNotices('new@example.org'))->toBe([]);

    $record = ecRecord($user);
    expect($record->enabled_at)->not->toBeNull()
        ->and($record->confirmed_at)->toBeNull()
        ->and($record->trusted_devices_version)->toBe(1)
        ->and(cache()->get('orchid-2fa:code:'.$user->id))->toBeNull();
});

it('sends the next login code to the new address and confirms it', function () {
    $user = ecEnabledUser();
    $user->forceFill(['email' => 'new@example.org'])->save();

    tfLogin('new@example.org')->assertRedirect(route('platform.two-factor.challenge'));
    $this->get(route('platform.two-factor.challenge'))->assertSee('n***@example.org');
    expect(tfSentCodes('old@example.com'))->toBe([]);

    tfVerify(tfLastCode('new@example.org'))->assertRedirect(route('platform.main'));

    expect(ecRecord($user)->confirmed_at)->not->toBeNull();
});

it('notifies an enforced user without a record and creates none', function () {
    $user = tfEnforcedUser('old@example.com');

    $user->forceFill(['email' => 'new@example.org'])->save();

    expect(ecNotices('old@example.com'))->toBe(['n***@example.org'])
        ->and(TwoFactorAuthentication::query()->count())->toBe(0);
});

it('does not notify a user without 2FA', function () {
    $user = tfUser('old@example.com');
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'confirmed_at' => now()]);

    $user->forceFill(['email' => 'new@example.org'])->save();

    Notification::assertNothingSent();
    expect(ecRecord($user)->confirmed_at)->toBeNull();
});

it('does nothing when the address does not change', function () {
    $user = ecEnabledUser();

    $user->forceFill(['name' => 'renamed'])->save();

    Notification::assertNothingSent();
    expect(ecRecord($user)->confirmed_at)->not->toBeNull();
});

it('does not notice mass updates through the query builder', function () {
    $user = ecEnabledUser();

    User::query()->whereKey($user->id)->update(['email' => 'new@example.org']);

    Notification::assertNothingSent();
});

it('notifies when the user changes the address in the profile screen', function () {
    $user = ecEnabledUser();

    $this->actingAs($user)
        ->post(route('platform.profile', ['method' => 'save']), [
            'user' => ['name' => 'user', 'email' => 'new@example.org'],
        ])
        ->assertSessionHasNoErrors();

    expect($user->refresh()->email)->toBe('new@example.org')
        ->and(ecNotices('old@example.com'))->toBe(['n***@example.org'])
        ->and(ecRecord($user)->confirmed_at)->toBeNull();
});

it('notifies when an administrator changes the address in the user edit screen', function () {
    $user = ecEnabledUser();
    $admin = tfUser('admin@example.com', Dashboard::getAllowAllPermission()->all());

    $this->actingAs($admin)
        ->post(route('platform.systems.users.edit', [$user, 'method' => 'save']), [
            'user' => ['name' => 'user', 'email' => 'new@example.org'],
            'permissions' => [base64_encode('platform.index') => '1'],
        ])
        ->assertRedirect(route('platform.systems.users'));

    expect(ecNotices('old@example.com'))->toBe(['n***@example.org'])
        ->and(ecRecord($user)->enabled_at)->not->toBeNull();
});

it('uses the configured notification class', function () {
    config(['orchid-2fa.notification.email_changed_class' => CustomEmailChangedNotification::class]);
    $user = ecEnabledUser();

    $user->forceFill(['email' => 'new@example.org'])->save();

    Notification::assertSentOnDemand(
        CustomEmailChangedNotification::class,
        fn ($notification, $channels, $notifiable) => $notifiable->routes['mail'] === 'old@example.com'
            && $notification->maskedNewAddress === 'n***@example.org',
    );
    Notification::assertNotSentTo(new AnonymousNotifiable, TwoFactorEmailChangedNotification::class);
});

it('sends the notice through the configured e-mail channel class', function () {
    config(['orchid-2fa.channels.email.driver' => RecordingEmailChannel::class]);
    RecordingEmailChannel::$sent = [];
    $user = ecEnabledUser();

    $user->forceFill(['email' => 'new@example.org'])->save();

    expect(RecordingEmailChannel::$sent)->toBe(['old@example.com'])
        ->and(ecNotices('old@example.com'))->toBe(['n***@example.org']);
});

it('queues the notice with notification.queue', function () {
    Queue::fake();
    config(['orchid-2fa.notification.queue' => true, 'orchid-2fa.notification.queue_name' => 'mail']);
    $user = ecEnabledUser();

    $user->forceFill(['email' => 'new@example.org'])->save();

    Queue::assertPushedOn('mail', SendQueuedNotifications::class, fn (SendQueuedNotifications $job) => $job->notification instanceof TwoFactorEmailChangedNotification
        && $job->notifiables->first()->routes === ['mail' => 'old@example.com']);
});

it('renders the notice in English and Russian without the full new address', function () {
    $notification = new TwoFactorEmailChangedNotification('n***@example.org');

    $en = $notification->toMail(new AnonymousNotifiable);
    expect($en->subject)->toBe('The e-mail address of your account has been changed')
        ->and(implode(' ', $en->introLines))->toContain('n***@example.org')
        ->toContain('contact your administrator');

    app()->setLocale('ru');
    $ru = $notification->toMail(new AnonymousNotifiable);
    expect($ru->subject)->toBe('Адрес электронной почты учётной записи изменён')
        ->and(implode(' ', $ru->introLines))->toContain('изменён на n***@example.org');
});

it('logs a failed notice and keeps the change', function () {
    // A real notification dispatcher instead of the fake of beforeEach().
    Notification::swap(new ChannelManager(app()));
    Mail::extend('down', fn () => new class extends AbstractTransport
    {
        protected function doSend(SentMessage $message): void
        {
            throw new TransportException('Connection refused.');
        }

        public function __toString(): string
        {
            return 'down://';
        }
    });
    config(['mail.mailers.down' => ['transport' => 'down'], 'mail.default' => 'down']);
    $user = ecEnabledUser();

    $user->forceFill(['email' => 'new@example.org'])->save();

    expect($user->refresh()->email)->toBe('new@example.org')
        ->and(ecRecord($user)->confirmed_at)->toBeNull()
        ->and($this->logHandler()->hasErrorThatContains('the e-mail change notice could not be sent'))->toBeTrue();
});
