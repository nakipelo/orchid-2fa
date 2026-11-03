<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Channels;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Bus\Dispatcher as BusDispatcher;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Notifications\Dispatcher as NotificationDispatcher;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\Notification;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Collection;
use InvalidArgumentException;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;
use ReflectionClass;
use Throwable;

/**
 * The default channel `email` (spec 0.2 §4.2, §4.3): sends the code by e-mail with the
 * notification from `notification.class` (spec §5.2, §5.8 of 0.1). Can be extended by an
 * application and registered as `channels.email.driver`.
 *
 * The notification is routed to the address from `channels.email.attribute`, so the user
 * model does not need the Notifiable trait. Without `notification.queue` it is sent
 * synchronously (even if the class implements ShouldQueue) and transport errors become
 * DeliveryFailedException (fail-closed, spec §4.10).
 */
class EmailChannel extends DeliveryChannel
{
    public function __construct(
        protected Repository $config,
        protected NotificationDispatcher $notifications,
        protected BusDispatcher $bus,
    ) {}

    /**
     * The registry name; `email` for an instance created outside the registry.
     */
    public function name(): string
    {
        return $this->channelName ?? 'email';
    }

    public function label(): string
    {
        return (string) __('orchid-2fa::messages.channels.email');
    }

    public function destination(Authenticatable $user): string
    {
        $address = data_get($user, (string) $this->config->get('orchid-2fa.channels.email.attribute', 'email'));

        return is_string($address) ? trim($address) : '';
    }

    public function maskedDestination(Authenticatable $user): string
    {
        return self::mask($this->destination($user));
    }

    /**
     * First character of the local part + `***` + `@` + the whole domain.
     */
    public static function mask(string $address): string
    {
        if ($address === '') {
            return '';
        }

        $at = mb_strrpos($address, '@');

        if ($at === false) {
            return mb_substr($address, 0, 1).'***';
        }

        return mb_substr($address, 0, min(1, $at)).'***'.mb_substr($address, $at);
    }

    public function send(Authenticatable $user, #[\SensitiveParameter] string $code, CarbonInterface $expiresAt): void
    {
        $address = $this->destination($user);

        if ($address === '') {
            throw new DeliveryFailedException('The user has no e-mail address to send the two-factor code to.');
        }

        $this->notify($address, $this->makeNotification($code, $expiresAt));
    }

    /**
     * Send a mail notification to an address: through the queue with `notification.queue`,
     * synchronously otherwise. Also used for the e-mail change notice (spec §4.9, §5.8).
     *
     * @throws DeliveryFailedException
     */
    public function notify(string $address, Notification $notification): void
    {
        $notifiable = (new AnonymousNotifiable)->route('mail', $address);

        try {
            if ($this->config->get('orchid-2fa.notification.queue')) {
                $this->bus->dispatch(
                    (new SendQueuedNotifications(new Collection([$notifiable]), $notification, ['mail']))
                        ->onConnection($this->stringOrNull('orchid-2fa.notification.connection'))
                        ->onQueue($this->stringOrNull('orchid-2fa.notification.queue_name')),
                );

                return;
            }

            $this->notifications->sendNow($notifiable, $notification, ['mail']);
        } catch (Throwable $e) {
            throw new DeliveryFailedException('The notification could not be sent: '.$e->getMessage(), 0, $e);
        }
    }

    protected function makeNotification(#[\SensitiveParameter] string $code, CarbonInterface $expiresAt): Notification
    {
        $class = $this->config->get('orchid-2fa.notification.class', TwoFactorCodeNotification::class);

        $notification = is_string($class) && class_exists($class)
            ? (new ReflectionClass($class))->newInstance($code, $expiresAt)
            : null;

        if (! $notification instanceof Notification) {
            throw new InvalidArgumentException('[orchid-2fa.notification.class] must be a notification class.');
        }

        return $notification;
    }

    protected function stringOrNull(string $key): ?string
    {
        $value = $this->config->get($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
