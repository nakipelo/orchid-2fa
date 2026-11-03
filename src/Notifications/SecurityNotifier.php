<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Notifications;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Log\LogManager;
use Illuminate\Notifications\Notification;
use InvalidArgumentException;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\EmailChannel;
use Psr\Log\LoggerInterface;
use ReflectionClass;
use Throwable;

/**
 * Sends the security notices (spec 0.2 §8.3) to the address `channels.email.attribute` of the user
 * through EmailChannel::notify() (queued with `notification.queue`). Off with
 * `notification.security.enabled = false`; a failed notice is logged and never breaks the action.
 *
 * @internal
 */
class SecurityNotifier
{
    public function __construct(
        protected Container $container,
        protected Repository $config,
        protected ChannelRegistry $channels,
        protected LogManager $log,
    ) {}

    /**
     * @param  array<string, mixed>  $context
     */
    public function send(Authenticatable $user, string $event, array $context = []): void
    {
        if (! $this->config->get('orchid-2fa.notification.security.enabled', true)) {
            return;
        }

        try {
            $email = $this->emailChannel();
            $address = $email->destination($user);

            if ($address === '') {
                return;
            }

            $email->notify($address, $this->make($event, $context + $this->labels($context)));
        } catch (Throwable $e) {
            $this->logger()->error('nakipelo/orchid-2fa: the security notice could not be sent.', [
                'user_id' => $user->getAuthIdentifier(),
                'event' => $event,
                'exception' => $e,
            ]);
        }
    }

    /**
     * The channel `email` of the registry, the same one that sends the codes; the base
     * EmailChannel if it is not registered or does not extend EmailChannel (the notices are always
     * e-mails, spec 0.2 §4.8).
     */
    public function emailChannel(): EmailChannel
    {
        try {
            $channel = $this->channels->has('email') ? $this->channels->channel('email') : null;
        } catch (InvalidArgumentException) {
            $channel = null;
        }

        return $channel instanceof EmailChannel ? $channel : $this->container->make(EmailChannel::class);
    }

    /**
     * Translated names of the channels `from` / `to`, when they are registered.
     *
     * @param  array<string, mixed>  $context
     * @return array<string, string>
     */
    protected function labels(array $context): array
    {
        $labels = [];

        foreach (['from', 'to'] as $key) {
            $name = $context[$key] ?? null;

            if (! is_string($name) || $name === '') {
                continue;
            }

            try {
                $labels[$key.'_label'] = $this->channels->has($name) ? $this->channels->channel($name)->label() : $name;
            } catch (Throwable) {
                $labels[$key.'_label'] = $name;
            }
        }

        return $labels;
    }

    /**
     * @param  array<string, mixed>  $context
     */
    protected function make(string $event, array $context): Notification
    {
        $class = $this->config->get('orchid-2fa.notification.security_class', TwoFactorSecurityNotification::class);

        $notification = is_string($class) && class_exists($class)
            ? (new ReflectionClass($class))->newInstance($event, $context)
            : null;

        if (! $notification instanceof Notification) {
            throw new InvalidArgumentException('[orchid-2fa.notification.security_class] must be a notification class.');
        }

        return $notification;
    }

    protected function logger(): LoggerInterface
    {
        $channel = $this->config->get('orchid-2fa.log.channel');

        return $this->log->channel(is_string($channel) && $channel !== '' ? $channel : null);
    }
}
