<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Channels;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use InvalidArgumentException;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Nakipelo\Orchid2FA\Exceptions\UnknownChannelException;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Psr\Log\LoggerInterface;

/**
 * The registry of two-factor channels (spec 0.2 §4.3), a singleton behind the `TwoFactor` facade.
 *
 * A name resolves to a channel through `channels.<name>.driver` (a name registered with
 * extend() or a class-string created by the container); without it, through the factory
 * registered under the name itself. The 0.1 key `channels.<name>.class` is read as `driver` when
 * `driver` is not set (deprecated, removed in 0.3). Only subclasses of DeliveryChannel or
 * VerifierChannel are accepted. Channels are created lazily and cached.
 *
 * The only place that reads the default channel `orchid-2fa.channel`.
 */
class ChannelRegistry
{
    /**
     * @var array<string, Closure(Container, array<array-key, mixed>): TwoFactorChannel>
     */
    protected array $extensions = [];

    /**
     * @var array<string, TwoFactorChannel>
     */
    protected array $channels = [];

    public function __construct(
        protected Container $container,
        protected Repository $config,
    ) {}

    /**
     * Register a driver: `$factory(Container $app, array $config): TwoFactorChannel`, where
     * `$config` is `orchid-2fa.channels.<name>`. Call it in `boot()` of the driver's provider.
     *
     * @param  Closure(Container, array<array-key, mixed>): TwoFactorChannel  $factory
     */
    public function extend(string $name, Closure $factory): void
    {
        $this->extensions[$name] = $factory;

        unset($this->channels[$name]);
    }

    /**
     * The channel registered under the name.
     *
     * @throws UnknownChannelException
     * @throws InvalidArgumentException the driver is not a subclass of a base class
     */
    public function channel(string $name): TwoFactorChannel
    {
        return $this->channels[$name] ??= $this->resolve($name);
    }

    /**
     * Whether a driver is registered under the name (it is validated when the channel is created).
     */
    public function has(string $name): bool
    {
        return $this->driver($name) !== null || isset($this->extensions[$name]);
    }

    /**
     * Names of the registered channels: the configured ones, then the extensions.
     *
     * @return list<string>
     */
    public function registered(): array
    {
        $names = [];

        foreach ((array) $this->config->get('orchid-2fa.channels', []) as $name => $config) {
            if (is_string($name) && $this->driver($name) !== null) {
                $names[] = $name;
            }
        }

        return array_values(array_unique([...$names, ...array_keys($this->extensions)]));
    }

    /**
     * Registered channels allowed by `channels.allowed`, in its order (spec 0.2 §4.3).
     *
     * @return list<string>
     */
    public function allowed(): array
    {
        return array_values(array_filter($this->allowedNames(), fn (string $name): bool => $this->has($name)));
    }

    /**
     * Names in `channels.allowed` without a driver: ignored (spec 0.2 §4.3).
     *
     * @return list<string>
     */
    public function ignored(): array
    {
        return array_values(array_filter($this->allowedNames(), fn (string $name): bool => ! $this->has($name)));
    }

    public function isAllowed(string $name): bool
    {
        return in_array($name, $this->allowed(), true);
    }

    /**
     * Check `channels.allowed` once the application has booted (spec 0.2 §4.3): an ignored name is
     * a `warning` in local/testing; no allowed channel at all is an exception in local/testing
     * (`$strict`) and a `critical` log entry elsewhere (the logins that need the second factor then
     * fail closed).
     *
     * @throws InvalidArgumentException
     */
    public function check(bool $strict, LoggerInterface $logger): void
    {
        if ($strict && ($ignored = $this->ignored()) !== []) {
            $logger->warning(sprintf(
                'nakipelo/orchid-2fa: [orchid-2fa.channels.allowed] lists channels without a registered driver, they are ignored: %s.',
                implode(', ', $ignored),
            ));
        }

        if ($this->allowed() !== []) {
            return;
        }

        $message = sprintf(
            'nakipelo/orchid-2fa: no two-factor channel is allowed: [orchid-2fa.channels.allowed] = [%s], registered: [%s]. '
            .'Users who need the second factor cannot sign in.',
            implode(', ', $this->allowedNames()),
            implode(', ', $this->registered()),
        );

        if ($strict) {
            throw new InvalidArgumentException($message);
        }

        $logger->critical($message);
    }

    /**
     * The method of the user (spec 0.2 §4.5): the enrolled and allowed method; an enrolled method
     * that is no longer allowed (the proof before enrolling an allowed one); otherwise the default
     * channel when it is allowed and a delivery channel without an enrollment step; null when the
     * driver of the recorded method is gone (fail closed) or there is no method (enrollment).
     */
    public function for(Authenticatable $user): ?TwoFactorChannel
    {
        $method = $this->methodFor($user);

        return $method->state === UserMethod::ACTIVE || $method->state === UserMethod::PROOF ? $method->channel : null;
    }

    /**
     * The resolved method of the user with its state (spec 0.2 §4.5).
     */
    public function methodFor(Authenticatable $user): UserMethod
    {
        $record = TwoFactorAuthentication::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->first(['channel', 'confirmed_at']);

        $name = $record?->channel;
        $name = is_string($name) && $name !== '' ? $name : null;

        if ($name !== null) {
            $channel = $this->has($name) ? $this->tryChannel($name) : null;

            if ($channel === null) {
                return new UserMethod(UserMethod::UNAVAILABLE, null, $name);
            }

            if ($channel->isAvailableFor($user)) {
                if ($this->isAllowed($name)) {
                    return new UserMethod(UserMethod::ACTIVE, $channel, $name);
                }

                // A delivery method proves the user only with a confirmed destination (§5.4 B).
                if (! $channel->requiresDelivery() || $record?->confirmed_at !== null) {
                    return new UserMethod(UserMethod::PROOF, $channel, $name);
                }
            }
        }

        $default = $this->defaultChannel();

        return $default !== null
            ? new UserMethod(UserMethod::ACTIVE, $default, $name)
            : new UserMethod(UserMethod::NONE, null, $name);
    }

    /**
     * The default channel when it can serve a user without an enrolled method: allowed, a delivery
     * channel and without an enrollment step (spec 0.2 §4.5 item 4).
     */
    public function defaultChannel(): ?TwoFactorChannel
    {
        $name = $this->defaultName();

        if (! $this->isAllowed($name)) {
            return null;
        }

        $channel = $this->tryChannel($name);

        return $channel instanceof DeliveryChannel && $channel->enrollmentView() === null ? $channel : null;
    }

    /**
     * The default channel (`orchid-2fa.channel`): the method of a user without one of their own.
     */
    public function defaultName(): string
    {
        $name = $this->config->get('orchid-2fa.channel', 'email');

        return is_string($name) && $name !== '' ? $name : 'email';
    }

    /**
     * The name of the channel a record gets when it is created or its method is removed (disabling,
     * reset by an administrator or the command; spec 0.2 §4.8–§4.9, §5.10): the default channel when
     * it is allowed and registered (allowed() contains only registered names), otherwise null.
     */
    public function initialName(): ?string
    {
        return $this->isAllowed($this->defaultName()) ? $this->defaultName() : null;
    }

    /**
     * Drop the created channels; the next channel() creates them again (tests, config changes).
     */
    public function forgetChannels(): void
    {
        $this->channels = [];
    }

    /**
     * @return list<string>
     */
    protected function allowedNames(): array
    {
        $allowed = $this->config->get('orchid-2fa.channels.allowed', ['email', 'totp']);

        return array_values(array_unique(array_filter(is_array($allowed) ? $allowed : [], fn ($name): bool => is_string($name) && $name !== '')));
    }

    /**
     * The channel, or null when its driver is missing or invalid.
     */
    protected function tryChannel(string $name): ?TwoFactorChannel
    {
        try {
            return $this->channel($name);
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    protected function resolve(string $name): TwoFactorChannel
    {
        $config = $this->channelConfig($name);
        $driver = $this->driver($name);

        if ($driver !== null && isset($this->extensions[$driver])) {
            $channel = ($this->extensions[$driver])($this->container, $config);
        } elseif ($driver !== null) {
            if (! is_a($driver, DeliveryChannel::class, true) && ! is_a($driver, VerifierChannel::class, true)) {
                throw new InvalidArgumentException(sprintf(
                    '[orchid-2fa.channels.%s.driver] must be a driver registered with TwoFactor::extend() or a class extending %s or %s.',
                    $name,
                    DeliveryChannel::class,
                    VerifierChannel::class,
                ));
            }

            $channel = $this->container->make($driver);
        } elseif (isset($this->extensions[$name])) {
            $channel = ($this->extensions[$name])($this->container, $config);
        } else {
            throw UnknownChannelException::named($name);
        }

        if (! $channel instanceof DeliveryChannel && ! $channel instanceof VerifierChannel) {
            throw new InvalidArgumentException(sprintf(
                'The two-factor channel [%s] must extend %s or %s.',
                $name,
                DeliveryChannel::class,
                VerifierChannel::class,
            ));
        }

        $channel->bootChannel($name, $config);

        return $channel;
    }

    /**
     * `channels.<name>.driver`, or the deprecated `channels.<name>.class` when `driver` is not set.
     */
    protected function driver(string $name): ?string
    {
        $config = $this->channelConfig($name);

        foreach (['driver', 'class'] as $key) {
            if (is_string($config[$key] ?? null) && $config[$key] !== '') {
                return $config[$key];
            }
        }

        return null;
    }

    /**
     * @return array<array-key, mixed>
     */
    protected function channelConfig(string $name): array
    {
        if ($name === 'allowed') {
            return [];
        }

        $config = $this->config->get('orchid-2fa.channels.'.$name, []);

        return is_array($config) ? $config : [];
    }
}
