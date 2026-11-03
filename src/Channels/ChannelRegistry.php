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
     * Stage 1: the intersection only; the warnings and the check of an empty list come in stage 2.
     *
     * @return list<string>
     */
    public function allowed(): array
    {
        $allowed = $this->config->get('orchid-2fa.channels.allowed', ['email', 'totp']);

        return array_values(array_filter(
            array_unique(array_filter(is_array($allowed) ? $allowed : [], 'is_string')),
            fn (string $name): bool => $this->has($name),
        ));
    }

    /**
     * The channel of the user (spec 0.2 §4.5): the channel of the user's record when it is
     * registered, otherwise the default channel; null when that is not registered either.
     *
     * Stage 1: `channels.allowed`, availability and the fail-closed branch for an unregistered
     * driver come in stage 2.
     */
    public function for(Authenticatable $user): ?TwoFactorChannel
    {
        $name = TwoFactorAuthentication::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->value('channel');

        if (is_string($name) && $name !== '' && $this->has($name)) {
            return $this->channel($name);
        }

        return $this->has($this->defaultName()) ? $this->channel($this->defaultName()) : null;
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
     * Drop the created channels; the next channel() creates them again (tests, config changes).
     */
    public function forgetChannels(): void
    {
        $this->channels = [];
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
