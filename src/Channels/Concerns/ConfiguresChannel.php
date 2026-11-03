<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Channels\Concerns;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Log\LogManager;
use Illuminate\Support\Str;
use LogicException;
use Psr\Log\LoggerInterface;

/**
 * The name and config of a channel, given by the registry after the channel is created
 * (spec 0.2 §4.2): the base classes have no constructor, so the driver's constructor stays free
 * for dependency injection.
 *
 * @internal
 */
trait ConfiguresChannel
{
    protected ?string $channelName = null;

    /**
     * @var array<array-key, mixed>
     */
    protected array $channelConfig = [];

    /**
     * Called by the registry once, right after the channel is created.
     *
     * @param  array<array-key, mixed>  $config  `orchid-2fa.channels.<name>`
     */
    final public function bootChannel(string $name, array $config): void
    {
        $this->channelName = $name;
        $this->channelConfig = $config;
    }

    public function name(): string
    {
        return $this->channelName
            ?? throw new LogicException(sprintf('The channel [%s] has not been booted by the ChannelRegistry.', static::class));
    }

    /**
     * The channel name as words; drivers override it with a translated name.
     */
    public function label(): string
    {
        return Str::headline($this->name());
    }

    protected function config(): Repository
    {
        return Container::getInstance()->make(Repository::class);
    }

    protected function logger(): LoggerInterface
    {
        $channel = $this->config()->get('orchid-2fa.log.channel');

        return Container::getInstance()->make(LogManager::class)
            ->channel(is_string($channel) && $channel !== '' ? $channel : null);
    }
}
