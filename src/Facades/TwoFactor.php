<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Facades;

use Illuminate\Support\Facades\Facade;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;

/**
 * The channel registry (spec 0.2 §4.3).
 *
 * @method static void extend(string $name, \Closure(\Illuminate\Contracts\Container\Container, array<array-key, mixed>): \Nakipelo\Orchid2FA\Contracts\TwoFactorChannel $factory)
 * @method static \Nakipelo\Orchid2FA\Contracts\TwoFactorChannel channel(string $name)
 * @method static bool has(string $name)
 * @method static list<string> registered()
 * @method static list<string> allowed()
 * @method static list<string> ignored()
 * @method static bool isAllowed(string $name)
 * @method static \Nakipelo\Orchid2FA\Contracts\TwoFactorChannel|null for(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static \Nakipelo\Orchid2FA\Channels\UserMethod methodFor(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static \Nakipelo\Orchid2FA\Contracts\TwoFactorChannel|null defaultChannel()
 * @method static string|null initialName()
 * @method static string defaultName()
 * @method static void forgetChannels()
 *
 * @see ChannelRegistry
 */
class TwoFactor extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return ChannelRegistry::class;
    }
}
