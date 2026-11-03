<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Fixtures;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Nakipelo\Orchid2FA\Channels\DeliveryChannel;
use Throwable;

/**
 * A delivery channel of the tests (spec 0.2 §10.1): "sends" the code to a phone-like destination
 * derived from the user id and records it, so a test can tell it from the e-mail channel.
 * Register it with `TwoFactor::extend('fake', fn () => new FakeDeliveryChannel)`.
 */
class FakeDeliveryChannel extends DeliveryChannel
{
    /**
     * @var list<array{user_id: int|string, destination: string, code: string}>
     */
    public static array $sent = [];

    /**
     * Thrown by send() when set.
     */
    public static ?Throwable $failWith = null;

    public static function reset(): void
    {
        self::$sent = [];
        self::$failWith = null;
    }

    public static function lastCode(): string
    {
        $last = end(self::$sent);

        if ($last === false) {
            throw new \RuntimeException('No code has been sent through the fake channel.');
        }

        return $last['code'];
    }

    public function label(): string
    {
        return 'Fake phone';
    }

    public function destination(Authenticatable $user): string
    {
        return '+1555000'.$user->getAuthIdentifier();
    }

    public function maskedDestination(Authenticatable $user): string
    {
        return '+1***'.substr($this->destination($user), -2);
    }

    public function send(Authenticatable $user, string $code, CarbonInterface $expiresAt): void
    {
        if (self::$failWith !== null) {
            throw self::$failWith;
        }

        self::$sent[] = ['user_id' => $user->getAuthIdentifier(), 'destination' => $this->destination($user), 'code' => $code];
    }

    /**
     * The config the registry booted the channel with.
     *
     * @return array<array-key, mixed>
     */
    public function bootedConfig(): array
    {
        return $this->channelConfig;
    }
}
