<?php

declare(strict_types=1);

use Nakipelo\Orchid2FA\Channels\EmailChannel;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;
use Nakipelo\Orchid2FA\Notifications\TwoFactorEmailChangedNotification;

return [

    /*
    |--------------------------------------------------------------------------
    | Enforcement
    |--------------------------------------------------------------------------
    |
    | When true, two-factor authentication is required for every user of the
    | admin panel. Otherwise it is required for users holding the
    | "platform.2fa.required" permission and for users who enabled it in their
    | profile.
    |
    */

    'enforce_all' => false,

    /*
    |--------------------------------------------------------------------------
    | Channels
    |--------------------------------------------------------------------------
    |
    | channel: the default channel, used for a user without a method of their
    | own. channels.<name>.driver: a class extending DeliveryChannel or
    | VerifierChannel, or a name registered with TwoFactor::extend(). The 0.1
    | key "class" is still read when "driver" is not set (deprecated).
    |
    */

    'channel' => 'email',

    'channels' => [
        'email' => [
            'driver' => EmailChannel::class,
            'attribute' => 'email',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | One-time code
    |--------------------------------------------------------------------------
    |
    | length: number of digits; ttl: lifetime in seconds;
    | max_attempts: wrong entries per code before it is invalidated.
    |
    */

    'code' => [
        'length' => 6,
        'ttl' => 600,
        'max_attempts' => 5,
    ],

    /*
    |--------------------------------------------------------------------------
    | Sending limits
    |--------------------------------------------------------------------------
    |
    | cooldown: seconds between sends; max_per_hour: sends per user per hour
    | (login, resend and profile sends all count).
    |
    */

    'resend' => [
        'cooldown' => 60,
        'max_per_hour' => 5,
    ],

    /*
    |--------------------------------------------------------------------------
    | Pending login lifetime (seconds)
    |--------------------------------------------------------------------------
    */

    'pending_ttl' => 600,

    /*
    |--------------------------------------------------------------------------
    | Trusted devices
    |--------------------------------------------------------------------------
    */

    'trusted_devices' => [
        'enabled' => true,
        'lifetime_days' => 30,
        'cookie' => 'orchid_2fa_trusted',
    ],

    /*
    |--------------------------------------------------------------------------
    | Notifications
    |--------------------------------------------------------------------------
    |
    | class: notification with the code, constructed with
    | (string $code, CarbonInterface $expiresAt).
    | queue: send through the queue (connection / queue_name) instead of
    | synchronously; delivery errors then are not reported to the user.
    |
    */

    'notification' => [
        'class' => TwoFactorCodeNotification::class,
        'email_changed_class' => TwoFactorEmailChangedNotification::class,
        'queue' => false,
        'connection' => null,
        'queue_name' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache store for codes (null — the default store)
    |--------------------------------------------------------------------------
    */

    'cache' => [
        'store' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    |
    | throttle: per-IP "throttle" middleware parameters for verify and resend.
    |
    */

    'routes' => [
        'throttle' => '10,1',
    ],

    /*
    |--------------------------------------------------------------------------
    | Main menu item
    |--------------------------------------------------------------------------
    */

    'menu' => [
        'enabled' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging of two-factor events
    |--------------------------------------------------------------------------
    */

    'log' => [
        'enabled' => false,
        'channel' => null,
    ],

];
