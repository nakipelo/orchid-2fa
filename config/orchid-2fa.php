<?php

declare(strict_types=1);

use Nakipelo\Orchid2FA\Channels\EmailChannel;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;
use Nakipelo\Orchid2FA\Notifications\TwoFactorEmailChangedNotification;
use Nakipelo\Orchid2FA\Notifications\TwoFactorSecurityNotification;

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
    | channel: the default channel for a user without an enrolled method; used
    | only when it is allowed and is a delivery channel. channels.allowed: the
    | methods users may use, in this order; a name without a driver is ignored
    | (see "php artisan about"). channels.<name>.driver: a class extending
    | DeliveryChannel or VerifierChannel, or a name registered with
    | TwoFactor::extend(). The 0.1 key "class" is still read when "driver" is
    | not set (deprecated).
    |
    */

    'channel' => 'email',

    'channels' => [
        'allowed' => ['email', 'totp'],

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
    | Verifier channels and recovery codes: attempts per user
    |--------------------------------------------------------------------------
    |
    | Wrong codes of a verifier channel (TOTP) and wrong recovery codes of a
    | user: user_max_attempts per user_decay seconds and user_max_per_day per
    | fixed 24 hours. code.max_attempts still limits one challenge.
    |
    */

    'verify' => [
        'user_max_attempts' => 10,
        'user_decay' => 600,
        'user_max_per_day' => 30,
    ],

    /*
    |--------------------------------------------------------------------------
    | Pending login lifetime (seconds)
    |--------------------------------------------------------------------------
    */

    'pending_ttl' => 600,

    /*
    |--------------------------------------------------------------------------
    | Enrollment at sign-in (seconds, from the start of the step)
    |--------------------------------------------------------------------------
    */

    'enrollment_ttl' => 900,

    /*
    |--------------------------------------------------------------------------
    | Recovery codes (methods that need them, e.g. TOTP)
    |--------------------------------------------------------------------------
    */

    'recovery_codes' => [
        'count' => 8,
        'warn_at' => 2,
    ],

    /*
    |--------------------------------------------------------------------------
    | Profile: lifetime of a confirmation with the current method (seconds)
    |--------------------------------------------------------------------------
    */

    'profile' => [
        'confirmation_ttl' => 600,
    ],

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
    | security: notices about changes of the method, recovery codes and code
    | guessing, constructed with (string $event, array $context).
    |
    */

    'notification' => [
        'class' => TwoFactorCodeNotification::class,
        'email_changed_class' => TwoFactorEmailChangedNotification::class,
        'security' => [
            'enabled' => true,
        ],
        'security_class' => TwoFactorSecurityNotification::class,
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
    | throttle: per-IP "throttle" middleware parameters for verify, resend,
    | recovery code, e-mail fallback and the enrollment confirmation.
    | profile_throttle: the same for the actions of the two-factor profile
    | screen (POST profile/two-factor/{method}), per signed-in user.
    |
    */

    'routes' => [
        'throttle' => '10,1',
        'profile_throttle' => '30,1',
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
