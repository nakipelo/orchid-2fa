<?php

declare(strict_types=1);

use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Testing\TestResponse;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;
use Nakipelo\Orchid2FA\Tests\TestCase;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\RawMessage;
use Workbench\App\Models\User;

pest()->extend(TestCase::class)->in('Feature');

/*
|--------------------------------------------------------------------------
| Helpers of the two-factor login tests
|--------------------------------------------------------------------------
*/

/**
 * @param  array<string, bool>  $permissions
 */
function tfUser(string $email = 'user@example.com', array $permissions = ['platform.index' => true], string $password = 'password'): User
{
    $user = new User(['name' => 'user', 'email' => $email, 'password' => Hash::make($password)]);
    $user->forceFill(['permissions' => $permissions])->save();

    return $user;
}

/**
 * A user with the "2fa.required" permission (spec §8).
 */
function tfEnforcedUser(string $email = 'enforced@example.com'): User
{
    return tfUser($email, ['platform.index' => true, 'platform.2fa.required' => true]);
}

/**
 * @param  array<string, mixed>  $extra
 */
function tfLogin(string $email = 'enforced@example.com', string $password = 'password', array $extra = []): TestResponse
{
    return test()->from('/admin/login')->post('/admin/login', ['email' => $email, 'password' => $password] + $extra);
}

/**
 * @param  array<string, mixed>  $extra
 */
function tfVerify(string $code, array $extra = []): TestResponse
{
    return test()->from('/admin/two-factor')->post('/admin/two-factor', ['code' => $code] + $extra);
}

/**
 * Codes sent with Notification::fake(), oldest first.
 *
 * @return list<string>
 */
function tfSentCodes(?string $to = null): array
{
    return Notification::sent(
        new AnonymousNotifiable,
        TwoFactorCodeNotification::class,
        fn ($notification, $channels, $notifiable) => $to === null || $notifiable->routes['mail'] === $to,
    )->map(fn (TwoFactorCodeNotification $notification) => $notification->code)->values()->all();
}

function tfLastCode(?string $to = null): string
{
    $codes = tfSentCodes($to);

    expect($codes)->not->toBeEmpty();

    return end($codes);
}

/**
 * A code that differs from the given one.
 */
function tfWrongCode(string $code): string
{
    return $code === '000000' ? '111111' : '000000';
}

/**
 * The code from a sent e-mail (text part, or the HTML part without tags).
 */
function tfCodeFromMail(RawMessage $message): string
{
    expect($message)->toBeInstanceOf(Email::class);

    /** @var Email $message */
    $body = (string) ($message->getTextBody() ?? strip_tags((string) $message->getHtmlBody()));

    expect(preg_match('/Your verification code: (\d{6})/', $body, $match))->toBe(1);

    return $match[1];
}
