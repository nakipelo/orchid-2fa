# nakipelo/orchid-2fa

Two-factor authentication for the password login of the [Orchid](https://orchid.software) admin
panel: after a correct password the user enters a one-time code sent by e-mail.

- **Code first, login second.** The password is checked with `SessionGuard::validate()`, so the
  user is not signed in until the code is correct. While the code step is pending the session stays
  a guest session: the admin panel is not reachable and no remember-me cookie is issued.
- **E-mail code only.** No authenticator app, no QR codes, no backup codes: the second factor is
  the mailbox the account already has.
- Required for users with the `platform.2fa.required` permission (or for everyone), optional for
  the rest: users enable it on their profile screen.
- Trusted devices ("Trust this device for 30 days"), a profile screen, an admin reset button and an
  artisan command, events, English and Russian translations.

## Requirements

- PHP 8.2+ (Laravel 13 requires PHP 8.3+)
- Laravel 11.35+ / 12 / 13
- `orchid/platform` ^14.53
- The Orchid guard (`platform.guard`) must be a session guard; otherwise the package throws an
  exception on boot.

### Laravel versions with security advisories

All Laravel 11 releases and the early Laravel 12 and 13 releases are flagged with security
advisories on Packagist, and Composer 2.9+ refuses to install them by default (when resolving
dependencies: `composer update` / `require`). This package still supports these versions, but
whether to bypass the blocking is your decision. The recommended fix is to update Laravel to a
release without advisories.

If you do need to bypass it:

- Composer 2.10+: `composer config policy.advisories.block false`, or `COMPOSER_NO_BLOCKING=1`
  (or `--no-blocking`) for a single command;
- Composer 2.9: `composer config audit.block-insecure false`, or `COMPOSER_NO_SECURITY_BLOCKING=1`
  (or `--no-security-blocking`). Composer 2.10 still accepts these but marks them as deprecated.

## Installation

The steps assume an application with Orchid installed (`php artisan orchid:install`), so the
Orchid stubs live in `app/Orchid` and `App\Models\User` extends `Orchid\Platform\Models\User`.

**1. Require the package and run the migration** (table `two_factor_authentications`; nothing is
added to `users`):

```bash
composer require nakipelo/orchid-2fa
php artisan migrate
```

The service provider is auto-discovered. The package replaces Orchid's `POST login` route with its
own controller; `GET login` and everything else stay Orchid's.

**2. Publish what you want to change** (all optional):

```bash
php artisan vendor:publish --tag=orchid-2fa-config        # config/orchid-2fa.php
php artisan vendor:publish --tag=orchid-2fa-translations  # lang/vendor/orchid-2fa/{en,ru}/messages.php
php artisan vendor:publish --tag=orchid-2fa-views         # resources/views/vendor/orchid-2fa/challenge.blade.php
php artisan vendor:publish --tag=orchid-2fa-migrations    # database/migrations
```

The migration is loaded from the package, so publish it only to change it (for example, a
non-`bigint` `users.id`), and do it **before** `php artisan migrate`: the copy keeps the file name and
replaces the package migration.

**3. Add the `HasTwoFactor` trait to the user model.** Without it the login works, but a password
change does not sign the user out of trusted devices and an e-mail change sends no notice (in
`local`/`testing` the package logs a warning about the missing trait).

```php
// app/Models/User.php
use Nakipelo\Orchid2FA\Concerns\HasTwoFactor;
use Orchid\Platform\Models\User as Authenticatable;

class User extends Authenticatable
{
    use HasTwoFactor;

    // ...
}
```

**4. Link the two-factor screen from the profile** — one line in `layout()` of
`app/Orchid/Screens/User/UserProfileScreen.php`. The block shows the status and a "Manage" button
that opens `admin/profile/two-factor` (Orchid 14 has no profile menu to hook into).

```php
use Nakipelo\Orchid2FA\Layouts\TwoFactorProfileLinkLayout;

public function layout(): iterable
{
    return [
        // ... Orchid's "Profile Information" and "Update Password" blocks

        TwoFactorProfileLinkLayout::class,
    ];
}
```

**5. Add the reset button to the user edit screen** — the trait and the layout in
`app/Orchid/Screens/User/UserEditScreen.php`. The block shows the user's two-factor status and a
"Reset 2FA" button; it is visible only to holders of the `platform.systems.users.2fa-reset`
permission (checked on the server as well) and is hidden on the "create user" screen.

```php
use Nakipelo\Orchid2FA\Concerns\ResetsTwoFactor;
use Nakipelo\Orchid2FA\Layouts\TwoFactorResetLayout;

class UserEditScreen extends Screen
{
    use ResetsTwoFactor;

    public function layout(): iterable
    {
        return [
            // ... Orchid's blocks

            TwoFactorResetLayout::class,
        ];
    }
}
```

**6. After installing, rotate the remember tokens.** "Remember me" cookies issued before the package
was installed would let their owners in without a code:

```bash
php artisan orchid-2fa:rotate-remember-tokens
```

It clears `remember_token` of all users of the Orchid guard's model (with confirmation; `--force`
skips it). Active sessions are not ended.

**7. Make the existing administrators enforced.** Permissions are stored on users and roles, so
administrators created before the package was installed do not hold `platform.2fa.required` (nor
`platform.systems.users.2fa-reset`). Grant them in the role or user screen, or re-run
`php artisan orchid:admin --id=<user id>`, which grants all registered permissions again. Make sure
their e-mail addresses work first (see below).

## Who has to pass the second factor

- Everyone, with `enforce_all = true` in the config.
- Users holding the **`platform.2fa.required`** permission (directly or through a role). The
  permission is registered in the "Two-factor authentication" group of Orchid's permission list.
- Users who enabled it on their profile screen. Enabling and disabling are confirmed with a code to
  the current address; an enforced user cannot disable it.

Everyone else signs in exactly as with plain Orchid.

**`orchid:admin` makes the administrator enforced.** It grants all permissions, including
`platform.2fa.required`. This is intended: the administrator then needs a working e-mail address
at the first sign-in. If the address does not work, access can be restored only from the
console: fix the address (another administrator in the user edit screen, or `php artisan tinker`),
then run `php artisan orchid-2fa:reset admin@example.com` — the next sign-in sends a code to the
current address.

## Sign-in flow

1. `POST admin/login` checks the e-mail and password as Orchid does (the same validation, the same
   error message, `Attempting`/`Failed` events, password rehash).
2. If the user needs 2FA and the browser is not a trusted device, the session is regenerated and a
   code is sent; the user is redirected to `admin/two-factor`. An active code (not expired, not used
   up, bound to the current address) is reused instead of sending a new one.
3. On the code screen: "Sign in", "Send the code again" (with a countdown), "Sign in as a different
   user" and, if trusted devices are enabled, "Trust this device for N days".
4. A correct code signs the user in (`remember` as chosen on the login form, Orchid's lock cookie,
   `redirect()->intended()`).

Requests that want JSON get `200 {"two_factor": true, "redirect": "…"}` from the login, `204` on a
successful code, `200 {"resend_available_in": N}` on resend and `422` with an error on `code`
otherwise.

Limits: 6 digits, valid 10 minutes, 5 wrong entries per code (then the code is invalidated), one send
per 60 seconds and 5 sends per hour per user (login, resend and profile sends together), plus a per-IP
`throttle` on the verify and resend routes. Exceeding the send limit does not lock the account.

If the code cannot be sent (transport error, no address), the login does not happen (fail-closed);
there is no "skip" button.

Not asked for a code: sign-in by Laravel's remember cookie (it is issued only after the second
factor) and Orchid impersonation (`loginAs`).

## Routes

Registered with Orchid's domain, prefix (`admin` by default) and middleware groups:

| Method | URI | Name |
|---|---|---|
| POST | `login` | `platform.login.auth` (replaces Orchid's) |
| GET | `two-factor` | `platform.two-factor.challenge` |
| POST | `two-factor` | `platform.two-factor.verify` |
| POST | `two-factor/resend` | `platform.two-factor.resend` |
| POST | `two-factor/cancel` | `platform.two-factor.cancel` |
| GET/POST | `profile/two-factor/{method?}` | `platform.profile.two-factor` (screen) |

The replacement works with `php artisan route:cache` too.

## Configuration

`config/orchid-2fa.php` (publish with `--tag=orchid-2fa-config`):

| Key | Default | Description |
|---|---|---|
| `enforce_all` | `false` | Require 2FA for every user of the admin panel |
| `channel` | `'email'` | Channel used to send codes (only `email` in 0.1) |
| `channels.email.class` | `EmailChannel::class` | Channel implementation |
| `channels.email.attribute` | `'email'` | User attribute with the address |
| `code.length` | `6` | Digits in a code |
| `code.ttl` | `600` | Code lifetime, seconds |
| `code.max_attempts` | `5` | Wrong entries per code before it is invalidated |
| `resend.cooldown` | `60` | Seconds between sends |
| `resend.max_per_hour` | `5` | Sends per user per hour (login, resend and profile together) |
| `pending_ttl` | `600` | Seconds between a correct password and the code before the user has to sign in again |
| `trusted_devices.enabled` | `true` | Show the "Trust this device" checkbox and accept trusted device cookies |
| `trusted_devices.lifetime_days` | `30` | Lifetime of a trusted device cookie, days |
| `trusted_devices.cookie` | `'orchid_2fa_trusted'` | Cookie name prefix |
| `notification.class` | `TwoFactorCodeNotification::class` | Notification with the code |
| `notification.email_changed_class` | `TwoFactorEmailChangedNotification::class` | Notification about an e-mail change |
| `notification.queue` | `false` | Send notifications through the queue |
| `notification.connection` | `null` | Queue connection (`null` — default) |
| `notification.queue_name` | `null` | Queue name (`null` — default) |
| `cache.store` | `null` | Cache store for codes (`null` — default store) |
| `routes.throttle` | `'10,1'` | Per-IP throttle for verify and resend: `max,minutes` |
| `menu.enabled` | `false` | Add a "Two-factor authentication" item to Orchid's main menu |
| `log.enabled` | `false` | Write the package events to the log |
| `log.channel` | `null` | Log channel (`null` — default) |

Codes are stored in the cache as an HMAC, never in plain text. Use a persistent store shared by all
application servers (not `array`); attempt and send counters use Laravel's rate limiter (its cache
store is `cache.limiter`).

Permission names are not configurable: `platform.2fa.required` and
`platform.systems.users.2fa-reset`.

## Trusted devices

When the user ticks "Trust this device for N days", a cookie is issued after the correct code; the
next sign-in on this browser asks for the password only. The cookie is encrypted with the app key,
bound to the user and the Orchid guard, `HttpOnly`, `SameSite=Lax`, limited to the Orchid path,
`Secure` per `session.secure` (or the request scheme when it is not set). Its name is per user and
guard, so several accounts in one browser do not interfere.

All trusted devices of a user stop working when:

- the user clicks "Sign out of all trusted devices" on the two-factor profile screen;
- the password changes through the model (profile, user edit screen, password reset);
- the user disables 2FA, or an administrator resets it;
- the e-mail address changes — until the new address is confirmed by a code at the next sign-in.

With `trusted_devices.enabled = false` the checkbox is hidden and existing cookies are ignored (not
deleted: they work again once the option is turned back on).

## Events

`Nakipelo\Orchid2FA\Events\*`; every event has `user` (`Authenticatable`) and `guard` (string).

| Event | Extra properties |
|---|---|
| `TwoFactorChallengeSent` | `channel`, `maskedDestination` (`a***@example.com`), `context`: `login`, `enable`, `disable` |
| `TwoFactorPassed` | `via`: `code`, `trusted_device`; `trustedDeviceIssued` (bool) |
| `TwoFactorFailed` | `reason`: `invalid_code`, `expired`, `delivery_failed` |
| `TwoFactorLockedOut` | `reason`: `attempts_exceeded`, `send_limit`; `availableIn` (seconds) |

The values are also class constants (`TwoFactorFailed::INVALID_CODE` and so on). `TwoFactorPassed` is
a sign-in event: the profile screen does not fire it. Enabling, disabling and resetting fire no
events in 0.1. The final sign-in fires Laravel's usual `Illuminate\Auth\Events\Login`.

With `log.enabled = true` the package writes all four events to `log.channel` (user id, guard and
the properties above; no codes).

## Notifications

| Config key | Default class | Constructor |
|---|---|---|
| `notification.class` | `Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification` | `(string $code, CarbonInterface $expiresAt)` |
| `notification.email_changed_class` | `Nakipelo\Orchid2FA\Notifications\TwoFactorEmailChangedNotification` | `(string $maskedNewAddress)` |

To change the e-mails, extend the class (or write your own `Illuminate\Notifications\Notification`
with the same constructor and the `mail` channel) and set it in the config:

```php
use Illuminate\Notifications\Messages\MailMessage;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;

class SignInCodeNotification extends TwoFactorCodeNotification
{
    public function toMail(mixed $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('Your code for '.config('app.name'))
            ->line('Code: '.$this->code)
            ->line('Valid until '.$this->expiresAt->format('H:i'));
    }
}
```

Notifications are routed to the address in `channels.email.attribute` (the model does not need
`Notifiable`). By default they are sent synchronously, even if the class implements `ShouldQueue`,
so a transport error is shown to the user and the login does not happen. With
`notification.queue = true` both notifications are queued (`notification.connection`,
`notification.queue_name`); see the limitations below.

The e-mail change notice goes to the **old** address when the address of a user who needs 2FA
changes; it contains the new address masked only.

## Translations

All texts of the code screen, the profile screen, the layouts, the toasts, the permissions and the
e-mails are in `orchid-2fa::messages`, shipped in English and Russian. The locale is the application
locale (`APP_LOCALE`). To change texts or add a locale:

```bash
php artisan vendor:publish --tag=orchid-2fa-translations
```

and edit or copy `lang/vendor/orchid-2fa/{locale}/messages.php`. Strings that belong to Orchid
(the "Profile" breadcrumb, the wrong password message) use Orchid's own JSON translations. Artisan
command output is English only.

The code screen is the view `orchid-2fa::challenge` (it extends Orchid's `platform::auth` layout);
publish it with `--tag=orchid-2fa-views`.

## Commands

| Command | Description |
|---|---|
| `orchid-2fa:rotate-remember-tokens [--force]` | Clear `remember_token` of all users of the Orchid guard's model. Run once after installing. |
| `orchid-2fa:reset {email} [--force]` | Reset 2FA of a user: disable the voluntary 2FA, sign out of all trusted devices, remove the active code, the attempt counter, the cooldown and the hourly limit. An enforced user gets a code to the current address at the next sign-in. Does not check Orchid permissions. |

Both ask for confirmation unless `--force` is given, and exit with code 1 when declined (or when the
e-mail is unknown).

## Limitations and recommendations

- **Queue mode.** With `notification.queue = true` a delivery error happens in the worker: the user
  sees the code screen, but no code arrives (they can resend within the limits). A queue worker must
  be running. Keep the default synchronous sending unless your mail transport is slow.
- **Mass updates.** The `HasTwoFactor` listeners run on Eloquent `save()`. A query builder
  `update()` of `password` or `email` fires no model events, so trusted devices are not invalidated
  and the e-mail change notice is not sent. After such updates call
  `TwoFactorAuthentication::bumpTrustedDevicesVersionFor($userId)` (password) or
  `app(TwoFactorManager::class)->addressChanged($user, $oldAddress)` (address), or update through
  the model.
- **Sign-in into the same guard bypassing Orchid is not protected.** The package protects Orchid's
  password login only. Breeze, Fortify, `orchid/fortify`, your own `/login` routes or API tokens that
  sign users into the Orchid guard skip the second factor. Protect them yourself or keep the Orchid
  guard separate.
- **`platform.auth = false`.** Orchid then registers no login routes and the package does not replace
  `POST login`: your own login must take care of the second factor. In `local` and `testing` the
  package logs a warning once per boot; in other environments it is silent. The code step and
  profile routes are still registered.
- **E-mail change without a password.** Orchid's `UserProfileScreen` changes the e-mail address
  without asking for the password. Someone with a stolen session can redirect the codes to their own
  address; the owner only gets the notice at the old address. Ask for the current password in the
  stub (`app/Orchid/Screens/User/UserProfileScreen.php`):

  ```php
  use Orchid\Screen\Fields\Password;

  // layout(): add a password field to the "Profile Information" block
  Layout::block([
      UserEditLayout::class,
      Layout::rows([
          Password::make('current_password')
              ->title(__('Current password'))
              ->help(__('Required to change the email address.')),
      ]),
  ])
      ->title(__('Profile Information'))
      // ... the rest of the block as in the stub

  // save(): require it when the address changes
  $request->validate([
      'user.name' => 'required|string',
      'user.email' => [
          'required',
          Rule::unique(User::class, 'email')->ignore($request->user()),
      ],
      'current_password' => [
          Rule::requiredIf($request->input('user.email') !== $request->user()->email),
          'nullable',
          'current_password:'.config('platform.guard', 'web'),
      ],
  ]);
  ```

- **Recovery.** There are no backup codes and no self-service recovery: a user who lost the mailbox
  is restored by an administrator (fix the address, then "Reset 2FA" or `orchid-2fa:reset`).
- Only the e-mail channel in 0.1; TOTP, backup codes and other channels are not implemented.

## Security

- No sign-in before the code: the password is checked with `validate()`, the session stays a guest
  session and is regenerated when the code step starts and at the final sign-in.
- The user of the code step comes from the server session only; request parameters are ignored.
- Codes: `random_int`, stored as an HMAC (app key) bound to the challenge and the address,
  compared with `hash_equals`; the attempt is counted before the comparison, a used code is consumed
  atomically, a new code invalidates the old one. 5 attempts × 5 codes per hour against 10⁶ values,
  plus a per-IP throttle.
- Wrong passwords get exactly Orchid's response; send limits apply only after a correct password.
- Remember-me cookies are issued only after the second factor; tokens are rotated when 2FA is enabled
  and by `orchid-2fa:rotate-remember-tokens`.
- Disabling 2FA requires a code; enforced users cannot disable it (checked on the server).
- Fail-closed when the code cannot be delivered.

Please report vulnerabilities privately (GitHub: Security → Report a vulnerability), not in public
issues.

## Development

```bash
composer install
composer serve      # workbench: Orchid at http://127.0.0.1:8000/admin
composer check      # pint --test, adapter check, larastan, pest
```

Workbench test administrator (seeded by `composer serve` / `composer build`; it holds all
permissions, so it is enforced; codes go to the log mailer, `MAIL_MAILER=log`):

| Login | Password |
|---|---|
| `admin@example.com` | `password` |

Individual checks: `composer test`, `composer analyse` (Larastan level 8), `composer lint` (Pint),
`composer check-adapter` (`platform.`, `platform::` and `Orchid\` appear in `src/` only in
`src/Support/Orchid.php`, and `Orchid\` also in the UI layer `src/Screens`, `src/Layouts`).

## License

MIT. See [LICENSE](LICENSE).
