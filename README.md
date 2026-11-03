# nakipelo/orchid-2fa

Two-factor authentication for the password login of the [Orchid](https://orchid.software) admin
panel: after a correct password the user confirms the sign-in with a one-time code — sent by e-mail
out of the box, or from another method provided by a channel driver, such as an authenticator app
([nakipelo/orchid-2fa-totp](https://github.com/nakipelo/orchid-2fa-totp)).

- **Code first, login second.** The password is checked with `SessionGuard::validate()`, so the
  user is not signed in until the code is correct. While the code step is pending the session stays
  a guest session: the admin panel is not reachable and no remember-me cookie is issued.
- **Channel drivers.** E-mail codes work with zero configuration. Other methods are drivers in their
  own packages (TOTP: `nakipelo/orchid-2fa-totp`); `channels.allowed` decides which methods users may
  use. One active method per user.
- **Recovery codes** for methods that need them (an authenticator app on a lost phone).
- Required for users with the `platform.2fa.required` permission (or for everyone), optional for
  the rest: users enable it on their profile screen. A user who must use 2FA but has no method sets
  one up right after the password.
- Changing the method, setting it up again and disabling it are confirmed with the current password
  and a code.
- Trusted devices ("Trust this device for 30 days"), a profile screen, an admin reset button and
  artisan commands, attempt limits per user with an alert about code guessing, events and security
  notices, English and Russian translations.

## Requirements

- PHP 8.2+ (Laravel 13 requires PHP 8.3+)
- Laravel 11.35+ / 12 / 13
- `orchid/platform` ^14.53
- The Orchid guard (`platform.guard`) must be a session guard; otherwise the package throws an
  exception on boot.
- **A server-side session driver** (`file`, `database`, `redis`, …). The pending sign-in, the secret of
  an unfinished enrollment and the recovery codes waiting to be shown live in the session; the `cookie`
  driver would send them to the browser (encrypted), and a session over the 4 KB cookie limit is
  silently lost. In `local`/`testing` the package logs a warning when `session.driver` is `cookie`.

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
Upgrading from 0.1? See [Upgrade 0.1 → 0.2](#upgrade-01--02).

**1. Require the package and run the migrations** (tables `two_factor_authentications` and
`two_factor_recovery_codes`; nothing is added to `users`):

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
php artisan vendor:publish --tag=orchid-2fa-views         # resources/views/vendor/orchid-2fa/*
php artisan vendor:publish --tag=orchid-2fa-migrations    # database/migrations
```

The migrations are loaded from the package, so publish them only to change them (for example, a
non-`bigint` `users.id` or a user table other than `users`), and do it **before**
`php artisan migrate`: the copies keep the file names and replace the package migrations.

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
`app/Orchid/Screens/User/UserProfileScreen.php`. The block shows the status and the method and a
"Manage" button that opens `admin/profile/two-factor` (Orchid 14 has no profile menu to hook into).

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
`app/Orchid/Screens/User/UserEditScreen.php`. The block shows the user's two-factor status and
method and a "Reset 2FA" button; it is visible only to holders of the
`platform.systems.users.2fa-reset` permission (checked on the server as well) and is hidden on the
"create user" screen.

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

**8. Optionally add an authenticator app:** `composer require nakipelo/orchid-2fa-totp` and
`php artisan migrate`. See [Channels](#channels).

## Who has to pass the second factor

- Everyone, with `enforce_all = true` in the config.
- Users holding the **`platform.2fa.required`** permission (directly or through a role). The
  permission is registered in the "Two-factor authentication" group of Orchid's permission list.
- Users who enabled it on their profile screen. An enforced user cannot disable it.

Everyone else signs in exactly as with plain Orchid.

**`orchid:admin` makes the administrator enforced.** It grants all permissions, including
`platform.2fa.required`. This is intended: the administrator then needs a working e-mail address
(or another allowed method) at the first sign-in. If the address does not work, access can be
restored only from the console: fix the address (another administrator in the user edit screen, or
`php artisan tinker`), then run `php artisan orchid-2fa:reset admin@example.com` — the next sign-in
sends a code to the current address.

## Channels

A **channel** (driver) is a way to get the second factor. There are two kinds:

- **delivery** channels — the server generates a code and delivers it (`email`; SMS or a messenger
  would be others);
- **verifier** channels — the user's device generates the code and the server only checks it (TOTP;
  WebAuthn would be another).

The package ships the `email` channel. Other channels come from driver packages, which register
themselves with `TwoFactor::extend()`; the first one is
[nakipelo/orchid-2fa-totp](https://github.com/nakipelo/orchid-2fa-totp) (Google Authenticator and
compatible apps).

**`channels.allowed`** lists the methods users may use, in the order they are offered
(default `['email', 'totp']`). A name without a registered driver is ignored — `totp` is in the
default list, so installing the TOTP package is enough to offer it. Ignored names are logged as a
warning in `local`/`testing` and shown by `php artisan about` (section "Orchid 2FA": default,
registered, allowed and ignored channels). If no allowed channel is left, the package throws on boot
in `local`/`testing`; elsewhere it logs a `critical` entry and the sign-in of users who need 2FA fails
closed (users without 2FA still sign in).

**The method of a user** is stored in `two_factor_authentications.channel`:

1. The recorded channel is registered, allowed and set up for the user — it is used.
2. It is set up but no longer allowed (an administrator removed it from `channels.allowed`) — it is
   still accepted once as a proof, and right after the correct code the user has to set up an allowed
   method. This is how all users are moved from one method to another
   ([see below](#moving-all-users-to-another-method)).
3. Its driver is not registered (the package was removed) — the sign-in fails closed ("Your sign-in
   method is not available. Please contact your administrator.") until an administrator resets the
   user, or all users of the channel at once with `orchid-2fa:reset --channel=<name>`. There is no
   silent downgrade to e-mail.
4. No method (a new user, after disabling or a reset): the default channel (`channel`, `email`) is
   used when it is allowed and is a delivery channel without a setup step — the behaviour of 0.1.
   Otherwise an enforced user sets up a method right after the password.

A new record — and a record after disabling or a reset — gets the default channel when it is allowed
and registered, otherwise none.

### Only an authenticator app

```php
// config/orchid-2fa.php
'channels' => [
    'allowed' => ['totp'],
    // ...
],
```

A user who needs 2FA and has no app sets it up at the next sign-in, right after the password.

### Moving all users to another method

With the TOTP package installed and migrated, `'allowed' => ['totp']` moves everyone at the next
sign-in:

- users with a confirmed e-mail method (`two_factor_authentications.confirmed_at` is not null) enter
  a code sent by e-mail **as a proof**, then set up the app — signing in without setting it up is not
  possible;
- users whose e-mail is not confirmed (the address was changed, or they signed in without 2FA before
  it became required) set up the app protected by the password only. Check how many there are before
  switching: `select count(*) from two_factor_authentications where channel = 'email' and confirmed_at is null`;
- voluntary users move the same way; users who disabled 2FA are not affected.

Rollback: put `email` back into `allowed` — an app already set up stays the user's method.

## Sign-in flow

1. `POST admin/login` checks the e-mail and password as Orchid does (the same validation, the same
   error message, `Attempting`/`Failed` events, password rehash).
2. If the user needs 2FA and the browser is not a trusted device, the session is regenerated and the
   code step starts; the user is redirected to `admin/two-factor`. For e-mail a code is sent; an
   active code (not expired, not used up, bound to the current address) is reused instead of sending
   a new one. For an authenticator app nothing is sent.
3. On the code screen: the prompt of the method ("We have sent a code to e\*\*\*@example.com." / "Enter
   the code from your authenticator app."), "Sign in", "Send the code again" with a countdown (delivery
   channels only), "Use a recovery code" (methods with recovery codes), "Send a code by e-mail instead"
   (when the driver offers it), "Sign in as a different user" and, if trusted devices are enabled,
   "Trust this device for N days".
4. A correct code signs the user in (`remember` as chosen on the login form, Orchid's lock cookie,
   `redirect()->intended()`).

Requests that want JSON get `200 {"two_factor": true, "redirect": "…"}` from the login, `204` on a
successful code, `200 {"resend_available_in": N}` on resend and `422` with an error on `code`
otherwise. When the login could not send the code (send limit, delivery error), its response is
still `200` — the password is correct and the code step has started — with two more fields:
`{"two_factor": true, "redirect": "…", "error": "…", "resend_available_in": N}`. When the sign-in
continues with setting up a method (below), the login or the code answers
`200 {"two_factor": true, "enroll": true, "redirect": "…"}`: the setup and the recovery codes are
HTML only, and their routes answer JSON requests with `406 {"message": "…", "redirect": "…"}` — open
`redirect` in a browser.

If the password changes while the code step is pending (for example, an administrator changes a
compromised password), the code step ends: the user is sent back to the login form ("Your password
has been changed. Please sign in again.").

If the code cannot be sent (transport error, no address), the login does not happen (fail-closed);
there is no "skip" button.

Not asked for a code: sign-in by Laravel's remember cookie (it is issued only after the second
factor) and Orchid impersonation (`loginAs`).

### Setting up a method at sign-in

When an enforced user has no usable method (case 4 above without a default channel, for example
`allowed = ['totp']`), the password step leads to `admin/two-factor/enroll`: choose a method (if
several are allowed), set it up (an authenticator app: scan the QR code, enter the first code) and,
for a method with recovery codes, save them ("I have saved the codes") — then the user is signed in.
The step lives `enrollment_ttl` (15 minutes) from its start; five wrong codes end it and the user signs
in again.

- **No confirmed method** (a new user, after a reset): the setup is protected by the password only —
  the accepted risk of a first enrollment (as in Laravel Fortify). It offers no "Trust this device"
  checkbox. If the user gets a method meanwhile (set up in another browser), the step ends and the
  sign-in starts again — with that method's code.
- **A confirmed method that is no longer allowed:** first a code of that method (or a recovery code),
  then the setup. Someone who knows only the password cannot bind their own method. The checkbox is
  offered after a code (not after a recovery code); the record is confirmed only when the setup is
  finished.

### Recovery codes

For methods that need them (an authenticator app; not e-mail) the user gets 8 one-time codes
`xxxx-xxxx` whenever the method is set up, changed to or set up again, and on "New recovery codes" in
the profile; the old set stops working. They are shown once ("I have saved the codes") and stored only
as hashes (`Hash::make()`, so they survive an `APP_KEY` rotation). Case, spaces and the dash are
ignored on input.

A recovery code is accepted at sign-in ("Use a recovery code"), for changing the method, setting it up
again and disabling 2FA in the profile — not for issuing new recovery codes. A sign-in with a recovery
code never trusts the device (the checkbox is not shown and the cookie is not issued, even if
requested), sends a security notice and shows a banner in the profile: "You have signed in with a
recovery code… If you lost your device, set up your method again." The profile warns when 2 or fewer
codes are left. Switching to a method without recovery codes, disabling and a reset delete them.

### Limits

- **E-mail codes** (as in 0.1): 6 digits, valid 10 minutes, 5 wrong entries per code (then the code is
  invalidated), one send per 60 seconds and 5 sends per hour per user (login, resend and profile sends
  together). Exceeding the send limit does not lock the account.
- **Codes of a verifier channel and recovery codes:** 5 wrong entries per pending sign-in (then the
  user signs in again with the password), and per user **10 wrong entries per 10 minutes** and **30 per
  24 hours** — across sign-ins, so a new password step does not reset them. Only wrong codes count. When
  a per-user limit is reached, the code step is paused ("Please try again in N min / N h") and the owner
  gets an e-mail **"Someone is trying to sign in to your account"** (at most once per 10 minutes).
- A per-IP `throttle` (`routes.throttle`, 10 per minute) on verify, resend, recovery code, e-mail
  fallback and the setup confirmation.

The attempts are counted before the code is checked, for every channel: a driver is not called once a
limit is used up.

## Profile

`admin/profile/two-factor` shows the status ("Required for your account", "Enabled", "Disabled",
"Required, no method set up yet"), the method and, for e-mail, the address the codes go to. Depending
on the status and the permissions:

| Action | Confirmation |
|---|---|
| **Enable** (voluntary) — choose a method, set it up | Current password and the code of the new method (e-mail: a code to the address). A user whose 2FA is disabled but who still has a set-up method with data of its driver (e.g. an authenticator app left after "2FA required" was taken away) can enable only that method again — as a new setup; other methods are reached with "Change to …" afterwards |
| **Change to …** another allowed method | Current password **and** a code of the current method (or a recovery code), then the setup of the new one |
| **Set up again** (a method with a setup step, e.g. a new phone) | Current password and a code of the current method (or a recovery code), then the new setup; the old one works until the new one is confirmed |
| **Disable** (voluntary users only; enforced users get `403`) | Current password and a code of the current method (or a recovery code) |
| **New recovery codes** | Current password and a code of the current method (not a recovery code) |
| **Sign out of all trusted devices** | — |

The confirmation lives 10 minutes (`profile.confirmation_ttl`) and is bound to the session, the user,
the action and the target method. A wrong password counts like a wrong code (and does not use up the
code), so a stolen session cannot guess the password faster than a code. The actions are throttled per
user (`routes.profile_throttle`, 30 per minute). If the driver of the user's method is not installed,
every change but enabling is refused with "Your sign-in method is not available". Changing or setting up the
method again signs out of all trusted devices and rotates the remember token; every change sends a
security notice to the user's address.

## Routes

Registered with Orchid's domain, prefix (`admin` by default) and middleware groups:

| Method | URI | Name |
|---|---|---|
| POST | `login` | `platform.login.auth` (replaces Orchid's) |
| GET | `two-factor` | `platform.two-factor.challenge` |
| POST | `two-factor` | `platform.two-factor.verify` |
| POST | `two-factor/resend` | `platform.two-factor.resend` |
| POST | `two-factor/cancel` | `platform.two-factor.cancel` |
| POST | `two-factor/recovery` | `platform.two-factor.recovery` |
| POST | `two-factor/fallback` | `platform.two-factor.fallback` |
| GET | `two-factor/enroll/{channel?}` | `platform.two-factor.enroll` |
| POST | `two-factor/enroll/{channel}` | `platform.two-factor.enroll.confirm` |
| GET | `two-factor/recovery-codes` | `platform.two-factor.recovery-codes` |
| POST | `two-factor/recovery-codes` | `platform.two-factor.recovery-codes.confirm` |
| GET/POST | `profile/two-factor/{method?}` | `platform.profile.two-factor` (screen) |

The user of every `two-factor*` route comes from the pending sign-in in the session only. The
replacement works with `php artisan route:cache` too.

## Configuration

`config/orchid-2fa.php` (publish with `--tag=orchid-2fa-config`):

| Key | Default | Description |
|---|---|---|
| `enforce_all` | `false` | Require 2FA for every user of the admin panel |
| `channel` | `'email'` | The default channel: the method of a user without one of their own; used only when it is allowed and is a delivery channel without a setup step |
| `channels.allowed` | `['email', 'totp']` | Methods users may use, in this order; names without a driver are ignored |
| `channels.email.driver` | `EmailChannel::class` | Driver of the `email` channel: a class extending `DeliveryChannel`, or a name registered with `TwoFactor::extend()` (the 0.1 key `channels.email.class` is still read when `driver` is not set; deprecated, removed in 0.3) |
| `channels.email.attribute` | `'email'` | User attribute with the address |
| `channels.<name>.driver` | — | Driver of another channel (class or `extend()` name); drivers from packages register themselves and need no entry |
| `code.length` | `6` | Digits in an e-mail code |
| `code.ttl` | `600` | E-mail code lifetime, seconds |
| `code.max_attempts` | `5` | Wrong entries per code / per pending sign-in of a verifier channel / per profile confirmation |
| `resend.cooldown` | `60` | Seconds between sends |
| `resend.max_per_hour` | `5` | Sends per user per hour (login, resend and profile together) |
| `verify.user_max_attempts` | `10` | Wrong codes of a verifier channel and wrong recovery codes per user per window |
| `verify.user_decay` | `600` | That window, seconds; also how often the "someone is guessing" notice may be sent |
| `verify.user_max_per_day` | `30` | The same attempts per user per fixed 24 hours |
| `pending_ttl` | `600` | Seconds between a correct password and the code before the user has to sign in again |
| `enrollment_ttl` | `900` | Lifetime of the setup at sign-in (including the recovery codes screen), seconds from its start |
| `recovery_codes.count` | `8` | Codes per set |
| `recovery_codes.warn_at` | `2` | Warn in the profile when this many or fewer are left |
| `profile.confirmation_ttl` | `600` | Lifetime of a confirmation and of a setup step in the profile, seconds |
| `trusted_devices.enabled` | `true` | Show the "Trust this device" checkbox and accept trusted device cookies |
| `trusted_devices.lifetime_days` | `30` | Lifetime of a trusted device cookie, days |
| `trusted_devices.cookie` | `'orchid_2fa_trusted'` | Cookie name prefix |
| `notification.class` | `TwoFactorCodeNotification::class` | Notification with the code |
| `notification.email_changed_class` | `TwoFactorEmailChangedNotification::class` | Notification about an e-mail change |
| `notification.security.enabled` | `true` | Send the security notices (below) |
| `notification.security_class` | `TwoFactorSecurityNotification::class` | Security notice |
| `notification.queue` | `false` | Send notifications through the queue |
| `notification.connection` | `null` | Queue connection (`null` — default) |
| `notification.queue_name` | `null` | Queue name (`null` — default) |
| `cache.store` | `null` | Cache store for codes (`null` — default store) |
| `routes.throttle` | `'10,1'` | Per-IP throttle of the code routes: `max,minutes` |
| `routes.profile_throttle` | `'30,1'` | Per-user throttle of the actions of the two-factor profile screen (`POST profile/two-factor/{method}`): `max,minutes` |
| `menu.enabled` | `false` | Add a "Two-factor authentication" item to Orchid's main menu |
| `log.enabled` | `false` | Write the package events to the log |
| `log.channel` | `null` | Log channel (`null` — default) |

Drivers keep their own settings in their own config files (TOTP: `config/orchid-2fa-totp.php`).

E-mail codes are stored in the cache as an HMAC, never in plain text. Use a persistent store shared
by all application servers (not `array`); attempt and send counters use Laravel's rate limiter (its
cache store is `cache.limiter`).

Permission names are not configurable: `platform.2fa.required` and
`platform.systems.users.2fa-reset`.

## Trusted devices

When the user ticks "Trust this device for N days", a cookie is issued after the correct code; the
next sign-in on this browser asks for the password only. The cookie is encrypted with the app key,
bound to the user and the Orchid guard, `HttpOnly`, `SameSite=Lax`, limited to the Orchid path,
`Secure` per `session.secure` (or the request scheme when it is not set). Its name is per user and
guard, so several accounts in one browser do not interfere. A sign-in with a recovery code never
issues it, and the cookie replaces the code only for the user's current, allowed method (not while
the user is being moved to another method).

All trusted devices of a user stop working when:

- the user clicks "Sign out of all trusted devices" on the two-factor profile screen;
- the password changes through the model (profile, user edit screen, password reset);
- the user changes the method or sets it up again, disables 2FA, or an administrator resets it;
- the e-mail address of an e-mail user changes: the next sign-in asks for a code to the new address and
  deletes the trusted device cookie, so after confirming the new address the device has to be trusted
  again (the method of an authenticator app user does not depend on the address);
- the user signs in without the second factor while it is not required (for example, the
  `platform.2fa.required` permission was taken away for a while): the cookie is deleted the same way
  at the first sign-in after 2FA is required again.

With `trusted_devices.enabled = false` the checkbox is hidden and existing cookies are ignored (not
deleted: they work again once the option is turned back on).

## Events

`Nakipelo\Orchid2FA\Events\*`; every event has `user` (`Authenticatable`) and `guard` (string).

| Event | Extra properties |
|---|---|
| `TwoFactorChallengeSent` | `channel`, `maskedDestination` (`a***@example.com`), `context`: `login`, `enable`, `disable`, `switch`, `rebind`, `regenerate`, `enroll`, `fallback` — delivery channels only (nothing is sent for a verifier channel) |
| `TwoFactorPassed` | `via`: `code`, `trusted_device`, `recovery_code`, `enrollment`; `trustedDeviceIssued` (bool); `channel` |
| `TwoFactorFailed` | `reason`: `invalid_code`, `expired`, `delivery_failed`, `invalid_recovery_code`, `channel_unavailable`; `channel` |
| `TwoFactorLockedOut` | `reason`: `attempts_exceeded`, `send_limit`, `user_attempts_exceeded` (10 per 10 min), `user_daily_attempts_exceeded` (30 per day); `availableIn` (seconds); `channel` |
| `TwoFactorChannelChanged` | `from`, `to` (channel names or null), `reason`: `enrolled`, `switched`, `rebound`, `disabled`, `reset` |
| `RecoveryCodeUsed` | `channel`, `remaining`, `context`: `login`, `profile` |
| `RecoveryCodesRegenerated` | `channel`, `count` |

The values are also class constants (`TwoFactorFailed::INVALID_CODE`, `TwoFactorChannelChanged::RESET`
and so on). `TwoFactorPassed` is a sign-in event: the profile screen does not fire it. The final
sign-in fires Laravel's usual `Illuminate\Auth\Events\Login`. Events are fired by the package, never by
a driver.

With `log.enabled = true` the package writes all these events to `log.channel` (user id, guard and the
properties above; no codes, secrets or recovery codes).

## Notifications

| Config key | Default class | Constructor |
|---|---|---|
| `notification.class` | `Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification` | `(string $code, CarbonInterface $expiresAt)` |
| `notification.email_changed_class` | `Nakipelo\Orchid2FA\Notifications\TwoFactorEmailChangedNotification` | `(string $maskedNewAddress)` |
| `notification.security_class` | `Nakipelo\Orchid2FA\Notifications\TwoFactorSecurityNotification` | `(string $event, array $context)` |

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

**Security notices** (`notification.security.enabled`, on by default) go to the user's address
(`channels.email.attribute`) whatever the method is; `$event` is one of:

- `channel_changed` — a method was set up, changed, set up again, disabled, or reset by an
  administrator (every user of `orchid-2fa:reset --channel` gets one); context `from`, `to`, `reason`,
  `from_label`, `to_label`;
- `recovery_code_used` — at sign-in or in the profile; context `remaining`, `context`;
- `attempts_exceeded` — the per-user limit of wrong codes was reached: "Someone entered your password
  and is trying to guess the sign-in code"; context `channel`, `limit` (`window` or `day`),
  `available_in`. At most once per `verify.user_decay`.

Notifications are routed to the address in `channels.email.attribute` (the model does not need
`Notifiable`). By default they are sent synchronously, even if the class implements `ShouldQueue`,
so a transport error of a code is shown to the user and the login does not happen; a failed security
or e-mail change notice is logged and does not stop the action. With `notification.queue = true` all
notifications are queued (`notification.connection`, `notification.queue_name`); see the limitations
below.

The e-mail change notice goes to the **old** address when the address of a user who needs 2FA
changes; it contains the new address masked only.

## Translations

All texts of the code, setup and recovery code screens, the profile screen, the layouts, the toasts,
the permissions and the e-mails are in `orchid-2fa::messages`, shipped in English and Russian. The
locale is the application locale (`APP_LOCALE`). To change texts or add a locale:

```bash
php artisan vendor:publish --tag=orchid-2fa-translations
```

and edit or copy `lang/vendor/orchid-2fa/{locale}/messages.php`. Strings that belong to Orchid
(the "Profile" breadcrumb, the wrong password message) use Orchid's own JSON translations; drivers
keep theirs in their own namespace (`orchid-2fa-totp::messages`). Artisan command output is English
only.

The guest screens are the views `orchid-2fa::challenge` (the code), `orchid-2fa::enroll` (the setup at
sign-in) and `orchid-2fa::recovery-codes`, with partials in `orchid-2fa::partials.*`; they extend
Orchid's `platform::auth` layout. Publish them with `--tag=orchid-2fa-views`.

## Commands

| Command | Description |
|---|---|
| `orchid-2fa:rotate-remember-tokens [--force]` | Clear `remember_token` of all users of the Orchid guard's model. Run once after installing. |
| `orchid-2fa:reset {email} [--force]` | Reset 2FA of a user (as the "Reset 2FA" button): disable the voluntary 2FA, remove the method (the driver's data too) and the recovery codes, sign out of all trusted devices, rotate the remember token, remove the active code and all limits, fire `TwoFactorChannelChanged(reset)` and send the security notice. The record gets the default channel when it is allowed and registered: an enforced user then gets a code to the current address at the next sign-in, or sets up a method. The user is looked up by the address attribute (`channels.email.attribute`). |
| `orchid-2fa:reset --channel=<name> [--force]` | The same for every user whose method is `<name>` — for example before or after removing a driver. Works for a channel that is no longer registered (then only this package's data are reset, and the driver's table is left as it is). Without `--force` it asks with the number of users; non-interactive runs without `--force` fail. |

`orchid-2fa:reset` takes either the e-mail address or `--channel`, not both. The commands ask for
confirmation unless `--force` is given, exit with code 1 when declined (or when the e-mail is unknown)
and do not check Orchid permissions.

## Writing a channel

A channel is a class extending one of two base classes — the registry accepts nothing else:

- **`Nakipelo\Orchid2FA\Channels\DeliveryChannel`** — the server sends a code. Implement
  `destination(Authenticatable): string` (the raw address the code is bound to; `''` — the channel
  cannot serve the user) and `send(Authenticatable, string $code, CarbonInterface $expiresAt): void`
  (throw `DeliveryFailedException` on failure). Code generation, storage (an HMAC in the cache), the
  send limits, the countdown, fail-closed delivery and an atomic one-time check are in the base class;
  `issue()` and `verify()` are `final`. Override `maskedDestination()`, `label()`, `prompt()` as needed.
  If the destination is something the user enters (a phone number), override `enrollmentView()` and
  the enrollment methods and call `TwoFactorManager::destinationChanged($user, '<name>', $old)` when it
  changes.
- **`Nakipelo\Orchid2FA\Channels\VerifierChannel`** — the user's device generates the code. Implement
  `verifyCode(Authenticatable, string $code): bool` (protected; the code arrives without spaces and
  dashes and is never empty), `isAvailableFor()`, `startEnrollment()`, `confirmEnrollment()` and
  `forget()`; `enrollmentView()` and `enrollmentData()` default to no partial (`null` and `[]`), as in
  `DeliveryChannel` — override them to show a QR code or a key. `verifyCode()` **must** refuse a code that
  was already accepted (replay protection) **atomically**: two parallel requests with the same code
  must not both pass — use a conditional `UPDATE … WHERE last_step < ?` and check that one row changed,
  not read-compare-write. An exception from `verifyCode()` or `confirmEnrollment()` is logged (without
  the code) and counts as a wrong code. A new enrollment (setting the method up again) must replace
  the previous binding: the old secret stops working at once.
  The core marks its parameters carrying a code, a recovery code or a secret `#[\SensitiveParameter]`,
  so a logged trace of a driver exception does not show them in the core's frames; the attribute is not
  inherited, so a driver marks its own such parameters too (`verifyCode()`, `confirmEnrollment()`,
  `send()`, helpers), as [nakipelo/orchid-2fa-totp](https://github.com/nakipelo/orchid-2fa-totp) does.
  Recovery codes are on by default (`needsRecoveryCodes()`); `allowsEmailFallback()` is off.

The package does the rest for every channel: who the user is (the session only), attempt counting
before the driver is called, lockouts, events, recovery codes, trusted devices, remember tokens, the
final sign-in. Base classes have no constructor, so the driver's constructor is free for dependency
injection; the registry calls `bootChannel($name, $config)` after creating it.

**Register** the driver in `boot()` of the package's service provider; keep the driver's settings in
its own config file (not under `orchid-2fa.channels.<name>`: a published `orchid-2fa.php` would
override them):

```php
use Illuminate\Contracts\Container\Container;
use Nakipelo\Orchid2FA\Facades\TwoFactor;

public function register(): void
{
    $this->mergeConfigFrom(__DIR__.'/../config/orchid-2fa-acme.php', 'orchid-2fa-acme');
}

public function boot(): void
{
    $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    $this->loadViewsFrom(__DIR__.'/../resources/views', 'orchid-2fa-acme');
    $this->loadTranslationsFrom(__DIR__.'/../lang', 'orchid-2fa-acme');

    TwoFactor::extend('acme', static fn (Container $app, array $config) => $app->make(AcmeChannel::class));
}
```

The channel is offered once its name is in `orchid-2fa.channels.allowed` (the application's choice).
An application can also register a channel class without a package:
`'channels' => ['sms' => ['driver' => App\TwoFactor\SmsChannel::class], 'allowed' => ['email', 'sms']]`.

**UI.** `label()` names the method everywhere (translate it); `prompt()` is the line above the code
field; `codeInput()` describes the field (`CodeInput::digits(6)`). Two optional Blade partials, one for
both the sign-in screens and the profile:

- `enrollmentView()` — the setup step (a QR code, instructions); it gets the array of
  `enrollmentData($user, $state)` as variables. Keep secrets of an unfinished setup in the
  `EnrollmentState` (`$state->put('secret', …)`), which lives in the server session, and store them
  only in `confirmEnrollment()` after a correct code;
- `challengeView()` — replaces the common code field on the code screen; gets `$channel`, `$user` and
  `$codeInput`.

Partials have no `@extends`, no forms and no external resources (CSP); the package draws the `code`
field and the buttons. Translations live in the driver's namespace.

**What a driver may call.** Besides its own base class, a driver uses only these: the stable methods of
`Nakipelo\Orchid2FA\Challenge\ChallengeManager` — `issue(Authenticatable $user, string $context =
Context::LOGIN, ?TwoFactorChannel $channel = null): Challenge` (a delivery driver's enrollment issues its
code through it: limits, events, fail-closed), `verify()`, `verifyRecoveryCode()`,
`attemptsLeft()`, `sendAvailableIn()`, `annul()` and `fallbackChannel()`; the rest (`start()`,
`rejectAttempt()`, `startEnrollment()`, `confirmEnrollment()`, `enrollmentChallenge()`, `lockout()`,
`clear()`, `activeChallenge()`, `channelFor()`) serves the package's controllers and the profile and may
change in a minor version. `TwoFactorManager::destinationChanged($user, '<name>', $old)` for a
destination of its own. From the registry (`TwoFactor` facade): `TwoFactor::for($user)` returns the
channel that verifies the user's code — the allowed method, **and also an enrolled method that is no
longer allowed** (the proof before an allowed one is set up, state `proof`); `TwoFactor::methodFor($user)`
returns `Channels\UserMethod` with the state (`active`, `proof`, `unavailable` — the driver is gone or
cannot be created, `none`), the channel and the recorded name. The context of a challenge
(`Challenge::$context`, the `$context` of `issue()`, `EnrollmentState::$context`) is one of the string
constants of `Nakipelo\Orchid2FA\Challenge\Context`: `LOGIN`, `ENABLE`, `DISABLE`, `SWITCH`, `REBIND`,
`REGENERATE`, `ENROLL`, `FALLBACK`.

**Data and reset hooks.** Keep the driver's data in its own tables and migrations (foreign key to
`users.id`, `cascadeOnDelete`). `forget(Authenticatable)` must erase them and be idempotent: the
package calls it when the user leaves the method (change, disabling, reset). `isAvailableFor()` must
be false afterwards. A row may outlive a reset made while the driver was not installed — the next
`confirmEnrollment()` should replace it (upsert).

**Conformance suite.** `Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase` is a PHPUnit test case
(on Orchestra Testbench; Pest runs it as is) that boots Orchid, this package and the driver with an
in-memory SQLite database and checks the sign-in, limits, bypasses, replay (also of two interleaved
verifications), trusted devices, remember tokens, reset, that a new enrollment invalidates the code of
the old binding, recovery codes, enrollment and that no codes or secrets reach logs and events — also
while the enrollment step is shown (string values of `enrollmentData()` of 8 characters or more must not
reach the log).
Add the dependencies to the driver's `require-dev` (this package does not require them):

```json
{
    "require": {
        "nakipelo/orchid-2fa": "^0.2"
    },
    "require-dev": {
        "orchestra/testbench": "^9.9 || ^10.0 || ^11.0",
        "pestphp/pest": "^3.7 || ^4.0"
    }
}
```

and extend the test case:

```php
namespace Acme\Orchid2FA\Tests\Conformance;

use Closure;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Channels\VerifierChannel;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;
use Nakipelo\Orchid2FA\Testing\Fixtures\User;

class AcmeChannelConformanceTest extends ChannelConformanceTestCase
{
    protected function channelName(): string { return 'acme'; }

    protected function channelProviders(): array { return [AcmeServiceProvider::class]; }

    // Bring the user to the enrolled state directly (e.g. insert a confirmed secret).
    protected function enroll(User $user): void { /* ... */ }

    // A code the channel accepts now (a delivery channel: the code it has just sent).
    protected function validCode(User $user): string { /* ... */ }

    // A code the channel refuses now; $state — the enrollment step the code is for (null — the
    // login): exclude the codes of the secret in the state too.
    protected function invalidCode(User $user, ?EnrollmentState $state = null): string { /* ... */ }

    // Move to the next code window (e.g. $this->travel(30)->seconds()); a no-op for delivery.
    protected function nextCodeWindow(): void { /* ... */ }

    protected function completeEnrollmentCode(User $user, EnrollmentState $state): string { /* ... */ }

    // Verifier channels (required): a second instance of the channel that calls $between once after
    // reading and before writing in verifyCode(); see the doc comment of the method.
    protected function racingChannel(Closure $between): ?VerifierChannel { /* ... */ }
}
```

```xml
<!-- phpunit.xml.dist -->
<testsuites>
    <testsuite name="Package">
        <directory>tests</directory>
    </testsuite>
</testsuites>
<php>
    <env name="APP_ENV" value="testing"/>
</php>
```

The test user is enforced and the channel under test is its only allowed method. Tests that cannot
apply skip themselves (e.g. "send again" of a verifier channel); skip others only by overriding them
with `markTestSkipped()` when they really do not apply.

**Replay under parallel requests.** The suite can check atomicity only with your help:
`racingChannel()` returns a new instance of the channel (usually an anonymous subclass) that runs
`$between` once between the read and the write of `verifyCode()`; the suite verifies the same code
inside it and expects exactly one of the two verifications to pass. For a verifier channel the hook is
**required**: with the default `null` the test fails ("Override racingChannel() or skipsRaceTest()").
A driver that really cannot offer that point (e.g. the read and the write are one call of an external
service) opts out explicitly with `protected function skipsRaceTest(): bool { return true; }`; the
test is then skipped and **the atomicity of the replay protection is checked only by the driver's own
tests** — see `tests/Feature/ReplayTest.php` of `nakipelo/orchid-2fa-totp` for both an interleaving
test and one with parallel processes. A delivery channel needs nothing: its `verify()` is the final one
of `DeliveryChannel`.

**A new binding replaces the old one.** `test_a_new_enrollment_replaces_the_old_binding` takes
`validCode()` of the enrolled user, enrolls the channel again (`completeEnrollmentCode()`) and expects
the old code to be refused. When the new binding happens to give the same code (a verifier channel,
about 10⁻⁶), the suite enrolls again (at most 5 times) instead of skipping; a driver that accepts the
neighbouring time steps may, with a probability of about 2·10⁻⁶, get a false failure there.

**Compatibility.** Depend on `nakipelo/orchid-2fa` `^0.2`. The public API — `Contracts\*`, the base
classes, `EmailChannel`, `ChannelRegistry` and `Facades\TwoFactor`, `Challenge\{Challenge, CodeInput,
Context, EnrollmentState, VerificationResult}`, `Channels\UserMethod`, `Events\*`, `Exceptions\*`,
`Testing\*`, the `ChallengeManager` methods listed above, config, route, view and
translation names — changes in 0.x only in a minor version with an upgrade section here. Classes
marked `@internal` (`CodeStore`, `StoredCode`, `PendingLogin`, `ProfileChallenge`, `RecoveryCodes`,
the controllers) are not part of it.

## Upgrade 0.1 → 0.2

**For applications with e-mail codes only** nothing but `migrate` is needed:

1. `composer require nakipelo/orchid-2fa:^0.2`, then `php artisan migrate`: the column
   `two_factor_authentications.channel` becomes nullable, and the table `two_factor_recovery_codes`
   is created. Do not change migrations you published for 0.1; the new ones are loaded from the
   package.
2. A published config keeps working: `channels.email.class` is read as `channels.email.driver`. Rename
   it to `driver` and add `channels.allowed` when convenient (without it the default
   `['email', 'totp']` applies; `totp` is ignored until its package is installed). New keys work with
   their defaults without publishing.
3. A published `challenge.blade.php` keeps working for e-mail; publish the views again to get the
   recovery code link and the partials of drivers.
4. Users who are on the code step during the deployment sign in again (a pending sign-in of 0.1 is not
   accepted).
5. The sign-in, the limits, trusted devices and remember-me for e-mail users do not change. What users
   see: disabling 2FA in the profile now asks for the current password too; disabling and a reset by an
   administrator send a security notice and fire `TwoFactorChannelChanged` (turn the notices off with
   `notification.security.enabled = false`).
6. Use a server-side session driver (see Requirements).

**If you changed the default `channel` in 0.1** to a channel of your own: 0.1 took the channel from the
config and ignored the column, which holds `'email'` for every 0.1 record. 0.2 uses the column, so those
users would get e-mail codes after the upgrade while `email` is allowed. Port the channel (below),
register it in `channels.<name>.driver`, add its name to `channels.allowed`, and move the records:
`UPDATE two_factor_authentications SET channel = '<name>' WHERE channel = 'email'`. New records, and
records after disabling or a reset, get the default channel only when it is allowed and registered;
otherwise none (an enforced user then sets up a method at sign-in).

**Moving everyone to TOTP** is one line of config after installing
`nakipelo/orchid-2fa-totp` and migrating: `'channels' => ['allowed' => ['totp'], …]` (see
[Moving all users to another method](#moving-all-users-to-another-method)).

**Removing a driver** (e.g. TOTP), in this order:

1. Reset its users: `php artisan orchid-2fa:reset --channel=totp --force` — otherwise they cannot
   sign in (fail-closed). The command also works after the package is removed.
2. If you list the channel in `channels.allowed`, remove it and keep another channel there (for
   example `'allowed' => ['email']` after `['totp']`). With no allowed channel left the package throws on
   boot in `local`/`testing` — `composer remove` then fails in its `package:discover` step — and
   elsewhere users who need 2FA cannot sign in.
3. Roll back the driver's migration while the package is still installed:
   `php artisan migrate:reset --path=vendor/nakipelo/orchid-2fa-totp/database/migrations` rolls back
   only the migrations of that path (the others are listed as "Migration not found"); for a published
   migration pass the path of the copy.
4. `composer remove nakipelo/orchid-2fa-totp`.

If the package is already removed, drop its table (`two_factor_totp`) and delete its row from the
`migrations` table by hand.

**Breaking API changes** (own channels and integrations):

- `Contracts\TwoFactorChannel` is a new contract: `label()`, `requiresDelivery()`,
  `needsRecoveryCodes()`, `issue()`/`verify()` with `Challenge` objects, the enrollment methods,
  `forget()`. A 0.1 channel with `send()`, `destination()` and `maskedDestination()` ports by extending
  `DeliveryChannel` (the methods are the same) and registering it in `channels.<name>.driver` (the key
  `class` still works until 0.3).
- `ChallengeManager::channel()` is removed (use `TwoFactor::for($user)` or `TwoFactor::channel($name)`);
  `issue()` and `verify()` take and return `Challenge` instead of a challenge id string.
- `TwoFactorManager::enable()` is replaced by `commitEnrollment($user, $channel, $reason)`.
- `TwoFactorPassed`, `TwoFactorFailed` and `TwoFactorLockedOut` have a new last constructor
  parameter `channel` (`TwoFactorChallengeSent` already had it; listeners are not affected, code that
  constructs these events is); `TwoFactorPassed::$trustedDeviceIssued` has no default any more;
  `TwoFactorLockedOut::$reason` has the new values `user_attempts_exceeded` and
  `user_daily_attempts_exceeded`.
- `TwoFactorAuthentication::$channel` is nullable.
- The contexts of challenges are constants of `Challenge\Context` (`Context::LOGIN`, …, the values are
  unchanged); `TwoFactorChallengeSent::CONTEXT_LOGIN`, `CONTEXT_ENABLE` and `CONTEXT_DISABLE` of 0.1 are
  deprecated aliases, removed in 0.3.
- `orchid-2fa:reset`: the `email` argument is optional (exclusive with `--channel`); `orchid-2fa:reset
  <email>` works as before.

## Limitations and recommendations

- **Session driver.** Use a server-side session driver; with `cookie` the pending sign-in, the secret
  of an unfinished setup and the recovery codes to show travel to the browser, and a session over 4 KB
  is lost (see Requirements).
- **First enrollment.** A user without any confirmed method (new, after a reset, or whose e-mail was
  never confirmed when only an app is allowed) sets up a method protected by the password only, as in
  Laravel Fortify. The setup lives `enrollment_ttl` (15 minutes) from its start; the user then signs in
  again. Such a setup never trusts the device (no checkbox, no cookie), and it ends (back to the
  sign-in form) as soon as the user has a method by other means — e.g. the owner set one up in another
  browser — so a second browser with the password cannot replace it. A window remains inside one
  request, from that check until `commitEnrollment()` records the method; the driver's
  `confirmEnrollment()` stores its data (the secret) before the core records the method, so only a
  conditional write in the driver as well can close it (a candidate for the 0.3 contract:
  `confirmEnrollment()` with the expected previous state). In practice it needs the password and both
  confirmations within milliseconds of each other.
- **Lost device and recovery codes.** A user without the device and without recovery codes is restored
  only by an administrator ("Reset 2FA" or `orchid-2fa:reset`); there is no self-service recovery.
- **Removing a driver.** Users of a channel whose driver is not registered cannot sign in (fail-closed,
  no silent downgrade to e-mail) until they are reset: run `orchid-2fa:reset --channel=<name>` before
  or after removing the package.
- **Code guessing locks out the owner too.** Someone who knows the password can use up the per-user
  limits of a verifier channel (10 per 10 minutes, 30 per day) and so keep the owner from signing in
  with a code for up to 24 hours (a recovery code is counted in the same limits). The owner gets an
  e-mail and should change the password; `TwoFactorLockedOut` is the signal for monitoring.
- **Atomicity of drivers.** Replay protection of a verifier channel is the driver's job. The
  conformance suite requires its `racingChannel()` hook from a verifier driver; a driver may opt out
  with `skipsRaceTest()` — check for it and review the driver's own tests before trusting a
  third-party driver. A driver runs in your application process
  and can do anything: install drivers you trust.
- **Password for changes of 2FA.** Enabling, changing the method, setting it up again, disabling 2FA
  and new recovery codes ask for the current password; the "Profile" screen of the Orchid stubs changes the
  e-mail address without it (see "E-mail change without a password").
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
  guard separate. (A middleware "signed in, but the second factor was not passed in this session" is
  planned for 0.3.)
- **`platform.auth = false`.** Orchid then registers no login routes and the package does not replace
  `POST login`: your own login must take care of the second factor. In `local` and `testing` the
  package logs a warning once per boot; in other environments it is silent. The profile routes are
  still registered; the code step routes (`two-factor*`) are not.
- **E-mail change without a password.** Orchid's `UserProfileScreen` changes the e-mail address
  without asking for the password. Someone with a stolen session can redirect the e-mail codes to their
  own address; the owner only gets the notice at the old address. (Changing the 2FA method itself needs
  the password, so the new address alone does not let them replace an authenticator app.) Ask for the
  current password in the stub (`app/Orchid/Screens/User/UserProfileScreen.php`):

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

- **Active code reuse and send limits.** While an e-mail code is active (not expired, attempts left),
  a new sign-in reuses it and sends no e-mail. Someone who knows the password can use up the attempts
  and the hourly send limit and so keep the owner from signing in with a code until the limits expire
  (up to an hour). The account is not locked, and the owner should change the password.
- **Foreign keys to `users.id`.** The migrations reference the `users` table. If the model of the
  Orchid guard's provider uses another table (or a non-`bigint` key), publish the migrations and fix
  them before `php artisan migrate`.
- **Codes in the queue.** With `notification.queue = true` the code is in plain text in the queued job
  payload until the job is sent (the cache keeps only an HMAC). Protect the queue storage accordingly,
  or keep the default synchronous sending.
- **Impersonation.** Orchid's "Login as" (permission `platform.systems.users`) signs in as an enforced
  user without that user's second factor. Grant the permission only to people you trust with that.
- **Rotating `app.key`.** E-mail codes are stored as an HMAC with the app key and trusted device
  cookies are encrypted with it: a new `app.key` invalidates active codes and all trusted devices.
  Recovery codes survive (they use the password hasher). Drivers may depend on it too (TOTP secrets are
  encrypted with it: keep the old key in `APP_PREVIOUS_KEYS`).
- **Remember-me cookies after 2FA becomes required.** Once a user gets `platform.2fa.required` (or
  `enforce_all` is turned on), the first password sign-in that starts the code step rotates the
  remember token, so remember-me cookies issued without the second factor stop working. Until that
  sign-in they still work: run `php artisan orchid-2fa:rotate-remember-tokens` for an immediate
  effect. A reset by an administrator and every change of the method rotate the remember token too.
- **One method per user.** A user has one active method at a time (plus recovery codes); requiring a
  specific method per role is not supported — `channels.allowed` applies to everyone.

## Security

- No sign-in before the code: the password is checked with `validate()`, the session stays a guest
  session and is regenerated when the code step starts and at the final sign-in.
- The user of the code step comes from the server session only; request parameters are ignored.
- E-mail codes: `random_int`, stored as an HMAC (app key) bound to the challenge and the address,
  compared with `hash_equals`; a used code is consumed atomically, a new code invalidates the old one.
  5 attempts × 5 codes per hour against 10⁶ values, plus a per-IP throttle.
- Attempts are counted before the code is checked, for every channel. Verifier codes and recovery codes
  share per-user limits (10 per 10 minutes, 30 per day): about 0.009 % per day to guess a TOTP code with
  ±1 step tolerance, and the owner is told by e-mail.
- A code of another channel's challenge is not accepted (the method changed or was reset meanwhile).
- Recovery codes: about 40 bits each, stored as hashes only, consumed atomically, shown once.
- Enabling needs the current password with the first code of the new method; changing, setting up again
  or disabling the method and new recovery codes need the current password and a code in the same form; the confirmation is bound to the session, the user, the action and the
  target method. Enforced users cannot disable 2FA (checked on the server). Every change sends a
  security notice.
- Setting up a method at sign-in when a confirmed (but no longer allowed) method exists requires a code
  of that method first. A setup step checks on every request that the user's method is still what it
  was when the step started (none, or the proof method): a method set up meanwhile ends it, so a
  second browser with the password cannot replace it. A setup with the password only never trusts the
  device. A setup over a recorded method signs out of the trusted devices.
- Wrong passwords get exactly Orchid's response; send limits apply only after a correct password.
- Remember-me cookies are issued only after the second factor; tokens are rotated when a method is set
  up, changed or set up again, when the code step starts for a user whose 2FA is not confirmed (a new
  record, after disabling, a reset, an e-mail change or a sign-in without the second factor), on a reset
  by an administrator and by `orchid-2fa:rotate-remember-tokens`.
- The pending code step is bound to the password: it keeps an HMAC of the password hash (not the hash
  itself) and ends when the password changes.
- Fail-closed when the code cannot be delivered, when a driver throws while checking a code, and when
  the user's driver is not installed.

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

The workbench is e-mail only and keeps the session in files (`SESSION_DRIVER=file`). The test verifier
driver `fake` (codes from `php vendor/bin/testbench orchid-2fa-fake:code <email>`) is enabled with
`ORCHID_2FA_FAKE=1`, and `ORCHID_2FA_ALLOWED="email,fake"` sets `channels.allowed`.

Individual checks: `composer test`, `composer analyse` (Larastan level 8), `composer lint` (Pint),
`composer check-adapter` (`platform.`, `platform::` and `Orchid\` appear in `src/` only in
`src/Support/Orchid.php`, and `Orchid\` also in the UI layer `src/Screens`, `src/Layouts` and the
conformance suite `src/Testing`).

## License

MIT. See [LICENSE](LICENSE).
