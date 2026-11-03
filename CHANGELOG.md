# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Version 0.2.0: channel drivers. The first external driver is
[nakipelo/orchid-2fa-totp](https://github.com/nakipelo/orchid-2fa-totp) (authenticator apps). For
applications with e-mail codes only the upgrade is `composer require` and `php artisan migrate`; see
"Upgrade notes" below and "Upgrade 0.1 → 0.2" in the README.

### Added

- Channel drivers: the base classes `Channels\DeliveryChannel` (the server sends a code) and
  `Channels\VerifierChannel` (the user's device generates it), the registry `Channels\ChannelRegistry`
  with the facade `Facades\TwoFactor` (`extend()`, `channel()`, `has()`, `registered()`, `allowed()`,
  `for()`), config `channels.<name>.driver`. `EmailChannel` is a `DeliveryChannel` and stays the
  zero-config default.
- `channels.allowed` (default `['email', 'totp']`): the methods users may use. Names without a driver
  are ignored (a warning in `local`/`testing`); no allowed channel at all is an exception in
  `local`/`testing` and a `critical` log entry with fail-closed sign-ins elsewhere. A section
  "Orchid 2FA" in `php artisan about`.
- One method per user, stored in `two_factor_authentications.channel`. A method that is set up but no
  longer allowed is accepted once as a proof before setting up an allowed one; a method whose driver is
  not installed fails closed.
- Setting up a method at sign-in (`two-factor/enroll`, `enrollment_ttl`) for enforced users without a
  method; JSON clients get `200 {"two_factor": true, "enroll": true, "redirect": …}` and the setup
  routes answer JSON with `406`.
- Recovery codes for methods that need them (8 codes `xxxx-xxxx`, hashed with the password hasher,
  consumed atomically, shown once): at sign-in (never trusts the device), for changing the method,
  setting it up again and disabling; "New recovery codes" in the profile; a warning when 2 or fewer
  are left and a banner after a sign-in with a recovery code. Table `two_factor_recovery_codes`.
- Profile: choose a method when enabling, "Change to …", "Set up again", "New recovery codes"; status
  "Required, no method set up yet".
- Per-user limits for verifier codes and recovery codes: `verify.user_max_attempts` (10) per
  `verify.user_decay` (600 s) and `verify.user_max_per_day` (30); 5 wrong codes per pending sign-in of a
  verifier channel.
- Security notices (`Notifications\TwoFactorSecurityNotification`, `notification.security.enabled`,
  `notification.security_class`): a method set up, changed, set up again, disabled or reset; a recovery
  code used; someone guessing the code (the per-user limit reached, at most once per window).
- Events `TwoFactorChannelChanged` (`enrolled`, `switched`, `rebound`, `disabled`, `reset`),
  `RecoveryCodeUsed`, `RecoveryCodesRegenerated`; the field `channel` in all events; new values
  `TwoFactorPassed::$via` (`recovery_code`, `enrollment`), `TwoFactorFailed::$reason`
  (`invalid_recovery_code`, `channel_unavailable`), `TwoFactorLockedOut::$reason`
  (`user_attempts_exceeded`, `user_daily_attempts_exceeded`), `TwoFactorChallengeSent::$context`
  (`switch`, `rebind`, `regenerate`, `enroll`, `fallback`).
- `orchid-2fa:reset --channel=<name>`: reset every user of a channel, also of one whose driver was
  removed.
- E-mail fallback for verifier channels that offer it (`two-factor/fallback`).
- UI extension points for drivers: `label()`, `prompt()`, `codeInput()`, `challengeView()`,
  `enrollmentView()` with `enrollmentData()`; new views `orchid-2fa::enroll`,
  `orchid-2fa::recovery-codes` and partials.
- The conformance suite for drivers `Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase` (needs
  `orchestra/testbench` and PHPUnit or Pest in the driver's `require-dev`), with the hook
  `racingChannel()` to check that the replay protection of a verifier channel is atomic (required for a
  verifier channel: without it the test fails; `skipsRaceTest()` is the explicit opt-out), a check that
  a new enrollment invalidates the code of the old binding and a check that the values of
  `enrollmentData()` do not reach the log. The hook `invalidCode(User $user, ?EnrollmentState $state =
  null)` gets the enrollment step the code is for.
- `Challenge\Context`: the contexts of challenges as constants (`LOGIN`, `ENABLE`, `DISABLE`, `SWITCH`,
  `REBIND`, `REGENERATE`, `ENROLL`, `FALLBACK`).
- `Channels\UserMethod` (`TwoFactor::methodFor()`) is public API: the state of the user's method
  (`active`, `proof`, `unavailable`, `none`).
- `routes.profile_throttle` (`'30,1'`): a per-user throttle of the actions of the two-factor profile
  screen.
- A warning in the log (`local`/`testing`) when `session.driver` is `cookie`.

### Changed

- **Breaking:** `Contracts\TwoFactorChannel` is a new contract (`label()`, `requiresDelivery()`,
  `needsRecoveryCodes()`, `issue()`/`verify()` with `Challenge` objects, enrollment methods, `forget()`);
  a 0.1 channel ports by extending `DeliveryChannel`.
- **Breaking:** `ChallengeManager::issue()`/`verify()` take and return `Challenge` instead of a
  challenge id; `TwoFactorManager::enable()` is replaced by `commitEnrollment()`.
- **Breaking:** `TwoFactorPassed`, `TwoFactorFailed` and `TwoFactorLockedOut` take a new last
  constructor parameter `channel`; `TwoFactorPassed::$trustedDeviceIssued` has no default.
- **Breaking:** `two_factor_authentications.channel` is nullable (null — no method); the method of a
  user comes from this column, not from the config `channel`, which is now the default channel for
  users without a method (used only when it is allowed and is a delivery channel).
- Disabling 2FA in the profile asks for the current password together with the code; changing the
  method, setting it up again and new recovery codes ask for both too. A wrong password counts like a
  wrong code.
- Disabling and a reset by an administrator fire `TwoFactorChannelChanged` and send a security notice
  (0.1 fired nothing).
- After disabling and after a reset the record gets the default channel when it is allowed and
  registered, otherwise none (one rule for both).
- `channels.email.class` is renamed to `channels.email.driver`; `class` is still read when `driver` is
  not set.
- `VerifierChannel::enrollmentView()` and `enrollmentData()` have defaults (`null`, `[]`), as in
  `DeliveryChannel`.
- Enabling 2FA in the profile asks for the current password with the first code. A user whose 2FA is
  disabled but who still has a set-up method with data of its driver can enable only that method again
  (a new setup) instead of silently replacing it with another one.
- A setup at sign-in with the password only (no confirmed method) no longer offers "Trust this device";
  after the proof with a code it still does.
- A driver of an allowed channel that cannot be created (`channels.<name>.driver` is not a subclass of a
  base class, the factory fails) is found at boot: an exception in `local`/`testing`, elsewhere a warning
  and the channel is ignored like a name without a driver.
- `orchid-2fa:reset`: the `email` argument is optional and exclusive with `--channel`; a reset also
  removes the driver's data and the recovery codes and clears the per-user limits.
- An e-mail change no longer drops the confirmation of a user whose method is not e-mail.
- The texts about "a code by e-mail" in the profile, the profile link and the reset block are
  generalised.
- A pending sign-in stored by 0.1.x is not accepted after the upgrade: the user signs in again.

### Deprecated

- `channels.<name>.class` (use `channels.<name>.driver`); removed in 0.3.
- `TwoFactorChallengeSent::CONTEXT_LOGIN`, `CONTEXT_ENABLE`, `CONTEXT_DISABLE` (use `Challenge\Context`);
  removed in 0.3.

### Removed

- `ChallengeManager::channel()` (it ignored the user's channel): use `TwoFactor::for($user)` or
  `TwoFactor::channel($name)`.
- `TwoFactorManager::enable()` (see `commitEnrollment()`).
- The default value `'email'` of the column and the model attribute `channel`.

### Security

- A setup step at sign-in no longer replaces a method the user got after the step had started: a step
  started without a method (password only) or after the proof checks the user's method on every
  request, and a method set up meanwhile (e.g. by the owner in another browser) ends it; the recovery
  codes step of a setup ends when the method was reset or changed meanwhile. A setup over a recorded
  method signs out of the trusted devices. (Found in the review of 0.2.0 before the release: someone
  with the password could keep a setup step open and replace the owner's freshly set-up method, its
  recovery codes included.)
- Changing the second factor from a stolen session needs the current password: enabling, changing the
  method, setting it up again, disabling and new recovery codes; enforced users still cannot disable 2FA.
- Setting up a method at sign-in requires a code of the confirmed method first when one exists, so a
  narrowed `channels.allowed` does not let someone with the password bind their own method.
- Attempts of every channel are counted before the driver is called; a challenge of another channel is
  refused; an exception of a driver while checking a code counts as a wrong code; a missing driver
  fails closed instead of falling back to e-mail.
- A trusted device cookie replaces the code only for the user's current allowed method, and a sign-in
  with a recovery code never issues one.
- The owner is notified when someone with the password is guessing the code.
- Parameters of the core carrying a code, a recovery code or a secret are `#[\SensitiveParameter]`:
  a logged trace of a driver exception (with arguments when `zend.exception_ignore_args=0`) no longer
  shows the code in the core's frames. The attribute is not inherited: a driver marks its own
  parameters (see "Writing a channel").

### Fixed

- Before the release (review of 0.2.0): "Disable" and the other changes in the profile of a user whose
  driver was removed answered 500 (now a message, enabling still works); the attempts of a setup step
  were counted only `code.ttl` while the step lives `enrollment_ttl` (`profile.confirmation_ttl` in the
  profile); "Send again" of the setup step of an authenticator app generated a new secret behind the
  shown QR code; the proof with a no longer allowed method confirmed the record before the new method
  was set up; an exception of a driver's `confirmEnrollment()` answered 500 instead of counting as a
  wrong code.

### Upgrade notes

- `php artisan migrate` (nullable `channel`, `two_factor_recovery_codes`); published 0.1 migrations
  and a published config keep working; publish the views again to get the recovery code link.
- Use a server-side session driver (`file`, `database`, `redis`, …).
- If you changed the default `channel` to your own channel in 0.1, every 0.1 record still says
  `email`: port the channel to `DeliveryChannel`, register it, allow it and update the records
  (README, "Upgrade 0.1 → 0.2").
- Moving all users to TOTP: install `nakipelo/orchid-2fa-totp`, migrate, set
  `channels.allowed = ['totp']`.
- Removing a driver: `php artisan orchid-2fa:reset --channel=<name> --force` (before or after).

## [0.1.1] - 2026-11-03

Patch release after an independent review.

### Security

- An old remember-me cookie no longer signs in without the code after 2FA becomes required for a user
  who already has a two-factor record (enabled and disabled 2FA, reset by an administrator, the
  `platform.2fa.required` permission taken away and granted again, `enforce_all` turned on). The
  remember token is now rotated when the code step starts and the record is new **or not confirmed**
  (`confirmed_at` is null); a sign-in without the second factor drops the confirmation of an existing
  record. Remember-me cookies of a confirmed user are not touched.
- A reset by an administrator ("Reset 2FA", `orchid-2fa:reset`) rotates the remember token.
- The pending code step is bound to the password: it keeps an HMAC of the password hash and ends
  (back to the login form, "Your password has been changed. Please sign in again.") when the password
  changes before the code is entered.

### Fixed

- With `platform.auth = false` the code step routes (`two-factor*`) are no longer registered: without
  Orchid's login route they answered 500. The profile routes stay.
- `orchid-2fa:reset` looks the user up by the configured address attribute
  (`channels.email.attribute`) instead of a hard-coded `email`.
- The e-mail change notice is sent through the configured channel class (`channels.email.class`)
  instead of a hard-coded `EmailChannel`.

### Changed

- The JSON response of the password step reports a code that could not be sent (send limit, delivery
  error): still `200` with `two_factor` and `redirect`, plus `error` and `resend_available_in`.
- A pending login stored by 0.1.0 is not accepted after the upgrade: the user signs in again.

### Documentation

- An e-mail change invalidates trusted devices: the trusted device cookie is deleted at the first
  sign-in after the change (the spec and README said it would work again after confirmation).
- README limitations: active code reuse and send limits, the foreign key to `users.id`, codes in the
  queue payload, impersonation, rotating `app.key`, remember-me cookies after 2FA becomes required.
- The spec reflects the decisions of this release.

## [0.1.0] - 2026-11-03

First release.

### Added

- Second factor for Orchid's password login: a one-time code sent by e-mail, "code first, login
  second" (`POST login` replaced by the package; the user is not signed in before the code).
- Code step screen (`orchid-2fa::challenge`): resend with a countdown, "Sign in as a different user",
  JSON responses.
- Enforcement by the `platform.2fa.required` permission or for everyone (`enforce_all`); voluntary
  enabling and disabling on the profile screen, confirmed with a code.
- Limits: code lifetime, attempts per code, resend cooldown, hourly send limit, per-IP throttle;
  fail-closed when the code cannot be delivered.
- Trusted devices: an encrypted per-user cookie, invalidated by "Sign out of all trusted devices", a
  password change, disabling, an admin reset and an e-mail change (until the new address is confirmed).
- `TwoFactorProfileScreen` with `TwoFactorProfileLinkLayout` for `UserProfileScreen`; optional main
  menu item (`menu.enabled`).
- `TwoFactorResetLayout` and the `ResetsTwoFactor` trait for `UserEditScreen`, the
  `platform.systems.users.2fa-reset` permission and the `orchid-2fa:reset` command.
- `remember_token` rotation when 2FA is enabled and the `orchid-2fa:rotate-remember-tokens` command.
- E-mail change handling in `HasTwoFactor`: a notice to the old address, the next sign-in confirms
  the new one.
- Events `TwoFactorChallengeSent`, `TwoFactorPassed`, `TwoFactorFailed`, `TwoFactorLockedOut` and an
  optional log subscriber.
- Replaceable notifications (`notification.class`, `notification.email_changed_class`), optional
  queueing.
- English and Russian translations; publish tags `orchid-2fa-config`, `orchid-2fa-migrations`,
  `orchid-2fa-views`, `orchid-2fa-translations`.
- Support for Laravel 11.35+, 12 and 13 with `orchid/platform` ^14.53, PHP 8.2+.

[Unreleased]: https://github.com/nakipelo/orchid-2fa/compare/0.1.1...HEAD
[0.1.1]: https://github.com/nakipelo/orchid-2fa/releases/tag/0.1.1
[0.1.0]: https://github.com/nakipelo/orchid-2fa/releases/tag/0.1.0
