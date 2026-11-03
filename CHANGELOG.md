# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
