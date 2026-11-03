# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First release, planned as 0.1.0.

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

[Unreleased]: https://github.com/nakipelo/orchid-2fa/commits/main
