# nakipelo/orchid-2fa

> Draft (stages 1–2 of `docs/SPEC.md`). Installation and usage docs come with the 0.1.0 release.

Second factor (one-time e-mail code) for the [Orchid](https://orchid.software) admin panel password login.

## Requirements

- PHP 8.2+ (Laravel 13 requires PHP 8.3+)
- Laravel 11.35+ / 12 / 13
- `orchid/platform` ^14.53
- The Orchid guard (`platform.guard`) must be a session guard.

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

## Behaviour notes

### `platform.auth = false`

With `platform.auth` set to `false`, Orchid does not register its login routes and this package
does not install the two-factor login (`POST login`): your own login must take care of the second
factor. The package logs a warning about this once per boot, but only in the `local` and `testing`
environments; in production (and any other environment) no warning is written.

## Development

```bash
composer install
composer serve      # workbench: Orchid at http://127.0.0.1:8000/admin
composer check      # pint --test, adapter check, larastan, pest
```

Workbench test administrator (seeded by `composer serve` / `composer build`):

| Login | Password |
|---|---|
| `admin@example.com` | `password` |

Individual checks: `composer test`, `composer analyse` (Larastan level 8), `composer lint` (Pint),
`composer check-adapter` (`platform.`, `platform::` and `Orchid\` appear in `src/` only in
`src/Support/Orchid.php`).

## License

MIT
