<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\TrustedDevice;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Cookie\CookieJar;
use Illuminate\Http\Request;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Support\Orchid;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * The trusted device cookie (spec §4.4, §5.6).
 *
 * One cookie per user and guard: `{trusted_devices.cookie}_{hmac(guard|user_id)[0..16]}`. The value
 * is `encryptString(json{uid, g, v, exp})` — encrypted with a MAC by the package itself, independent
 * of `EncryptCookies` (which encrypts it once more when the cookie passes through the `web` group).
 */
class TrustedDeviceCookie
{
    public function __construct(
        protected Repository $config,
        protected StringEncrypter $encrypter,
        protected CookieJar $cookies,
    ) {}

    /**
     * `trusted_devices.enabled`: the checkbox is shown and cookies are issued and accepted.
     * When disabled, existing cookies are ignored (not deleted).
     */
    public function isEnabled(): bool
    {
        return (bool) $this->config->get('orchid-2fa.trusted_devices.enabled', true);
    }

    public function lifetimeDays(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.trusted_devices.lifetime_days', 30));
    }

    /**
     * The cookie name of the user. The user id is not readable from it, and several
     * accounts in one browser do not overwrite each other's cookies.
     */
    public function name(int|string $userId): string
    {
        $prefix = (string) $this->config->get('orchid-2fa.trusted_devices.cookie', 'orchid_2fa_trusted');
        $hash = hash_hmac('sha256', Orchid::guardName().'|'.$userId, $this->key());

        return $prefix.'_'.substr($hash, 0, 16);
    }

    /**
     * Queue the cookie for the user and the current trusted devices version of the record.
     */
    public function issue(Authenticatable $user, TwoFactorAuthentication $record): void
    {
        $this->cookies->queue($this->make($user->getAuthIdentifier(), $record->trusted_devices_version));
    }

    public function make(int|string $userId, int $version): Cookie
    {
        $expires = now()->addDays($this->lifetimeDays());

        $value = $this->encrypter->encryptString((string) json_encode([
            'uid' => $userId,
            'g' => Orchid::guardName(),
            'v' => $version,
            'exp' => $expires->getTimestamp(),
        ]));

        return $this->cookie($this->name($userId), $value, $expires->getTimestamp());
    }

    /**
     * Whether the request carries a valid trusted device cookie of the user who has just passed
     * the password: decrypts, the user id and the guard match, the version equals the record's
     * `trusted_devices_version`, not expired, the current address is confirmed (spec §4.4, §5.6).
     *
     * A present but invalid cookie is queued for deletion.
     */
    public function passes(Request $request, Authenticatable $user, ?TwoFactorAuthentication $record): bool
    {
        if (! $this->isEnabled()) {
            return false;
        }

        $name = $this->name($user->getAuthIdentifier());

        if (! $request->cookies->has($name)) {
            return false;
        }

        if ($this->isValid($request->cookie($name), $user, $record)) {
            return true;
        }

        $this->cookies->queue($this->forget($user->getAuthIdentifier()));

        return false;
    }

    public function forget(int|string $userId): Cookie
    {
        return $this->cookie($this->name($userId), '', now()->subYears(5)->getTimestamp());
    }

    protected function isValid(#[\SensitiveParameter] mixed $value, Authenticatable $user, ?TwoFactorAuthentication $record): bool
    {
        // No record: no cookie was ever issued for this record. Not confirmed: the address changed
        // or the user signed in without the second factor after the cookie was issued (spec §4.5, §4.9).
        if ($record === null || ! $record->exists || $record->confirmed_at === null || ! is_string($value) || $value === '') {
            return false;
        }

        try {
            $payload = json_decode($this->encrypter->decryptString($value), true);
        } catch (DecryptException) {
            return false;
        }

        if (! is_array($payload)) {
            return false;
        }

        $uid = $payload['uid'] ?? null;

        return (is_int($uid) || is_string($uid))
            && (string) $uid === (string) $user->getAuthIdentifier()
            && ($payload['g'] ?? null) === Orchid::guardName()
            && ($payload['v'] ?? null) === $record->trusted_devices_version
            && is_int($payload['exp'] ?? null)
            && $payload['exp'] > now()->getTimestamp();
    }

    /**
     * HttpOnly, SameSite=Lax, path = the Orchid prefix. `Secure` follows `session.secure`;
     * when it is not set (null), Symfony applies the request scheme when sending the response.
     */
    protected function cookie(string $name, #[\SensitiveParameter] string $value, int $expires): Cookie
    {
        $secure = $this->config->get('session.secure');
        $domain = $this->config->get('session.domain');

        return new Cookie(
            $name,
            $value,
            $expires,
            Orchid::pathPrefix(),
            is_string($domain) && $domain !== '' ? $domain : null,
            $secure === null ? null : (bool) $secure,
            true,
            false,
            Cookie::SAMESITE_LAX,
        );
    }

    protected function key(): string
    {
        return (string) $this->config->get('app.key');
    }
}
