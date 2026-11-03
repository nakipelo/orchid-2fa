<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Recovery;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Contracts\Session\Session;
use Nakipelo\Orchid2FA\Models\TwoFactorRecoveryCode;

/**
 * Recovery codes of the user (spec 0.2 §4.7): `recovery_codes.count` codes `xxxx-xxxx` from an
 * alphabet without 0/o/1/l/i, `random_int`; only hashes of the application hasher are stored
 * (they survive an `app.key` rotation); a code is consumed atomically.
 *
 * Attempts are counted by the ChallengeManager (spec 0.2 §4.4), not here.
 *
 * @internal
 */
class RecoveryCodes
{
    public const ALPHABET = '23456789abcdefghjkmnpqrstuvwxyz';

    /**
     * The plain codes to show once, in the server session only (spec 0.2 §4.7), bound to the user.
     */
    public const SESSION_KEY = 'orchid-2fa.recovery_codes';

    public function __construct(
        protected Hasher $hasher,
        protected Repository $config,
    ) {}

    /**
     * A new set replacing the old one; the plain codes are returned once and kept nowhere.
     *
     * @return list<string>
     */
    public function generate(Authenticatable $user): array
    {
        $userId = $user->getAuthIdentifier();
        $codes = [];

        for ($i = 0, $count = $this->count(); $i < $count; $i++) {
            $codes[] = $this->randomCode();
        }

        TwoFactorRecoveryCode::query()->where('user_id', $userId)->delete();

        $now = now();

        TwoFactorRecoveryCode::query()->insert(array_map(fn (string $code): array => [
            'user_id' => $userId,
            'code_hash' => $this->hasher->make($this->normalize($code)),
            'used_at' => null,
            'created_at' => $now,
        ], $codes));

        return $codes;
    }

    /**
     * Consume the code if it is one of the unused codes of the user. Input is case-insensitive,
     * spaces and dashes are ignored. Only the first of parallel requests consumes a code.
     */
    public function consume(Authenticatable $user, string $code): bool
    {
        $code = $this->normalize($code);

        if ($code === '' || strlen($code) > 64) {
            return false;
        }

        $unused = TwoFactorRecoveryCode::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->whereNull('used_at')
            ->get(['id', 'code_hash']);

        foreach ($unused as $row) {
            if ($this->hasher->check($code, $row->code_hash)) {
                return TwoFactorRecoveryCode::query()
                    ->whereKey($row->id)
                    ->whereNull('used_at')
                    ->update(['used_at' => now()]) === 1;
            }
        }

        return false;
    }

    /**
     * Keep the plain codes in the session until the user confirms "I have saved the codes".
     *
     * @param  list<string>  $codes
     */
    public static function keepForDisplay(Session $session, Authenticatable $user, array $codes): void
    {
        $session->put(self::SESSION_KEY, ['user_id' => $user->getAuthIdentifier(), 'codes' => $codes]);
    }

    /**
     * The plain codes kept for the user, if any.
     *
     * @return list<string>|null
     */
    public static function forDisplay(Session $session, Authenticatable $user): ?array
    {
        $data = $session->get(self::SESSION_KEY);

        if (! is_array($data)
            || ! (is_int($data['user_id'] ?? null) || is_string($data['user_id'] ?? null))
            || (string) $data['user_id'] !== (string) $user->getAuthIdentifier()
            || ! is_array($data['codes'] ?? null)) {
            return null;
        }

        return array_values(array_filter($data['codes'], 'is_string'));
    }

    public static function forgetDisplay(Session $session): void
    {
        $session->forget(self::SESSION_KEY);
    }

    public function remaining(Authenticatable $user): int
    {
        return TwoFactorRecoveryCode::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->whereNull('used_at')
            ->count();
    }

    /**
     * Whether the user has a set (used codes included).
     */
    public function exists(Authenticatable $user): bool
    {
        return TwoFactorRecoveryCode::query()->where('user_id', $user->getAuthIdentifier())->exists();
    }

    public function delete(Authenticatable $user): void
    {
        TwoFactorRecoveryCode::query()->where('user_id', $user->getAuthIdentifier())->delete();
    }

    public function count(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.recovery_codes.count', 8));
    }

    public function warnAt(): int
    {
        return max(0, (int) $this->config->get('orchid-2fa.recovery_codes.warn_at', 2));
    }

    protected function randomCode(): string
    {
        $max = strlen(self::ALPHABET) - 1;
        $code = '';

        for ($i = 0; $i < 8; $i++) {
            $code .= self::ALPHABET[random_int(0, $max)];
        }

        return substr($code, 0, 4).'-'.substr($code, 4);
    }

    protected function normalize(string $code): string
    {
        return mb_strtolower((string) preg_replace('/[\s-]+/u', '', $code));
    }
}
