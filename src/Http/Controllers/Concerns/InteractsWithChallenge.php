<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Http\Controllers\Concerns;

use Illuminate\Http\Request;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;

/**
 * Messages of the code step, the enrollment and the profile confirmations.
 */
trait InteractsWithChallenge
{
    public const FLASH_ERROR = 'orchid-2fa.error';

    public const FLASH_STATUS = 'orchid-2fa.status';

    /**
     * @param  array<string, string|int>  $replace
     */
    protected function trans(string $key, array $replace = []): string
    {
        return (string) __('orchid-2fa::messages.'.$key, $replace);
    }

    protected function sendLimitMessage(int $availableIn): string
    {
        return $this->trans('errors.send_limit', ['minutes' => max(1, (int) ceil($availableIn / 60))]);
    }

    /**
     * The message of a lockout of the user limits ("try again in N min / N h"), or null for the
     * lockout of one challenge.
     *
     * @param  array{reason: string, available_in: int}|null  $lockout
     */
    protected function userLockoutMessage(?array $lockout): ?string
    {
        return match ($lockout['reason'] ?? null) {
            TwoFactorLockedOut::USER_ATTEMPTS_EXCEEDED => $this->trans('errors.too_many_attempts_wait', [
                'minutes' => max(1, (int) ceil($lockout['available_in'] / 60)),
            ]),
            TwoFactorLockedOut::USER_DAILY_ATTEMPTS_EXCEEDED => $this->trans('errors.too_many_attempts_today', [
                'hours' => max(1, (int) ceil($lockout['available_in'] / 3600)),
            ]),
            default => null,
        };
    }

    protected function flashError(Request $request, string $message): void
    {
        $request->session()->flash(self::FLASH_ERROR, $message);
    }

    protected function flashStatus(Request $request, string $message): void
    {
        $request->session()->flash(self::FLASH_STATUS, $message);
    }
}
