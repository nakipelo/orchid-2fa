<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Http\Controllers\Concerns;

use Illuminate\Http\Request;

/**
 * Messages of the code step.
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

    protected function flashError(Request $request, string $message): void
    {
        $request->session()->flash(self::FLASH_ERROR, $message);
    }

    protected function flashStatus(Request $request, string $message): void
    {
        $request->session()->flash(self::FLASH_STATUS, $message);
    }
}
