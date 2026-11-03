<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Notifications;

use Carbon\CarbonInterface;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * The e-mail with the one-time code (spec §5.8). Contains the code and its lifetime only:
 * no masked address, IP or user agent.
 *
 * A replacement (`notification.class`) must accept `(string $code, CarbonInterface $expiresAt)`.
 */
class TwoFactorCodeNotification extends Notification
{
    public function __construct(
        public readonly string $code,
        public readonly CarbonInterface $expiresAt,
    ) {}

    /**
     * @return list<string>
     */
    public function via(mixed $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(mixed $notifiable): MailMessage
    {
        $minutes = max(1, (int) ceil(now()->diffInSeconds($this->expiresAt, true) / 60));

        return (new MailMessage)
            ->subject($this->trans('subject'))
            ->greeting($this->trans('greeting'))
            ->line($this->trans('line', ['code' => $this->code]))
            ->line($this->trans('expires', ['minutes' => $minutes]))
            ->line($this->trans('ignore'));
    }

    /**
     * @param  array<string, string|int>  $replace
     */
    protected function trans(string $key, array $replace = []): string
    {
        return (string) __('orchid-2fa::messages.notification.'.$key, $replace);
    }
}
