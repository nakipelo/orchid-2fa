<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * Sent to the old address when the e-mail of a user with two-factor authentication changes
 * (spec §4.9, §5.8). Contains the new address masked only.
 *
 * A replacement (`notification.email_changed_class`) must accept `(string $maskedNewAddress)`.
 */
class TwoFactorEmailChangedNotification extends Notification
{
    public function __construct(
        public readonly string $maskedNewAddress,
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
        $message = (new MailMessage)
            ->subject($this->trans('subject'))
            ->greeting($this->trans('greeting'));

        $message->line($this->maskedNewAddress !== ''
            ? $this->trans('line', ['address' => $this->maskedNewAddress])
            : $this->trans('line_removed'));

        return $message->line($this->trans('ignore'));
    }

    /**
     * @param  array<string, string|int>  $replace
     */
    protected function trans(string $key, array $replace = []): string
    {
        return (string) __('orchid-2fa::messages.email_changed.'.$key, $replace);
    }
}
