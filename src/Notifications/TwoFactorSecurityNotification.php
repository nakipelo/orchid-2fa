<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * A security notice to the address of the user (spec 0.2 §8.3): a recovery code was used, the
 * method changed (also disabled and reset) or someone is guessing the code. No codes, secrets or
 * addresses.
 *
 * A replacement (`notification.security_class`) must accept `(string $event, array $context)`.
 */
class TwoFactorSecurityNotification extends Notification
{
    public const RECOVERY_CODE_USED = 'recovery_code_used';

    public const CHANNEL_CHANGED = 'channel_changed';

    public const ATTEMPTS_EXCEEDED = 'attempts_exceeded';

    /**
     * @param  array<string, mixed>  $context  `recovery_code_used`: remaining, context;
     *                                         `channel_changed`: from, to, reason;
     *                                         `attempts_exceeded`: channel, limit (window|day), available_in
     */
    public function __construct(
        public readonly string $event,
        public readonly array $context = [],
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
            ->subject($this->trans($this->event.'.subject'))
            ->greeting($this->trans('greeting'));

        foreach ($this->lines() as $line) {
            $message->line($line);
        }

        return $message->line($this->trans($this->event === self::ATTEMPTS_EXCEEDED ? 'change_password' : 'ignore'));
    }

    /**
     * @return list<string>
     */
    protected function lines(): array
    {
        return match ($this->event) {
            self::RECOVERY_CODE_USED => [
                $this->trans('recovery_code_used.line'),
                $this->trans('recovery_code_used.remaining', ['count' => $this->int('remaining')]),
            ],
            self::CHANNEL_CHANGED => [$this->trans('channel_changed.'.$this->reasonKey(), [
                'from' => $this->channelLabel('from'),
                'to' => $this->channelLabel('to'),
            ])],
            self::ATTEMPTS_EXCEEDED => [$this->trans('attempts_exceeded.line')],
            default => [],
        };
    }

    protected function reasonKey(): string
    {
        $reason = $this->context['reason'] ?? null;

        return in_array($reason, ['enrolled', 'switched', 'rebound', 'disabled', 'reset'], true) ? $reason : 'switched';
    }

    protected function channelLabel(string $key): string
    {
        $name = $this->context[$key.'_label'] ?? $this->context[$key] ?? null;

        return is_string($name) && $name !== '' ? $name : '—';
    }

    protected function int(string $key): int
    {
        $value = $this->context[$key] ?? 0;

        return is_int($value) ? $value : 0;
    }

    /**
     * @param  array<string, string|int>  $replace
     */
    protected function trans(string $key, array $replace = []): string
    {
        return (string) __('orchid-2fa::messages.security.'.$key, $replace);
    }
}
