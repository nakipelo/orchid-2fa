<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Listeners;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Log\LogManager;
use Nakipelo\Orchid2FA\Events\RecoveryCodesRegenerated;
use Nakipelo\Orchid2FA\Events\RecoveryCodeUsed;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorChannelChanged;
use Nakipelo\Orchid2FA\Events\TwoFactorEvent;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Psr\Log\LoggerInterface;

/**
 * Writes the package events to `log.channel`; subscribed when `log.enabled` (spec §5.7, 0.2 §8.2).
 * Never logs codes, recovery codes or secrets.
 */
class LogTwoFactorEvents
{
    public function __construct(
        protected LogManager $log,
        protected Repository $config,
    ) {}

    /**
     * @return array<class-string, string>
     */
    public function subscribe(): array
    {
        return [
            TwoFactorChallengeSent::class => 'handleChallengeSent',
            TwoFactorPassed::class => 'handlePassed',
            TwoFactorFailed::class => 'handleFailed',
            TwoFactorLockedOut::class => 'handleLockedOut',
            TwoFactorChannelChanged::class => 'handleChannelChanged',
            RecoveryCodeUsed::class => 'handleRecoveryCodeUsed',
            RecoveryCodesRegenerated::class => 'handleRecoveryCodesRegenerated',
        ];
    }

    public function handleChallengeSent(TwoFactorChallengeSent $event): void
    {
        $this->logger()->info('Two-factor code sent.', $this->context($event, [
            'channel' => $event->channel,
            'destination' => $event->maskedDestination,
            'context' => $event->context,
        ]));
    }

    public function handlePassed(TwoFactorPassed $event): void
    {
        $this->logger()->info('Two-factor authentication passed.', $this->context($event, [
            'channel' => $event->channel,
            'via' => $event->via,
            'trusted_device_issued' => $event->trustedDeviceIssued,
        ]));
    }

    public function handleFailed(TwoFactorFailed $event): void
    {
        $this->logger()->warning('Two-factor authentication failed.', $this->context($event, [
            'channel' => $event->channel,
            'reason' => $event->reason,
        ]));
    }

    public function handleLockedOut(TwoFactorLockedOut $event): void
    {
        $this->logger()->warning('Two-factor authentication locked out.', $this->context($event, [
            'channel' => $event->channel,
            'reason' => $event->reason,
            'available_in' => $event->availableIn,
        ]));
    }

    public function handleChannelChanged(TwoFactorChannelChanged $event): void
    {
        $this->logger()->info('Two-factor method changed.', $this->context($event, [
            'from' => $event->from,
            'to' => $event->to,
            'reason' => $event->reason,
        ]));
    }

    public function handleRecoveryCodeUsed(RecoveryCodeUsed $event): void
    {
        $this->logger()->warning('Two-factor recovery code used.', $this->context($event, [
            'channel' => $event->channel,
            'remaining' => $event->remaining,
            'context' => $event->context,
        ]));
    }

    public function handleRecoveryCodesRegenerated(RecoveryCodesRegenerated $event): void
    {
        $this->logger()->info('Two-factor recovery codes regenerated.', $this->context($event, [
            'channel' => $event->channel,
            'count' => $event->count,
        ]));
    }

    /**
     * @param  array<string, mixed>  $extra
     * @return array<string, mixed>
     */
    protected function context(TwoFactorEvent $event, array $extra): array
    {
        return ['user_id' => $event->user->getAuthIdentifier(), 'guard' => $event->guard] + $extra;
    }

    protected function logger(): LoggerInterface
    {
        $channel = $this->config->get('orchid-2fa.log.channel');

        return $this->log->channel(is_string($channel) && $channel !== '' ? $channel : null);
    }
}
