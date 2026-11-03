<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Listeners;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Log\LogManager;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorEvent;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Psr\Log\LoggerInterface;

/**
 * Writes the package events to `log.channel`; subscribed when `log.enabled` (spec §5.7).
 * Never logs the code.
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
            'via' => $event->via,
            'trusted_device_issued' => $event->trustedDeviceIssued,
        ]));
    }

    public function handleFailed(TwoFactorFailed $event): void
    {
        $this->logger()->warning('Two-factor authentication failed.', $this->context($event, [
            'reason' => $event->reason,
        ]));
    }

    public function handleLockedOut(TwoFactorLockedOut $event): void
    {
        $this->logger()->warning('Two-factor authentication locked out.', $this->context($event, [
            'reason' => $event->reason,
            'available_in' => $event->availableIn,
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
