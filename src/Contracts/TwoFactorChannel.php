<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Contracts;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;

/**
 * Delivery of the second factor (spec §5.2).
 *
 * Generation, storage and verification of one-time codes belong to the
 * ChallengeManager; a channel only knows where and how to deliver a code.
 */
interface TwoFactorChannel
{
    /**
     * Channel name, e.g. `email`.
     */
    public function name(): string;

    /**
     * Whether the user has a destination for this channel (e.g. an e-mail address).
     */
    public function isAvailableFor(Authenticatable $user): bool;

    /**
     * The raw destination the code is bound to.
     */
    public function destination(Authenticatable $user): string;

    /**
     * The destination as shown to the user, e.g. `e***@gmail.com`.
     */
    public function maskedDestination(Authenticatable $user): string;

    /**
     * @throws DeliveryFailedException
     */
    public function send(Authenticatable $user, string $code, CarbonInterface $expiresAt): void;
}
