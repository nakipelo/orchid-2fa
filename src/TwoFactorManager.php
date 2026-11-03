<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Log\LogManager;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Nakipelo\Orchid2FA\Events\TwoFactorChannelChanged;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Notifications\SecurityNotifier;
use Nakipelo\Orchid2FA\Notifications\TwoFactorEmailChangedNotification;
use Nakipelo\Orchid2FA\Notifications\TwoFactorSecurityNotification;
use Nakipelo\Orchid2FA\Policy\TwoFactorPolicy;
use Nakipelo\Orchid2FA\Recovery\RecoveryCodes;
use Nakipelo\Orchid2FA\Support\Orchid;
use Psr\Log\LoggerInterface;
use ReflectionClass;

/**
 * State changes of a user's two-factor authentication: enrollment of a method and disabling
 * (spec 0.2 §4.8, §5.4–§5.8), reset by an administrator (§5.10), e-mail change (§5.11), remember
 * token rotation (§4.5 of 0.1). Who may do what is checked by the callers (screens, commands).
 */
class TwoFactorManager
{
    public function __construct(
        protected Container $container,
        protected Repository $config,
        protected ChallengeManager $challenges,
        protected TwoFactorPolicy $policy,
        protected LogManager $log,
        protected ChannelRegistry $channels,
        protected RecoveryCodes $recoveryCodes,
        protected SecurityNotifier $notifier,
        protected Dispatcher $events,
    ) {}

    /**
     * A method has been enrolled (spec 0.2 §4.8): at the login, in the profile (enabling, switching,
     * rebinding). Writes the channel and `confirmed_at = now()`; `enabled_at = now()` for a voluntary
     * enabling (it stays on a switch or rebind); calls forget() of the previous channel on a switch;
     * signs out of the trusted devices on a switch or rebind; rotates the remember token; issues a new
     * set of recovery codes for a channel that needs them (and removes them otherwise); fires
     * `TwoFactorChannelChanged` and sends the security notice.
     *
     * @param  string  $reason  `TwoFactorChannelChanged::ENROLLED|SWITCHED|REBOUND`
     * @return list<string>|null the plain recovery codes to show once, or null
     */
    public function commitEnrollment(Authenticatable $user, TwoFactorChannel $channel, string $reason, bool $voluntary = false): ?array
    {
        $to = $channel->name();

        [$from, $codes] = $this->transaction(function () use ($user, $channel, $to, $reason, $voluntary): array {
            $record = $this->record($user);
            $from = $record->exists && is_string($record->channel) && $record->channel !== '' ? $record->channel : null;
            $now = now();

            $record->forceFill([
                'channel' => $to,
                'confirmed_at' => $now,
                'enabled_at' => $voluntary && $record->enabled_at === null ? $now : $record->enabled_at,
            ])->save();

            if ($from !== null && $from !== $to) {
                $this->forgetChannelData($user, $from);
            }

            if ($reason === TwoFactorChannelChanged::REBOUND || ($from !== null && $from !== $to)) {
                $this->forgetTrustedDevices($user);
            }

            $this->rotateRememberToken($user);

            if ($channel->needsRecoveryCodes()) {
                return [$from, $this->recoveryCodes->generate($user)];
            }

            $this->recoveryCodes->delete($user);

            return [$from, null];
        });

        $this->channelChanged($user, $from, $to, $reason);

        return $codes;
    }

    /**
     * Voluntary disabling after the confirmation with the current method and the password
     * (spec 0.2 §5.8): `enabled_at = confirmed_at = null`, the trusted devices are invalidated, the
     * driver's data and the recovery codes are erased, the channel becomes the default one (or null),
     * `TwoFactorChannelChanged(disabled)` and the security notice.
     */
    public function disable(Authenticatable $user): void
    {
        $from = $this->transaction(function () use ($user): ?string {
            $from = $this->recordedChannel($user);

            TwoFactorAuthentication::query()
                ->where('user_id', $user->getAuthIdentifier())
                ->update(['enabled_at' => null, 'confirmed_at' => null, 'channel' => $this->channels->initialName()]);

            $this->forgetTrustedDevices($user);

            if ($from !== null) {
                $this->forgetChannelData($user, $from);
            }

            $this->recoveryCodes->delete($user);

            return $from;
        });

        $this->channelChanged($user, $from, null, TwoFactorChannelChanged::DISABLED);
    }

    /**
     * Reset by an administrator (spec §4.8 of 0.1, §5.10 of 0.2): as disabling, plus the active code
     * and all counters are removed and the remember token is rotated. The driver's data are erased
     * when its driver is registered (otherwise only the data of this package, with a warning); the
     * channel becomes `email` when it is allowed, otherwise null (the next login of an enforced user
     * enrolls a method). Fires `TwoFactorChannelChanged(reset)` and sends the security notice.
     */
    public function reset(Authenticatable $user): void
    {
        $from = $this->transaction(function () use ($user): ?string {
            $from = $this->recordedChannel($user);

            TwoFactorAuthentication::query()
                ->where('user_id', $user->getAuthIdentifier())
                ->update([
                    'enabled_at' => null,
                    'confirmed_at' => null,
                    'channel' => $this->channels->isAllowed('email') ? 'email' : null,
                ]);

            $this->forgetTrustedDevices($user);

            if ($from !== null) {
                $this->forgetChannelData($user, $from);
            }

            $this->recoveryCodes->delete($user);
            $this->challenges->clear($user);
            $this->rotateRememberToken($user);

            return $from;
        });

        $this->channelChanged($user, $from, null, TwoFactorChannelChanged::RESET);
    }

    /**
     * Reset every user whose method is `$channel` (spec 0.2 §5.10), e.g. after its driver was
     * removed; the name is not checked against the registry. Each user is a separate reset();
     * a record whose user the guard provider does not return is skipped (`$onSkipped`).
     *
     * @param  (Closure(int|string): void)|null  $onSkipped  called with the user id of a skipped record
     * @return int the number of users reset
     */
    public function resetChannel(string $channel, ?Closure $onSkipped = null): int
    {
        $provider = Orchid::guard()->getProvider();
        $count = 0;

        TwoFactorAuthentication::query()
            ->where('channel', $channel)
            ->chunkById(100, function (Collection $records) use ($provider, $onSkipped, &$count): void {
                foreach ($records as $record) {
                    /** @var TwoFactorAuthentication $record */
                    $user = $provider->retrieveById($record->user_id);

                    if ($user === null) {
                        if ($onSkipped !== null) {
                            $onSkipped($record->user_id);
                        }

                        continue;
                    }

                    $this->reset($user);
                    $count++;
                }
            });

        return $count;
    }

    /**
     * "Sign out of all trusted devices" (spec §4.4, §4.7).
     */
    public function forgetTrustedDevices(Authenticatable $user): void
    {
        TwoFactorAuthentication::bumpTrustedDevicesVersionFor($user->getAuthIdentifier());
    }

    /**
     * Remember cookies issued before carry the old token and stop working (spec §4.5).
     */
    public function rotateRememberToken(Authenticatable $user): void
    {
        Orchid::guard()->getProvider()->updateRememberToken($user, Str::random(60));
    }

    /**
     * `remember_token = null` for all users of the Orchid guard's model, in one query and without
     * model events or timestamps (spec §4.5). Active sessions are not ended.
     *
     * @return int the number of users whose token was cleared
     */
    public function forgetAllRememberTokens(): int
    {
        $model = Orchid::userModel();
        $instance = new $model;
        $column = $instance instanceof Authenticatable ? $instance->getRememberTokenName() : 'remember_token';

        return $instance->newQueryWithoutScopes()->toBase()->whereNotNull($column)->update([$column => null]);
    }

    /**
     * The e-mail address of the user changed (spec §4.9 of 0.1, §5.11 of 0.2):
     * destinationChanged() for the channel `email`, and a user with two-factor authentication gets
     * a notice at the old address. 2FA stays enabled.
     *
     * A failed notice is logged and does not break the save that changed the address.
     */
    public function addressChanged(Authenticatable $user, string $oldAddress): void
    {
        $this->destinationChanged($user, 'email', $oldAddress);

        if ($oldAddress === '' || ! $this->policy->requires($user)) {
            return;
        }

        $email = $this->notifier->emailChannel();

        try {
            $email->notify($oldAddress, $this->makeEmailChangedNotification($email->maskedDestination($user)));
        } catch (DeliveryFailedException $e) {
            $this->logger()->error('nakipelo/orchid-2fa: the e-mail change notice could not be sent.', [
                'user_id' => $user->getAuthIdentifier(),
                'exception' => $e,
            ]);
        }
    }

    /**
     * The destination of a delivery channel changed (spec 0.2 §5.11): the active code is annulled
     * (it was bound to the old destination); the record is no longer confirmed only when its
     * channel is this one (for `email` also a record without a channel), so the next login sends
     * the code to the new destination and confirms it. The method of a user of another channel
     * (e.g. TOTP) and its confirmation are not touched.
     */
    public function destinationChanged(Authenticatable $user, string $channel, string $oldDestination): void
    {
        $this->challenges->annul($user);

        TwoFactorAuthentication::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->whereNotNull('confirmed_at')
            ->where(function (Builder $query) use ($channel): void {
                $query->where('channel', $channel);

                if ($channel === 'email') {
                    $query->orWhereNull('channel');
                }
            })
            ->update(['confirmed_at' => null]);
    }

    /**
     * `confirmed_at = null` for an existing record: the next challenge rotates the remember token
     * and confirms the address again; trusted device cookies are refused (and deleted) from now on
     * (spec §4.5, §4.9, §5.6). Used after an e-mail change and after a sign-in without the second factor.
     */
    public function forgetConfirmation(Authenticatable $user): void
    {
        TwoFactorAuthentication::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->whereNotNull('confirmed_at')
            ->update(['confirmed_at' => null]);
    }

    /**
     * Erase the driver's data of the user (its forget() hook); when the driver is not registered,
     * only the data of this package are reset and a warning is logged (spec 0.2 §5.10).
     */
    protected function forgetChannelData(Authenticatable $user, string $channel): void
    {
        try {
            $driver = $this->channels->has($channel) ? $this->channels->channel($channel) : null;
        } catch (InvalidArgumentException) {
            $driver = null;
        }

        if ($driver === null) {
            $this->logger()->warning(sprintf(
                'nakipelo/orchid-2fa: the two-factor channel [%s] is not registered; its data of the user stay in the tables of its driver.',
                $channel,
            ), ['user_id' => $user->getAuthIdentifier()]);

            return;
        }

        $driver->forget($user);
    }

    protected function channelChanged(Authenticatable $user, ?string $from, ?string $to, string $reason): void
    {
        $this->events->dispatch(new TwoFactorChannelChanged($user, Orchid::guardName(), $from, $to, $reason));

        $this->notifier->send($user, TwoFactorSecurityNotification::CHANNEL_CHANGED, [
            'from' => $from,
            'to' => $to,
            'reason' => $reason,
        ]);
    }

    protected function recordedChannel(Authenticatable $user): ?string
    {
        $channel = TwoFactorAuthentication::query()->where('user_id', $user->getAuthIdentifier())->value('channel');

        return is_string($channel) && $channel !== '' ? $channel : null;
    }

    /**
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    protected function transaction(Closure $callback): mixed
    {
        return (new TwoFactorAuthentication)->getConnection()->transaction($callback);
    }

    protected function logger(): LoggerInterface
    {
        $channel = $this->config->get('orchid-2fa.log.channel');

        return $this->log->channel(is_string($channel) && $channel !== '' ? $channel : null);
    }

    protected function record(Authenticatable $user): TwoFactorAuthentication
    {
        return TwoFactorAuthentication::query()->firstOrNew(['user_id' => $user->getAuthIdentifier()]);
    }

    protected function makeEmailChangedNotification(string $maskedNewAddress): Notification
    {
        $class = $this->config->get('orchid-2fa.notification.email_changed_class', TwoFactorEmailChangedNotification::class);

        $notification = is_string($class) && class_exists($class)
            ? (new ReflectionClass($class))->newInstance($maskedNewAddress)
            : null;

        if (! $notification instanceof Notification) {
            throw new InvalidArgumentException('[orchid-2fa.notification.email_changed_class] must be a notification class.');
        }

        return $notification;
    }
}
