<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Log\LogManager;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\EmailChannel;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Notifications\TwoFactorEmailChangedNotification;
use Nakipelo\Orchid2FA\Policy\TwoFactorPolicy;
use Nakipelo\Orchid2FA\Support\Orchid;
use ReflectionClass;

/**
 * State changes of a user's two-factor authentication: voluntary enabling and disabling
 * (spec §4.7), reset by an administrator (§4.8), e-mail change (§4.9), remember token
 * rotation (§4.5). Who may do what is checked by the callers (screens, commands).
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
    ) {}

    /**
     * Voluntary enabling after a correct code: `enabled_at = confirmed_at = now()`, the channel,
     * and the remember token is rotated so that older remember cookies stop working (spec §4.5, §4.7).
     *
     * `$channel` is the channel whose code confirmed the enabling; by default the user's channel.
     * Becomes `commitEnrollment()` in stage 2 of 0.2 (spec 0.2 §4.8).
     */
    public function enable(Authenticatable $user, ?TwoFactorChannel $channel = null): TwoFactorAuthentication
    {
        $record = $this->record($user);
        $now = now();

        $record->forceFill([
            'enabled_at' => $now,
            'confirmed_at' => $now,
            'channel' => ($channel ?? $this->channels->for($user))?->name() ?? $this->channels->defaultName(),
        ])->save();

        $this->rotateRememberToken($user);

        return $record;
    }

    /**
     * Voluntary disabling after a correct code: `enabled_at = confirmed_at = null` and
     * the trusted devices are invalidated (spec §4.7).
     */
    public function disable(Authenticatable $user): void
    {
        $this->clearRecord($user);
    }

    /**
     * Reset by an administrator (spec §4.8): as disabling, plus the active code and the
     * counters are removed and the remember token is rotated, so the remember cookies of the
     * user stop working. An enforced user gets a code to the current address on the next login.
     */
    public function reset(Authenticatable $user): void
    {
        $this->clearRecord($user);
        $this->challenges->clear($user);
        $this->rotateRememberToken($user);
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

        $email = $this->emailChannel();

        try {
            $email->notify($oldAddress, $this->makeEmailChangedNotification($email->maskedDestination($user)));
        } catch (DeliveryFailedException $e) {
            $channel = $this->config->get('orchid-2fa.log.channel');

            $this->log->channel(is_string($channel) && $channel !== '' ? $channel : null)
                ->error('nakipelo/orchid-2fa: the e-mail change notice could not be sent.', [
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

    protected function clearRecord(Authenticatable $user): void
    {
        TwoFactorAuthentication::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->update(['enabled_at' => null, 'confirmed_at' => null]);

        $this->forgetTrustedDevices($user);
    }

    /**
     * The channel `email` of the registry, the same one that sends the codes; the base
     * EmailChannel if it is not registered or does not extend EmailChannel (the notice is always
     * an e-mail, spec 0.2 §4.8).
     */
    protected function emailChannel(): EmailChannel
    {
        try {
            $channel = $this->channels->has('email') ? $this->channels->channel('email') : null;
        } catch (InvalidArgumentException) {
            $channel = null;
        }

        return $channel instanceof EmailChannel ? $channel : $this->container->make(EmailChannel::class);
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
