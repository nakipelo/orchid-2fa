<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Http\Controllers;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\PendingLogin;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\UserMethod;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\CompletesLogin;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\InteractsWithChallenge;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Policy\TwoFactorPolicy;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;
use Nakipelo\Orchid2FA\TwoFactorManager;
use Symfony\Component\HttpFoundation\Response;

/**
 * Replaces Orchid's `POST login` (spec §4.1–4.3, §5.3).
 *
 * The password is checked with `SessionGuard::validate()`, which logs nobody in. Users who
 * do not need the second factor are logged in right away, exactly as Orchid does it; the
 * others get a pending login in the session and a code.
 */
class LoginController
{
    use CompletesLogin;
    use InteractsWithChallenge;

    public function __construct(
        protected TwoFactorPolicy $policy,
        protected ChallengeManager $challenges,
        protected Dispatcher $events,
        protected Repository $config,
        protected TrustedDeviceCookie $trustedDevices,
        protected TwoFactorManager $manager,
        protected ChannelRegistry $channels,
    ) {
        Orchid::redirectAuthenticatedToIndex();
    }

    /**
     * @throws ValidationException
     */
    public function login(Request $request): Response
    {
        $request->validate([
            'email' => 'required|string',
            'password' => 'required|string',
        ]);

        /** @var array{email: string, password: string} $credentials */
        $credentials = $request->only(['email', 'password']);
        $remember = $request->boolean('remember');

        $user = $this->validateCredentials($credentials, $remember);

        PendingLogin::forget($request->session());

        if (! $this->policy->requires($user)) {
            // A remember cookie issued now did not pass the second factor: the next challenge
            // has to rotate the remember token (spec §4.5).
            $this->manager->forgetConfirmation($user);

            return $this->completeLogin($request, $user, $remember);
        }

        $method = $this->channels->methodFor($user);

        // The driver of the user's method is gone, or no channel is allowed: no login (spec 0.2 §4.3, §4.5).
        if ($method->state === UserMethod::UNAVAILABLE || $this->channels->allowed() === []) {
            $this->failClosed($user, $method);
        }

        // A trusted device replaces the code, never the password (spec §4.4); not the enrollment
        // of a method the user does not have yet (spec 0.2 §5.4).
        if ($method->state === UserMethod::ACTIVE
            && $this->trustedDevices->passes($request, $user, $this->policy->record($user))) {
            $this->events->dispatch(new TwoFactorPassed(
                $user,
                Orchid::guardName(),
                TwoFactorPassed::VIA_TRUSTED_DEVICE,
                false,
                $method->channel?->name() ?? $this->channels->defaultName(),
            ));

            return $this->completeLogin($request, $user, $remember);
        }

        if ($method->state === UserMethod::NONE) {
            return $this->startEnrollment($request, $user, $remember);
        }

        return $this->startChallenge($request, $user, $remember);
    }

    /**
     * No method to pass the second factor with (spec 0.2 §4.5 item 3): the login fails closed with
     * an error, without a pending login.
     *
     * @throws ValidationException
     */
    protected function failClosed(Authenticatable $user, UserMethod $method): never
    {
        $channel = $method->recorded ?? $this->channels->defaultName();

        $logChannel = $this->config->get('orchid-2fa.log.channel');
        Log::channel(is_string($logChannel) && $logChannel !== '' ? $logChannel : null)
            ->error('nakipelo/orchid-2fa: the two-factor method of the user is not available, the login is refused.', [
                'user_id' => $user->getAuthIdentifier(),
                'channel' => $channel,
                'allowed' => $this->channels->allowed(),
            ]);

        $this->events->dispatch(new TwoFactorFailed($user, Orchid::guardName(), TwoFactorFailed::CHANNEL_UNAVAILABLE, $channel));

        throw ValidationException::withMessages(['email' => $this->trans('errors.channel_unavailable')]);
    }

    /**
     * The user needs the second factor but has no method: enrollment at the login, protected by
     * the password only (spec 0.2 §5.4 A).
     */
    protected function startEnrollment(Request $request, Authenticatable $user, bool $remember): Response
    {
        $this->ensureRecord($user);

        $request->session()->regenerate();

        PendingLogin::forEnrollment($user, $remember)->store($request->session());

        $url = route(Orchid::enrollRoute());

        return $request->wantsJson()
            ? new JsonResponse(['two_factor' => true, 'enroll' => true, 'redirect' => $url])
            : redirect()->to($url);
    }

    /**
     * `validate()` instead of `attempt()`: the same checks without logging in. `validate()` neither
     * fires Attempting/Failed nor rehashes the password, so this is done here (spec §4.1).
     *
     * @param  array{email: string, password: string}  $credentials
     *
     * @throws ValidationException
     */
    protected function validateCredentials(array $credentials, bool $remember): Authenticatable
    {
        $guard = Orchid::guard();

        $this->events->dispatch(new Attempting(Orchid::guardName(), $credentials, $remember));

        $user = $guard->validate($credentials) ? $guard->getLastAttempted() : null;

        if ($user === null) {
            $this->events->dispatch(new Failed(Orchid::guardName(), $guard->getLastAttempted(), $credentials));

            throw ValidationException::withMessages([
                'email' => Orchid::failedLoginMessage(),
            ]);
        }

        // As SessionGuard::attempt() does: the password is not available after the code step.
        if ($this->config->get('hashing.rehash_on_login', true)) {
            $guard->getProvider()->rehashPasswordIfRequired($user, $credentials);
        }

        return $user;
    }

    /**
     * The code step with the channel of the user (spec 0.2 §4.5): an active code is reused,
     * otherwise a new one is sent.
     */
    protected function startChallenge(Request $request, Authenticatable $user, bool $remember): Response
    {
        $this->ensureRecord($user);

        $request->session()->regenerate();

        $channel = $this->challenges->channelFor($user);
        $challenge = null;
        $error = null;

        try {
            $challenge = $this->challenges->start($user, TwoFactorChallengeSent::CONTEXT_LOGIN, $channel);
        } catch (SendLimitExceededException $e) {
            $error = $this->sendLimitMessage($e->availableIn);
        } catch (DeliveryFailedException) {
            $error = $this->trans('errors.delivery_failed');
        }

        if ($error !== null) {
            $this->flashError($request, $error);
        }

        // Without a sent code the pending login still lets the user resend within the limits (spec §4.10).
        PendingLogin::for($user, $remember, $challenge->id ?? Str::random(40), $channel->name())->store($request->session());

        $url = route(Orchid::challengeRoute());

        if (! $request->wantsJson()) {
            return redirect()->to($url);
        }

        // Still 200: the password is correct and the code step has started; the client goes on
        // to the code step, where it can resend once `resend_available_in` is over (spec §4.2).
        return new JsonResponse(['two_factor' => true, 'redirect' => $url] + ($error === null ? [] : [
            'error' => $error,
            'resend_available_in' => $this->challenges->sendAvailableIn($user, $channel),
        ]));
    }

    /**
     * An enforced user gets the record lazily, on the first challenge (spec §4.7).
     *
     * The remember token is rotated when the record is created or not confirmed (`confirmed_at`
     * is null): remember cookies issued before the user had to pass the second factor (a new
     * record, after disabling, an admin reset, an e-mail change or a sign-in without the second
     * factor, which drops the confirmation) stop working. A confirmed user keeps the remember
     * cookies issued after the code (spec §4.5).
     *
     * A new record gets the default channel when it is allowed, otherwise none (spec 0.2 §4.9).
     */
    protected function ensureRecord(Authenticatable $user): void
    {
        $record = TwoFactorAuthentication::query()->createOrFirst(
            ['user_id' => $user->getAuthIdentifier()],
            ['channel' => $this->channels->initialName()],
        );

        if ($record->wasRecentlyCreated || $record->confirmed_at === null) {
            $this->manager->rotateRememberToken($user);
        }
    }
}
