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
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\PendingLogin;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\CompletesLogin;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\InteractsWithChallenge;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Policy\TwoFactorPolicy;
use Nakipelo\Orchid2FA\Support\Orchid;
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
            return $this->completeLogin($request, $user, $remember);
        }

        return $this->startChallenge($request, $user, $remember);
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

    protected function startChallenge(Request $request, Authenticatable $user, bool $remember): Response
    {
        $this->ensureRecord($user);

        $request->session()->regenerate();

        $challengeId = $this->challenges->activeChallenge($user);

        if ($challengeId === null) {
            try {
                $challengeId = $this->challenges->issue($user, TwoFactorChallengeSent::CONTEXT_LOGIN);
            } catch (SendLimitExceededException $e) {
                $this->flashError($request, $this->sendLimitMessage($e->availableIn));
            } catch (DeliveryFailedException) {
                $this->flashError($request, $this->trans('errors.delivery_failed'));
            }
        }

        // Without a sent code the pending login still lets the user resend within the limits (spec §4.10).
        (new PendingLogin(
            $user->getAuthIdentifier(),
            $remember,
            now()->getTimestamp(),
            $challengeId ?? Str::random(40),
        ))->store($request->session());

        $url = route(Orchid::challengeRoute());

        return $request->wantsJson()
            ? new JsonResponse(['two_factor' => true, 'redirect' => $url])
            : redirect()->to($url);
    }

    /**
     * An enforced user gets the record lazily, on the first challenge. Creating it rotates the
     * remember token, so remember cookies issued before 2FA became required stop working (spec §4.5).
     */
    protected function ensureRecord(Authenticatable $user): void
    {
        $record = TwoFactorAuthentication::query()->createOrFirst(['user_id' => $user->getAuthIdentifier()]);

        if ($record->wasRecentlyCreated) {
            Orchid::guard()->getProvider()->updateRememberToken($user, Str::random(60));
        }
    }
}
