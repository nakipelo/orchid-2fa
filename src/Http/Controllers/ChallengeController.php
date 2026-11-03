<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\View\View;
use Illuminate\Cookie\CookieJar;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\PendingLogin;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\CompletesLogin;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\InteractsWithChallenge;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Support\Orchid;
use Symfony\Component\HttpFoundation\Response;

/**
 * The code step: screen, verification, resend and "sign in as a different user" (spec §4.2, §6).
 *
 * The user is identified only by the pending login in the server session; request
 * parameters never select the user.
 */
class ChallengeController
{
    use CompletesLogin;
    use InteractsWithChallenge;

    public function __construct(
        protected ChallengeManager $challenges,
        protected Dispatcher $events,
        protected Repository $config,
    ) {
        Orchid::redirectAuthenticatedToIndex();
    }

    public function show(Request $request): View|RedirectResponse
    {
        $pending = PendingLogin::fromSession($request->session());

        if ($pending === null) {
            return redirect()->route(Orchid::loginRoute());
        }

        $user = $this->pendingUser($request, $pending);

        if ($user === null) {
            return $this->sessionExpiredRedirect();
        }

        $length = $this->challenges->codeLength();

        return view('orchid-2fa::challenge', [
            'layout' => Orchid::authLayout(),
            'destination' => $this->challenges->channel()->maskedDestination($user),
            'codeLength' => $length,
            'codePattern' => '\d{'.$length.'}',
            'resendAvailableIn' => $this->challenges->sendAvailableIn($user),
            'verifyUrl' => route(Orchid::verifyRoute()),
            'resendUrl' => route(Orchid::resendRoute()),
            'cancelUrl' => route(Orchid::cancelRoute()),
            'error' => $request->session()->get(self::FLASH_ERROR),
            'status' => $request->session()->get(self::FLASH_STATUS),
        ]);
    }

    /**
     * @throws ValidationException
     */
    public function verify(Request $request): Response
    {
        $pending = PendingLogin::fromSession($request->session());
        $user = $pending === null ? null : $this->pendingUser($request, $pending);

        if ($pending === null || $user === null) {
            return $this->sessionExpired($request);
        }

        $request->validate(['code' => 'required|string|max:64']);

        $result = $this->challenges->verify($user, $pending->challengeId, (string) $request->input('code'));

        if ($result !== VerificationResult::Passed) {
            throw ValidationException::withMessages([
                'code' => match ($result) {
                    VerificationResult::Invalid => $this->trans('errors.invalid_code', [
                        'attempts' => $this->challenges->attemptsLeft($user, $pending->challengeId),
                    ]),
                    default => $this->trans('errors.code_expired'),
                },
            ])->redirectTo(route(Orchid::challengeRoute()));
        }

        PendingLogin::forget($request->session());

        $this->confirmDestination($user);

        $this->events->dispatch(new TwoFactorPassed($user, Orchid::guardName(), TwoFactorPassed::VIA_CODE));

        return $this->completeLogin($request, $user, $pending->remember);
    }

    /**
     * @throws ValidationException
     */
    public function resend(Request $request): Response
    {
        $pending = PendingLogin::fromSession($request->session());
        $user = $pending === null ? null : $this->pendingUser($request, $pending);

        if ($pending === null || $user === null) {
            return $this->sessionExpired($request);
        }

        try {
            $challengeId = $this->challenges->issue($user, TwoFactorChallengeSent::CONTEXT_LOGIN);
        } catch (SendLimitExceededException $e) {
            return $this->sendError($request, $this->sendLimitMessage($e->availableIn));
        } catch (DeliveryFailedException) {
            return $this->sendError($request, $this->trans('errors.delivery_failed'));
        }

        $pending->withChallenge($challengeId)->store($request->session());

        if ($request->wantsJson()) {
            return new JsonResponse(['resend_available_in' => $this->challenges->sendAvailableIn($user)]);
        }

        $this->flashStatus($request, $this->trans('challenge.resent'));

        return redirect()->route(Orchid::challengeRoute());
    }

    /**
     * "Sign in as a different user": drop the pending login and Orchid's lock cookie.
     */
    public function cancel(Request $request, CookieJar $cookies): RedirectResponse
    {
        PendingLogin::forget($request->session());

        return redirect()
            ->route(Orchid::loginRoute())
            ->withCookie($cookies->forget(Orchid::lockCookieName()));
    }

    /**
     * The user of a valid pending login; an expired pending login is removed.
     */
    protected function pendingUser(Request $request, PendingLogin $pending): ?Authenticatable
    {
        if ($pending->isExpired($this->pendingTtl())) {
            PendingLogin::forget($request->session());

            return null;
        }

        $user = Orchid::guard()->getProvider()->retrieveById($pending->userId);

        if ($user === null) {
            PendingLogin::forget($request->session());
        }

        return $user;
    }

    /**
     * @throws ValidationException
     */
    protected function sessionExpired(Request $request): Response
    {
        if ($request->wantsJson()) {
            throw ValidationException::withMessages(['code' => $this->trans('errors.session_expired')]);
        }

        return $this->sessionExpiredRedirect();
    }

    protected function sessionExpiredRedirect(): RedirectResponse
    {
        return redirect()
            ->route(Orchid::loginRoute())
            ->withErrors(['email' => $this->trans('errors.session_expired')]);
    }

    /**
     * @throws ValidationException
     */
    protected function sendError(Request $request, string $message): Response
    {
        if ($request->wantsJson()) {
            throw ValidationException::withMessages(['code' => $message]);
        }

        $this->flashError($request, $message);

        return redirect()->route(Orchid::challengeRoute());
    }

    /**
     * A successful code confirms the current address (spec §4.2, §4.9).
     */
    protected function confirmDestination(Authenticatable $user): void
    {
        $record = TwoFactorAuthentication::query()->firstOrNew(['user_id' => $user->getAuthIdentifier()]);

        if ($record->confirmed_at === null) {
            $record->confirmed_at = now();
            $record->save();
        }
    }

    protected function pendingTtl(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.pending_ttl', 600));
    }
}
