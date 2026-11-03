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
use Nakipelo\Orchid2FA\Channels\DeliveryChannel;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\CompletesLogin;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\InteractsWithChallenge;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;
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
        protected TrustedDeviceCookie $trustedDevices,
    ) {
        Orchid::redirectAuthenticatedToIndex();
    }

    public function show(Request $request): View|RedirectResponse
    {
        if (PendingLogin::fromSession($request->session()) === null) {
            return redirect()->route(Orchid::loginRoute());
        }

        $resolved = $this->resolvePending($request);

        if (is_string($resolved)) {
            return $this->sessionExpiredRedirect($resolved);
        }

        [, $user] = $resolved;

        $channel = $this->challenges->channelFor($user);
        $input = $channel->codeInput();

        return view('orchid-2fa::challenge', [
            'layout' => Orchid::authLayout(),
            'destination' => $channel instanceof DeliveryChannel ? $channel->maskedDestination($user) : '',
            'codeLength' => $input->length,
            'codePattern' => $input->pattern,
            'resendAvailableIn' => $this->challenges->sendAvailableIn($user, $channel),
            'verifyUrl' => route(Orchid::verifyRoute()),
            'resendUrl' => route(Orchid::resendRoute()),
            'cancelUrl' => route(Orchid::cancelRoute()),
            'trustDevice' => $this->trustedDevices->isEnabled(),
            'trustDeviceDays' => $this->trustedDevices->lifetimeDays(),
            'error' => $request->session()->get(self::FLASH_ERROR),
            'status' => $request->session()->get(self::FLASH_STATUS),
        ]);
    }

    /**
     * @throws ValidationException
     */
    public function verify(Request $request): Response
    {
        $resolved = $this->resolvePending($request);

        if (is_string($resolved)) {
            return $this->sessionExpired($request, $resolved);
        }

        [$pending, $user] = $resolved;

        $request->validate(['code' => 'required|string|max:64']);

        $result = $this->challenges->verify($user, $pending->challenge(), (string) $request->input('code'));

        if ($result !== VerificationResult::Passed) {
            throw ValidationException::withMessages([
                'code' => match ($result) {
                    VerificationResult::Invalid => $this->trans('errors.invalid_code', [
                        'attempts' => $this->challenges->attemptsLeft($user, $pending->challenge()),
                    ]),
                    default => $this->trans('errors.code_expired'),
                },
            ])->redirectTo(route(Orchid::challengeRoute()));
        }

        PendingLogin::forget($request->session());

        $record = $this->confirmDestination($user);

        $trust = $this->trustedDevices->isEnabled() && $request->boolean('trust_device');

        if ($trust) {
            $this->trustedDevices->issue($user, $record);
        }

        $this->events->dispatch(new TwoFactorPassed($user, Orchid::guardName(), TwoFactorPassed::VIA_CODE, $trust, $pending->channel));

        return $this->completeLogin($request, $user, $pending->remember);
    }

    /**
     * @throws ValidationException
     */
    public function resend(Request $request): Response
    {
        $resolved = $this->resolvePending($request);

        if (is_string($resolved)) {
            return $this->sessionExpired($request, $resolved);
        }

        [$pending, $user] = $resolved;

        try {
            $challenge = $this->challenges->issue($user, TwoFactorChallengeSent::CONTEXT_LOGIN);
        } catch (SendLimitExceededException $e) {
            return $this->sendError($request, $this->sendLimitMessage($e->availableIn));
        } catch (DeliveryFailedException) {
            return $this->sendError($request, $this->trans('errors.delivery_failed'));
        }

        $pending->withChallenge($challenge->id, $challenge->channel)->store($request->session());

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
     * The valid pending login and its user, or the message key why there is none. A pending login
     * that expired, whose user is gone or whose password changed since the password step
     * (spec §4.2) is removed.
     *
     * @return array{0: PendingLogin, 1: Authenticatable}|string
     */
    protected function resolvePending(Request $request): array|string
    {
        $pending = PendingLogin::fromSession($request->session());

        if ($pending === null) {
            return 'errors.session_expired';
        }

        $user = $pending->isExpired($this->pendingTtl())
            ? null
            : Orchid::guard()->getProvider()->retrieveById($pending->userId);

        if ($user === null) {
            PendingLogin::forget($request->session());

            return 'errors.session_expired';
        }

        if (! $pending->matchesPassword($user)) {
            PendingLogin::forget($request->session());

            return 'errors.password_changed';
        }

        return [$pending, $user];
    }

    /**
     * @throws ValidationException
     */
    protected function sessionExpired(Request $request, string $message = 'errors.session_expired'): Response
    {
        if ($request->wantsJson()) {
            throw ValidationException::withMessages(['code' => $this->trans($message)]);
        }

        return $this->sessionExpiredRedirect($message);
    }

    protected function sessionExpiredRedirect(string $message = 'errors.session_expired'): RedirectResponse
    {
        return redirect()
            ->route(Orchid::loginRoute())
            ->withErrors(['email' => $this->trans($message)]);
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
    protected function confirmDestination(Authenticatable $user): TwoFactorAuthentication
    {
        $record = TwoFactorAuthentication::query()->firstOrNew(['user_id' => $user->getAuthIdentifier()]);

        if ($record->confirmed_at === null) {
            $record->confirmed_at = now();
            $record->save();
        }

        return $record;
    }

    protected function pendingTtl(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.pending_ttl', 600));
    }
}
