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
use Nakipelo\Orchid2FA\Challenge\Challenge;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\PendingLogin;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\DeliveryChannel;
use Nakipelo\Orchid2FA\Channels\UserMethod;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\CompletesLogin;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\HandlesPendingLogin;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\InteractsWithChallenge;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * The code step: screen, verification, resend, recovery code, e-mail fallback and "sign in as a
 * different user" (spec §4.2, §6; 0.2 §5.2, §5.3, §6.2).
 *
 * The user is identified only by the pending login in the server session; request
 * parameters never select the user.
 */
class ChallengeController
{
    use CompletesLogin;
    use HandlesPendingLogin;
    use InteractsWithChallenge;

    public function __construct(
        protected ChallengeManager $challenges,
        protected Dispatcher $events,
        protected Repository $config,
        protected TrustedDeviceCookie $trustedDevices,
        protected ChannelRegistry $channels,
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

        [$pending, $user] = $resolved;

        if ($pending->stage !== PendingLogin::STAGE_CHALLENGE) {
            return redirect()->to($this->stageUrl($pending));
        }

        $method = $this->channels->for($user);

        if ($method === null) {
            // The method was reset or its driver removed while the code step was pending.
            $this->forgetPending($request);

            return $this->sessionExpiredRedirect('errors.session_expired');
        }

        $channel = $this->displayChannel($user, $pending, $method);
        $input = $channel->codeInput();
        $fallback = $channel === $method && $this->challenges->fallbackChannel($user) !== null;

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
            'channel' => $channel->name(),
            'prompt' => $channel->prompt($user),
            'codeInput' => $input,
            'challengeView' => $channel->challengeView(),
            'user' => $user,
            'canResend' => $channel->requiresDelivery(),
            'recoveryUrl' => $method->needsRecoveryCodes() ? route(Orchid::recoveryRoute()) : null,
            'fallbackUrl' => $fallback ? route(Orchid::fallbackRoute()) : null,
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

        if ($pending->stage !== PendingLogin::STAGE_CHALLENGE) {
            return $this->wrongStage($request, $pending);
        }

        $request->validate(['code' => 'required|string|max:64']);

        $result = $this->challenges->verify($user, $pending->challenge(), (string) $request->input('code'));

        if ($result !== VerificationResult::Passed) {
            return $this->refused($request, $user, $pending, $result, $pending->challenge(), 'code');
        }

        return $this->passed($request, $user, $pending, TwoFactorPassed::VIA_CODE, $request->boolean('trust_device'));
    }

    /**
     * A recovery code instead of the code (spec 0.2 §5.3): no trusted device cookie, whatever
     * the request sends.
     *
     * @throws ValidationException
     */
    public function recovery(Request $request): Response
    {
        $resolved = $this->resolvePending($request);

        if (is_string($resolved)) {
            return $this->sessionExpired($request, $resolved, 'recovery_code');
        }

        [$pending, $user] = $resolved;

        if ($pending->stage !== PendingLogin::STAGE_CHALLENGE) {
            return $this->wrongStage($request, $pending);
        }

        $request->validate(['recovery_code' => 'required|string|max:64']);

        // After an e-mail fallback the pending challenge is the e-mail one; the recovery code
        // belongs to the user's method.
        $method = $this->channels->for($user);
        $challenge = $pending->context === TwoFactorChallengeSent::CONTEXT_FALLBACK && $method !== null
            ? new Challenge($pending->challengeId, $method->name(), TwoFactorChallengeSent::CONTEXT_LOGIN)
            : $pending->challenge();

        $result = $this->challenges->verifyRecoveryCode($user, $challenge, (string) $request->input('recovery_code'));

        if ($result !== VerificationResult::Passed) {
            return $this->refused($request, $user, $pending, $result, $challenge, 'recovery_code');
        }

        $request->session()->put(self::RECOVERY_LOGIN, true);

        return $this->passed($request, $user, $pending->withChallenge($pending->challengeId, $challenge->channel), TwoFactorPassed::VIA_RECOVERY_CODE, false);
    }

    /**
     * "Send a code by e-mail" for a verifier method that allows it (spec 0.2 §13): the e-mail
     * channel issues a code with the context `fallback` under the delivery limits.
     *
     * @throws ValidationException
     */
    public function fallback(Request $request): Response
    {
        $resolved = $this->resolvePending($request);

        if (is_string($resolved)) {
            return $this->sessionExpired($request, $resolved);
        }

        [$pending, $user] = $resolved;

        if ($pending->stage !== PendingLogin::STAGE_CHALLENGE) {
            return $this->wrongStage($request, $pending);
        }

        $email = $this->challenges->fallbackChannel($user);

        if ($email === null) {
            return $this->sendError($request, $this->trans('errors.fallback_unavailable'));
        }

        return $this->sendCode($request, $user, $pending, $email, TwoFactorChallengeSent::CONTEXT_FALLBACK, 'challenge.fallback_sent');
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

        if ($pending->stage !== PendingLogin::STAGE_CHALLENGE) {
            return $this->wrongStage($request, $pending);
        }

        $method = $this->channels->for($user);

        if ($method === null) {
            return $this->sendError($request, $this->trans('errors.code_expired'));
        }

        $channel = $this->displayChannel($user, $pending, $method);

        // A verifier channel sends nothing: a new challenge would only reset its attempts.
        if (! $channel->requiresDelivery()) {
            return $this->sendError($request, $this->trans('errors.resend_unavailable'));
        }

        return $this->sendCode($request, $user, $pending, $channel, $pending->context, 'challenge.resent');
    }

    /**
     * "Sign in as a different user": drop the pending login and Orchid's lock cookie.
     */
    public function cancel(Request $request, CookieJar $cookies): RedirectResponse
    {
        $this->forgetPending($request);

        return redirect()
            ->route(Orchid::loginRoute())
            ->withCookie($cookies->forget(Orchid::lockCookieName()));
    }

    /**
     * The second factor is passed. A method that is no longer allowed was only the proof: the
     * login goes on with the enrollment of an allowed method (spec 0.2 §5.4 B).
     */
    protected function passed(Request $request, Authenticatable $user, PendingLogin $pending, string $via, bool $trust): Response
    {
        if ($this->channels->methodFor($user)->state === UserMethod::PROOF) {
            $this->confirmDestination($user);

            $pending = $pending->toEnrollment($via === TwoFactorPassed::VIA_RECOVERY_CODE ? PendingLogin::VIA_RECOVERY_CODE : PendingLogin::VIA_CODE);
            $pending->store($request->session());

            $url = route(Orchid::enrollRoute());

            return $request->wantsJson()
                ? new JsonResponse(['two_factor' => true, 'enroll' => true, 'redirect' => $url])
                : redirect()->to($url);
        }

        return $this->finishLogin($request, $user, $pending, $via, $trust, $pending->channel);
    }

    /**
     * @throws ValidationException
     */
    protected function refused(Request $request, Authenticatable $user, PendingLogin $pending, VerificationResult $result, Challenge $challenge, string $field): Response
    {
        $lockout = $this->challenges->lockout();
        $userLockout = $this->userLockoutMessage($lockout);

        // The attempts of a pending login of a verifier channel (or of the recovery codes) are
        // over: the password again (spec 0.2 §4.4, §5.2).
        $method = $this->channels->for($user);

        $verifier = $field === 'recovery_code' || ($method !== null && ! $this->displayChannel($user, $pending, $method)->requiresDelivery());

        if ($verifier && $userLockout === null && $result !== VerificationResult::Invalid) {
            // A verifier challenge has no code to request again: the password again (spec 0.2 §4.4).
            $this->forgetPending($request);

            return $this->sessionExpired($request, $result === VerificationResult::LockedOut ? 'errors.too_many_attempts' : 'errors.session_expired', $field);
        }

        throw ValidationException::withMessages([
            $field => $userLockout ?? match ($result) {
                VerificationResult::Invalid => $this->trans($field === 'recovery_code' ? 'errors.invalid_recovery_code' : 'errors.invalid_code', [
                    'attempts' => $this->challenges->attemptsLeft($user, $challenge, $field === 'recovery_code' ? true : null),
                ]),
                default => $this->trans('errors.code_expired'),
            },
        ])->redirectTo(route(Orchid::challengeRoute()));
    }

    /**
     * @throws ValidationException
     */
    protected function sendCode(Request $request, Authenticatable $user, PendingLogin $pending, TwoFactorChannel $channel, string $context, string $status): Response
    {
        try {
            $challenge = $this->challenges->issue($user, $context, $channel);
        } catch (SendLimitExceededException $e) {
            return $this->sendError($request, $this->sendLimitMessage($e->availableIn));
        } catch (DeliveryFailedException) {
            return $this->sendError($request, $this->trans('errors.delivery_failed'));
        }

        $pending->withChallenge($challenge->id, $challenge->channel, $context)->store($request->session());

        if ($request->wantsJson()) {
            return new JsonResponse(['resend_available_in' => $this->challenges->sendAvailableIn($user, $channel)]);
        }

        $this->flashStatus($request, $this->trans($status));

        return redirect()->route(Orchid::challengeRoute());
    }

    /**
     * The channel of the pending challenge: the user's method, or the e-mail channel after a
     * fallback (while it is still available).
     */
    protected function displayChannel(Authenticatable $user, PendingLogin $pending, TwoFactorChannel $method): TwoFactorChannel
    {
        if ($pending->context === TwoFactorChallengeSent::CONTEXT_FALLBACK && $pending->channel !== $method->name()) {
            return $this->challenges->fallbackChannel($user) ?? $method;
        }

        return $method;
    }

    /**
     * @throws ValidationException
     */
    protected function wrongStage(Request $request, PendingLogin $pending): Response
    {
        if ($request->wantsJson()) {
            throw ValidationException::withMessages(['code' => $this->trans('errors.session_expired')]);
        }

        return redirect()->to($this->stageUrl($pending));
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
}
