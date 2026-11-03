<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\Context;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\PendingLogin;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\UserMethod;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Nakipelo\Orchid2FA\Events\TwoFactorChannelChanged;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\CompletesLogin;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\HandlesPendingLogin;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\InteractsWithChallenge;
use Nakipelo\Orchid2FA\Recovery\RecoveryCodes;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;
use Nakipelo\Orchid2FA\TwoFactorManager;
use Symfony\Component\HttpFoundation\Response;

/**
 * Enrollment of a method at the login and the recovery codes shown after it (spec 0.2 §5.4,
 * §6.2, §6.4). Only HTML: a JSON request gets `406` with the page to open in a browser, the
 * pending login is not changed.
 *
 * The user comes only from the pending login (stage `enroll` / `recovery_codes`); `{channel}` must
 * be allowed. The step lives `enrollment_ttl` from its start, the password fingerprint is checked
 * on every request.
 */
class EnrollmentController
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
        protected TwoFactorManager $manager,
    ) {
        Orchid::redirectAuthenticatedToIndex();
    }

    /**
     * The choice of the method (several allowed) or the enrollment step of `{channel}`.
     */
    public function show(Request $request, ?string $channel = null): Response|View
    {
        if ($request->wantsJson()) {
            return $this->browserRequired($request->fullUrl());
        }

        $resolved = $this->resolveEnrollment($request);

        if (! is_array($resolved)) {
            return $resolved;
        }

        [$pending, $user] = $resolved;
        $allowed = $this->channels->allowed();

        if ($channel === null || ! in_array($channel, $allowed, true)) {
            if (count($allowed) === 1) {
                return redirect()->route(Orchid::enrollRoute(), ['channel' => $allowed[0]]);
            }

            return view('orchid-2fa::enroll', $this->viewData($request, $user, $pending) + [
                'choices' => array_map(fn (string $name): array => [
                    'name' => $name,
                    'label' => $this->channels->channel($name)->label(),
                    'url' => route(Orchid::enrollRoute(), ['channel' => $name]),
                ], $allowed),
                'channel' => null,
            ]);
        }

        $driver = $this->channels->channel($channel);
        $state = EnrollmentState::fromSession($request->session(), $user, $channel, Context::ENROLL, $this->enrollmentTtl());

        $error = null;

        if ($state === null) {
            $state = EnrollmentState::start($request->session(), $user, $channel, Context::ENROLL);
            $error = $this->startStep($user, $driver, $state);
        }

        $input = $driver->codeInput();

        return view('orchid-2fa::enroll', ['error' => $error ?? $request->session()->get(self::FLASH_ERROR)] + $this->viewData($request, $user, $pending) + [
            'choices' => [],
            'channel' => $channel,
            'label' => $driver->label(),
            'enrollmentView' => $driver->enrollmentView(),
            'enrollmentData' => $driver->enrollmentData($user, $state),
            'prompt' => $driver->requiresDelivery() ? $driver->prompt($user) : null,
            'codeInput' => $input,
            'codeLength' => $input->length,
            'codePattern' => $input->pattern,
            'confirmUrl' => route(Orchid::enrollConfirmRoute(), ['channel' => $channel]),
            'canResend' => $driver->requiresDelivery(),
            'chooseUrl' => count($allowed) > 1 ? route(Orchid::enrollRoute()) : null,
            // The trust checkbox moves to the recovery codes page when there are codes (§5.4 item 6).
            'trustDevice' => $this->trustAllowed($pending) && ! $driver->needsRecoveryCodes(),
        ]);
    }

    /**
     * Confirm the enrollment with the first code (or send the code again with `resend`).
     *
     * @throws ValidationException
     */
    public function confirm(Request $request, string $channel): Response
    {
        if ($request->wantsJson()) {
            return $this->browserRequired(route(Orchid::enrollRoute(), ['channel' => $channel]));
        }

        $resolved = $this->resolveEnrollment($request);

        if (! is_array($resolved)) {
            return $resolved;
        }

        [$pending, $user] = $resolved;

        if (! $this->channels->isAllowed($channel)) {
            return redirect()->route(Orchid::enrollRoute());
        }

        $driver = $this->channels->channel($channel);
        $stepUrl = route(Orchid::enrollRoute(), ['channel' => $channel]);
        $state = EnrollmentState::fromSession($request->session(), $user, $channel, Context::ENROLL, $this->enrollmentTtl());

        // "Send again" exists only for a delivery channel; for a verifier channel it would only
        // generate a new secret behind the shown one.
        if ($request->boolean('resend') && ! $driver->requiresDelivery()) {
            $this->flashError($request, $this->trans('errors.resend_unavailable'));

            return redirect()->to($stepUrl);
        }

        if ($request->boolean('resend')) {
            $state ??= EnrollmentState::start($request->session(), $user, $channel, Context::ENROLL);
            $error = $this->startStep($user, $driver, $state);
            $error === null ? $this->flashStatus($request, $this->trans('challenge.resent')) : $this->flashError($request, $error);

            return redirect()->to($stepUrl);
        }

        $request->validate(['code' => 'required|string|max:64']);

        if ($state === null) {
            $this->flashError($request, $this->trans('errors.code_expired'));

            return redirect()->to($stepUrl);
        }

        $result = $this->challenges->confirmEnrollment($user, $driver, $state, (string) $request->input('code'));

        if ($result !== VerificationResult::Passed) {
            $userLockout = $this->userLockoutMessage($this->challenges->lockout());

            if ($result === VerificationResult::LockedOut && $userLockout === null) {
                // 5 wrong codes of the step: the password again (§5.4 item 4).
                $this->forgetPending($request);

                return $this->sessionExpiredRedirect('errors.too_many_attempts');
            }

            throw ValidationException::withMessages([
                'code' => $userLockout ?? match ($result) {
                    VerificationResult::Invalid => $this->trans('errors.invalid_code', [
                        'attempts' => $this->challenges->attemptsLeft($user, $this->challenges->enrollmentChallenge($driver, $state), ! $driver->requiresDelivery()),
                    ]),
                    default => $this->trans('errors.code_expired'),
                },
            ])->redirectTo($stepUrl);
        }

        EnrollmentState::forget($request->session());

        $codes = $this->manager->commitEnrollment($user, $driver, TwoFactorChannelChanged::ENROLLED);

        if ($codes !== null) {
            RecoveryCodes::keepForDisplay($request->session(), $user, $codes);
            $pending->toRecoveryCodes($channel)->store($request->session());

            return redirect()->route(Orchid::recoveryCodesRoute());
        }

        return $this->finishLogin($request, $user, $pending, TwoFactorPassed::VIA_ENROLLMENT, $this->trustAllowed($pending) && $request->boolean('trust_device'), $channel);
    }

    /**
     * The new recovery codes, shown once (spec 0.2 §5.4 item 6).
     */
    public function showCodes(Request $request): Response|View
    {
        if ($request->wantsJson()) {
            return $this->browserRequired(route(Orchid::recoveryCodesRoute()));
        }

        $resolved = $this->resolveCodes($request);

        if (! is_array($resolved)) {
            return $resolved;
        }

        [$pending, $user] = $resolved;

        return view('orchid-2fa::recovery-codes', [
            'layout' => Orchid::authLayout(),
            'codes' => RecoveryCodes::forDisplay($request->session(), $user) ?? [],
            'confirmUrl' => route(Orchid::recoveryCodesConfirmRoute()),
            'cancelUrl' => route(Orchid::cancelRoute()),
            'trustDevice' => $this->trustAllowed($pending),
            'trustDeviceDays' => $this->trustedDevices->lifetimeDays(),
        ]);
    }

    /**
     * "I have saved the codes": the final login.
     */
    public function confirmCodes(Request $request): Response
    {
        if ($request->wantsJson()) {
            return $this->browserRequired(route(Orchid::recoveryCodesRoute()));
        }

        $resolved = $this->resolveCodes($request);

        if (! is_array($resolved)) {
            return $resolved;
        }

        [$pending, $user] = $resolved;

        return $this->finishLogin($request, $user, $pending, TwoFactorPassed::VIA_ENROLLMENT, $this->trustAllowed($pending) && $request->boolean('trust_device'), $pending->channel);
    }

    /**
     * The pending login at the enrollment step, while the user's method is still what it was when
     * the step started (spec 0.2 §5.4, §9): without a method (A, `via` null) or with the proof
     * method (B). A method enrolled meanwhile (in another browser, in the profile) or a reset ends
     * the step: it must not replace the method with another binding, the login starts again.
     *
     * @return array{0: PendingLogin, 1: Authenticatable}|Response
     */
    protected function resolveEnrollment(Request $request): array|Response
    {
        $resolved = $this->resolveStage($request, PendingLogin::STAGE_ENROLL);

        if (! is_array($resolved)) {
            return $resolved;
        }

        if ($this->channels->allowed() === []) {
            // Nothing to enroll (spec 0.2 §4.3): fail closed.
            $this->forgetPending($request);

            return $this->sessionExpiredRedirect('errors.channel_unavailable');
        }

        $expected = $resolved[0]->via === null ? UserMethod::NONE : UserMethod::PROOF;

        if ($this->channels->methodFor($resolved[1])->state !== $expected) {
            $this->forgetPending($request);

            return $this->sessionExpiredRedirect();
        }

        return $resolved;
    }

    /**
     * The pending login at the recovery codes of the enrollment, while the user's method is still
     * the one it enrolled (a reset or another enrollment meanwhile ends it).
     *
     * @return array{0: PendingLogin, 1: Authenticatable}|Response
     */
    protected function resolveCodes(Request $request): array|Response
    {
        $resolved = $this->resolveStage($request, PendingLogin::STAGE_RECOVERY_CODES);

        if (! is_array($resolved)) {
            return $resolved;
        }

        $method = $this->channels->methodFor($resolved[1]);

        if ($method->state !== UserMethod::ACTIVE || $method->channel?->name() !== $resolved[0]->channel) {
            $this->forgetPending($request);

            return $this->sessionExpiredRedirect();
        }

        return $resolved;
    }

    /**
     * @return array{0: PendingLogin, 1: Authenticatable}|Response
     */
    protected function resolveStage(Request $request, string $stage): array|Response
    {
        if (PendingLogin::fromSession($request->session()) === null) {
            return redirect()->route(Orchid::loginRoute());
        }

        $resolved = $this->resolvePending($request);

        if (is_string($resolved)) {
            return $this->sessionExpiredRedirect($resolved);
        }

        if ($resolved[0]->stage !== $stage) {
            return redirect()->to($this->stageUrl($resolved[0]));
        }

        return $resolved;
    }

    /**
     * Start (or restart: a new code of a delivery channel) the enrollment step; the error message
     * of a failed send, if any.
     */
    protected function startStep(Authenticatable $user, TwoFactorChannel $channel, EnrollmentState $state): ?string
    {
        try {
            $this->challenges->startEnrollment($user, $channel, $state);
        } catch (SendLimitExceededException $e) {
            return $this->sendLimitMessage($e->availableIn);
        } catch (DeliveryFailedException) {
            return $this->trans('errors.delivery_failed');
        }

        return null;
    }

    /**
     * The trust checkbox only after a code of the user's method (spec 0.2 §5.4 B): not after a
     * recovery code (§5.3) and not for an enrollment protected by the password only (§5.4 A).
     */
    protected function trustAllowed(PendingLogin $pending): bool
    {
        return $this->trustedDevices->isEnabled() && $pending->via === PendingLogin::VIA_CODE;
    }

    /**
     * @return array<string, mixed>
     */
    protected function viewData(Request $request, Authenticatable $user, PendingLogin $pending): array
    {
        return [
            'layout' => Orchid::authLayout(),
            'user' => $user,
            'cancelUrl' => route(Orchid::cancelRoute()),
            'trustDeviceDays' => $this->trustedDevices->lifetimeDays(),
            'error' => $request->session()->get(self::FLASH_ERROR),
            'status' => $request->session()->get(self::FLASH_STATUS),
            'proof' => $pending->via !== null,
        ];
    }
}
