<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Http\Controllers\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\PendingLogin;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Recovery\RecoveryCodes;
use Nakipelo\Orchid2FA\Support\Orchid;
use Symfony\Component\HttpFoundation\Response;

/**
 * The pending login of the code step and of the enrollment at the login (spec §4.2, 0.2 §5.4):
 * resolving it from the session, its expiry, the redirects between the stages and the final
 * login after the second factor.
 *
 * Expects the using class to have `$config`, `$events` and `$trustedDevices` and to use
 * CompletesLogin and InteractsWithChallenge.
 */
trait HandlesPendingLogin
{
    /**
     * Session flag of a login with a recovery code (spec 0.2 §5.3): the profile shows a banner.
     */
    public const RECOVERY_LOGIN = 'orchid-2fa.recovery_login';

    /**
     * The valid pending login and its user, or the message key why there is none. A pending login
     * that expired (the code step after `pending_ttl`, the enrollment after `enrollment_ttl`),
     * whose user is gone or whose password changed since the password step (spec §4.2) is removed.
     *
     * @return array{0: PendingLogin, 1: Authenticatable}|string
     */
    protected function resolvePending(Request $request): array|string
    {
        $pending = PendingLogin::fromSession($request->session());

        if ($pending === null) {
            return 'errors.session_expired';
        }

        $user = $pending->isExpired($this->pendingTtl(), $this->enrollmentTtl())
            ? null
            : Orchid::guard()->getProvider()->retrieveById($pending->userId);

        if ($user === null) {
            $this->forgetPending($request);

            return 'errors.session_expired';
        }

        if (! $pending->matchesPassword($user)) {
            $this->forgetPending($request);

            return 'errors.password_changed';
        }

        return [$pending, $user];
    }

    /**
     * Drop the pending login with its enrollment state and the shown recovery codes.
     */
    protected function forgetPending(Request $request): void
    {
        PendingLogin::forget($request->session());
        EnrollmentState::forget($request->session());
        $request->session()->forget(RecoveryCodes::SESSION_KEY);
    }

    /**
     * The page of the stage of the pending login.
     */
    protected function stageUrl(PendingLogin $pending): string
    {
        return route(match ($pending->stage) {
            PendingLogin::STAGE_ENROLL => Orchid::enrollRoute(),
            PendingLogin::STAGE_RECOVERY_CODES => Orchid::recoveryCodesRoute(),
            default => Orchid::challengeRoute(),
        });
    }

    /**
     * @throws ValidationException
     */
    protected function sessionExpired(Request $request, string $message = 'errors.session_expired', string $field = 'code'): Response
    {
        if ($request->wantsJson()) {
            throw ValidationException::withMessages([$field => $this->trans($message)]);
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
     * The JSON answer of the enrollment pages (spec 0.2 §6.4): `406` with the HTML page to open;
     * the pending login is not changed.
     */
    protected function browserRequired(string $url): JsonResponse
    {
        return new JsonResponse(['message' => $this->trans('errors.browser_required'), 'redirect' => $url], 406);
    }

    /**
     * The second factor is passed: the final login (spec §4.3) with the trusted device cookie when
     * asked for and allowed.
     */
    protected function finishLogin(Request $request, Authenticatable $user, PendingLogin $pending, string $via, bool $trust, string $channel): Response
    {
        $this->forgetPending($request);

        $record = $this->confirmDestination($user);
        $trust = $trust && $this->trustedDevices->isEnabled();

        if ($trust) {
            $this->trustedDevices->issue($user, $record);
        }

        $this->events->dispatch(new TwoFactorPassed($user, Orchid::guardName(), $via, $trust, $channel));

        return $this->completeLogin($request, $user, $pending->remember);
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

    protected function enrollmentTtl(): int
    {
        return max(1, (int) $this->config->get('orchid-2fa.enrollment_ttl', 900));
    }
}
