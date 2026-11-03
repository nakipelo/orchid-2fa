<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Http\Controllers\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Cookie\CookieJar;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nakipelo\Orchid2FA\Support\Orchid;
use Symfony\Component\HttpFoundation\Response;

/**
 * The final login, shared by the password step without 2FA and the code step (spec §4.3).
 * Repeats Orchid's `LoginController::login()` + `sendLoginResponse()`.
 */
trait CompletesLogin
{
    protected function completeLogin(Request $request, Authenticatable $user, bool $remember): Response
    {
        $guard = Orchid::guard();

        $guard->login($user, $remember);

        $request->session()->regenerate();

        if ($remember) {
            $cookies = app(CookieJar::class);
            $cookies->queue($cookies->forever(Orchid::lockCookieName(), (string) $user->getAuthIdentifier()));
        }

        return $request->wantsJson()
            ? new JsonResponse([], 204)
            : redirect()->intended(Orchid::indexUrl());
    }
}
