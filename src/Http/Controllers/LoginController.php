<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Http\Controllers;

use Illuminate\Http\Request;
use Nakipelo\Orchid2FA\Support\Orchid;
use Symfony\Component\HttpFoundation\Response;

/**
 * Replaces Orchid's `POST login` route (named `login.auth` in the Orchid route group).
 *
 * Stage 1 stub: proves the route replacement works and hands the request
 * over to Orchid unchanged, so logging in behaves exactly as without the package.
 * The two-factor flow (spec §4.1–4.3) replaces the body in stage 2.
 */
class LoginController
{
    public function __construct()
    {
        Orchid::redirectAuthenticatedToIndex();
    }

    public function login(Request $request): Response
    {
        return Orchid::delegateLogin($request);
    }
}
