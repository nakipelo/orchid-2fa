<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel's `throttle` for the actions of the two-factor profile screen (`POST
 * profile/two-factor/{method}`, spec 0.2 §6.4): per signed-in user, with the parameters of
 * `routes.profile_throttle`. Showing the screen (GET, HEAD) is not counted: every action redirects
 * back to it.
 *
 * @internal
 */
class ThrottleProfileActions extends ThrottleRequests
{
    /**
     * @param  Request  $request
     */
    public function handle($request, Closure $next, $maxAttempts = 60, $decayMinutes = 1, $prefix = ''): Response
    {
        if ($request->isMethod('GET') || $request->isMethod('HEAD')) {
            return $next($request);
        }

        return parent::handle($request, $next, $maxAttempts, $decayMinutes, $prefix);
    }
}
