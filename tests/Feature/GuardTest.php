<?php

declare(strict_types=1);

use Illuminate\Auth\SessionGuard;
use Illuminate\Support\Facades\Auth;
use Nakipelo\Orchid2FA\Exceptions\UnsupportedGuardException;
use Nakipelo\Orchid2FA\Orchid2FAServiceProvider;

it('boots with the default session guard', function () {
    expect(Auth::guard(config('platform.guard')))->toBeInstanceOf(SessionGuard::class);
});

it('fails with a clear error when the Orchid guard is not a SessionGuard', function () {
    config([
        'auth.guards.api' => ['driver' => 'token', 'provider' => 'users'],
        'platform.guard' => 'api',
    ]);

    $this->app->register(Orchid2FAServiceProvider::class, force: true);
})->throws(
    UnsupportedGuardException::class,
    'nakipelo/orchid-2fa requires the Orchid guard to be an instance of Illuminate\Auth\SessionGuard, but guard [api] (config [platform.guard]) is Illuminate\Auth\TokenGuard.',
);

it('fails for a request guard too', function () {
    Auth::viaRequest('custom-request', fn () => null);

    config([
        'auth.guards.custom' => ['driver' => 'custom-request', 'provider' => 'users'],
        'platform.guard' => 'custom',
    ]);

    $this->app->register(Orchid2FAServiceProvider::class, force: true);
})->throws(UnsupportedGuardException::class, 'Illuminate\Auth\RequestGuard');
