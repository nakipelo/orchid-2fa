<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Monolog\Level;
use Nakipelo\Orchid2FA\Tests\AuthDisabled\AuthDisabledTestCase;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;

uses(AuthDisabledTestCase::class);

it('does not register POST login when platform.auth is false', function () {
    expect(Route::getRoutes()->getByName('platform.login.auth'))->toBeNull()
        ->and(Route::getRoutes()->getByName('platform.login'))->toBeNull();

    $request = Request::create('/admin/login', 'POST');
    $postRoutes = collect(Route::getRoutes()->getRoutes())
        ->filter(fn ($route) => in_array('POST', $route->methods(), true) && $route->matches($request));

    expect($postRoutes)->toBeEmpty();

    // Only Orchid's GET fallback route matches the URI, so POST is not handled at all.
    expect(fn () => Route::getRoutes()->match($request))
        ->toThrow(MethodNotAllowedHttpException::class);
});

it('logs a warning once in local/testing when platform.auth is false', function () {
    expect(app()->environment())->toBe('testing');

    $records = array_values(array_filter(
        $this->logHandler()->getRecords(),
        fn ($record) => $record->level === Level::Warning
            && str_contains($record->message, '[platform.auth] is false'),
    ));

    expect($records)->toHaveCount(1);
});
