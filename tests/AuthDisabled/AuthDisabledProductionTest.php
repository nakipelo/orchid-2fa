<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nakipelo\Orchid2FA\Tests\AuthDisabled\AuthDisabledProductionTestCase;

uses(AuthDisabledProductionTestCase::class);

it('does not log the platform.auth warning in production', function () {
    expect(app()->environment())->toBe('production')
        ->and(Route::getRoutes()->getByName('platform.login.auth'))->toBeNull()
        ->and($this->logHandler()->hasWarningThatContains('[platform.auth] is false'))->toBeFalse();
});
