<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie as CookieFacade;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

/**
 * Spec §5.6, §10 (unit): TrustedDeviceCookie.
 */
function tdcRequest(string $name, ?string $value): Request
{
    return Request::create('/admin/login', 'POST', cookies: [$name => $value]);
}

function tdcConfirmedRecord(User $user, int $version = 1): TwoFactorAuthentication
{
    $record = $user->twoFactorRecord();
    $record->forceFill(['confirmed_at' => now(), 'trusted_devices_version' => $version])->save();

    return $record;
}

beforeEach(function () {
    $this->trusted = app(TrustedDeviceCookie::class);
    $this->user = tfUser();
});

it('accepts its own cookie for the same user and version', function () {
    $record = tdcConfirmedRecord($this->user, 3);
    $cookie = $this->trusted->make($this->user->id, 3);

    expect($cookie->getName())->toBe($this->trusted->name($this->user->id))
        ->and($this->trusted->passes(tdcRequest($cookie->getName(), $cookie->getValue()), $this->user, $record))->toBeTrue()
        ->and(CookieFacade::getQueuedCookies())->toBeEmpty();
});

it('rejects and queues the deletion of an invalid cookie', function (Closure $record) {
    $cookie = $this->trusted->make($this->user->id, 1);

    expect($this->trusted->passes(tdcRequest($cookie->getName(), $cookie->getValue()), $this->user, $record($this->user)))->toBeFalse();

    $queued = CookieFacade::getQueuedCookies();
    expect($queued)->toHaveCount(1)
        ->and($queued[0]->getName())->toBe($cookie->getName())
        ->and($queued[0]->getExpiresTime())->toBeLessThan(now()->getTimestamp());
})->with([
    'no record' => fn (User $user) => null,
    'unsaved record' => fn (User $user) => $user->twoFactorRecord()->forceFill(['confirmed_at' => now()]),
    'unconfirmed' => function (User $user) {
        $record = $user->twoFactorRecord();
        $record->save();

        return $record;
    },
    'other version' => fn (User $user) => tdcConfirmedRecord($user, 2),
]);

it('ignores the request without the cookie', function () {
    $record = tdcConfirmedRecord($this->user);

    expect($this->trusted->passes(Request::create('/admin/login', 'POST'), $this->user, $record))->toBeFalse()
        ->and(CookieFacade::getQueuedCookies())->toBeEmpty();
});

it('neither accepts nor deletes cookies when disabled', function () {
    $record = tdcConfirmedRecord($this->user);
    $cookie = $this->trusted->make($this->user->id, 1);
    config(['orchid-2fa.trusted_devices.enabled' => false]);

    expect($this->trusted->isEnabled())->toBeFalse()
        ->and($this->trusted->passes(tdcRequest($cookie->getName(), $cookie->getValue()), $this->user, $record))->toBeFalse()
        ->and(CookieFacade::getQueuedCookies())->toBeEmpty();
});

it('reads the lifetime from the config with a minimum of one day', function () {
    expect($this->trusted->lifetimeDays())->toBe(30);

    config(['orchid-2fa.trusted_devices.lifetime_days' => 0]);
    expect($this->trusted->lifetimeDays())->toBe(1);
});

it('uses the Orchid prefix as the cookie path', function (?string $prefix, string $path) {
    config(['platform.prefix' => $prefix]);

    expect(Orchid::pathPrefix())->toBe($path)
        ->and($this->trusted->make(1, 1)->getPath())->toBe($path)
        ->and($this->trusted->forget(1)->getPath())->toBe($path);
})->with([
    ['/admin', '/admin'],
    ['admin/', '/admin'],
    ['/dashboard/panel', '/dashboard/panel'],
    ['', '/'],
    [null, '/'],
]);

it('increments the version without the trait and creates no record', function () {
    $record = tdcConfirmedRecord($this->user);
    $other = tfUser('other@example.com');

    TwoFactorAuthentication::bumpTrustedDevicesVersionFor($this->user->id);
    TwoFactorAuthentication::bumpTrustedDevicesVersionFor($other->id);

    expect($record->refresh()->trusted_devices_version)->toBe(2)
        ->and(TwoFactorAuthentication::query()->count())->toBe(1);
});
