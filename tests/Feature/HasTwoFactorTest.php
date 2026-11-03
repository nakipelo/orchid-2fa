<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

function makeUser(): User
{
    return User::query()->create(['name' => 'u', 'email' => 'u@example.com', 'password' => Hash::make('x')]);
}

it('returns a new unsaved record bound to the user', function () {
    $user = makeUser();

    $record = $user->twoFactorRecord();

    expect($record->exists)->toBeFalse()
        ->and($record->user_id)->toBe($user->id)
        ->and($record->channel)->toBe('email')
        ->and($record->trusted_devices_version)->toBe(1)
        ->and($user->hasTwoFactorEnabled())->toBeFalse();
});

it('reports voluntary enablement and relates back to the user', function () {
    $user = makeUser();
    $record = $user->twoFactorRecord();
    $record->enabled_at = now();
    $record->save();

    expect($user->hasTwoFactorEnabled())->toBeTrue()
        ->and($user->twoFactor)->toBeInstanceOf(TwoFactorAuthentication::class)
        ->and($user->twoFactorRecord()->is($record))->toBeTrue()
        ->and($record->user->is($user))->toBeTrue()
        ->and($record->isEnabled())->toBeTrue();
});

it('bumps the trusted devices version', function () {
    $user = makeUser();
    $user->twoFactorRecord()->save();

    $user->bumpTrustedDevicesVersion();
    $user->bumpTrustedDevicesVersion();

    expect($user->twoFactor->trusted_devices_version)->toBe(3);
});

it('does not create a record when bumping without one', function () {
    $user = makeUser();

    $user->bumpTrustedDevicesVersion();

    expect(TwoFactorAuthentication::query()->count())->toBe(0);
});
