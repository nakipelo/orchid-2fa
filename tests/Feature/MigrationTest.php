<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Workbench\App\Models\User;

function twoFactorMigration(): object
{
    return require dirname(__DIR__, 2).'/database/migrations/2026_11_03_000000_create_two_factor_authentications_table.php';
}

it('is loaded by the provider and creates the table', function () {
    $this->artisan('migrate')->assertSuccessful();

    expect(Schema::hasTable('two_factor_authentications'))->toBeTrue()
        ->and(Schema::getColumnListing('two_factor_authentications'))->toEqualCanonicalizing([
            'id', 'user_id', 'channel', 'enabled_at', 'confirmed_at',
            'trusted_devices_version', 'created_at', 'updated_at',
        ]);

    $user = User::query()->create(['name' => 'u', 'email' => 'u@example.com', 'password' => Hash::make('x')]);
    DB::table('two_factor_authentications')->insert(['user_id' => $user->id]);

    $row = DB::table('two_factor_authentications')->first();
    // `channel` is nullable without a default since 0.2 (2026_11_04_000000, spec 0.2 §4.9).
    expect($row->channel)->toBeNull()
        ->and((int) $row->trusted_devices_version)->toBe(1)
        ->and($row->enabled_at)->toBeNull()
        ->and($row->confirmed_at)->toBeNull();

    // user_id is unique
    expect(fn () => DB::table('two_factor_authentications')->insert(['user_id' => $user->id]))
        ->toThrow(QueryException::class);

    // FK users.id with cascadeOnDelete
    $user->delete();
    expect(DB::table('two_factor_authentications')->count())->toBe(0);
});

it('rolls back and re-applies', function () {
    $this->artisan('migrate')->assertSuccessful();

    twoFactorMigration()->down();
    expect(Schema::hasTable('two_factor_authentications'))->toBeFalse();

    twoFactorMigration()->up();
    expect(Schema::hasTable('two_factor_authentications'))->toBeTrue();

    $this->artisan('migrate:rollback')->assertSuccessful();
    expect(Schema::hasTable('two_factor_authentications'))->toBeFalse();
});

function nullableChannelMigration(): object
{
    return require dirname(__DIR__, 2).'/database/migrations/2026_11_04_000000_make_two_factor_channel_nullable.php';
}

function recoveryCodesMigration(): object
{
    return require dirname(__DIR__, 2).'/database/migrations/2026_11_04_000001_create_two_factor_recovery_codes_table.php';
}

it('makes the channel nullable and keeps the channel of existing rows (spec 0.2 §4.9)', function () {
    $this->artisan('migrate')->assertSuccessful();
    recoveryCodesMigration()->down();
    nullableChannelMigration()->down();

    // The 0.1 schema: not null with the default `email`.
    $a = User::query()->create(['name' => 'a', 'email' => 'a@example.com', 'password' => Hash::make('x')]);
    $b = User::query()->create(['name' => 'b', 'email' => 'b@example.com', 'password' => Hash::make('x')]);
    DB::table('two_factor_authentications')->insert(['user_id' => $a->id, 'confirmed_at' => now()]);
    expect(fn () => DB::table('two_factor_authentications')->insert(['user_id' => $b->id, 'channel' => null]))
        ->toThrow(QueryException::class);

    nullableChannelMigration()->up();

    expect(DB::table('two_factor_authentications')->where('user_id', $a->id)->value('channel'))->toBe('email')
        ->and(DB::table('two_factor_authentications')->where('user_id', $a->id)->value('confirmed_at'))->not->toBeNull();

    DB::table('two_factor_authentications')->insert(['user_id' => $b->id, 'channel' => null]);
    expect(DB::table('two_factor_authentications')->where('user_id', $b->id)->value('channel'))->toBeNull();

    // Down: rows without a channel get `email` back, the column is not null again.
    nullableChannelMigration()->down();
    expect(DB::table('two_factor_authentications')->pluck('channel')->all())->toBe(['email', 'email']);

    $c = User::query()->create(['name' => 'c', 'email' => 'c@example.com', 'password' => Hash::make('x')]);
    DB::table('two_factor_authentications')->insert(['user_id' => $c->id]);
    expect(DB::table('two_factor_authentications')->where('user_id', $c->id)->value('channel'))->toBe('email');

    nullableChannelMigration()->up();
    recoveryCodesMigration()->up();
    $this->artisan('migrate:rollback')->assertSuccessful();
    expect(Schema::hasTable('two_factor_authentications'))->toBeFalse();
});

it('creates the recovery codes table with a cascading foreign key and drops it', function () {
    $this->artisan('migrate')->assertSuccessful();

    expect(Schema::getColumnListing('two_factor_recovery_codes'))->toEqualCanonicalizing([
        'id', 'user_id', 'code_hash', 'used_at', 'created_at',
    ]);

    $user = User::query()->create(['name' => 'u', 'email' => 'u@example.com', 'password' => Hash::make('x')]);
    DB::table('two_factor_recovery_codes')->insert(['user_id' => $user->id, 'code_hash' => 'h', 'created_at' => now()]);
    DB::table('two_factor_recovery_codes')->insert(['user_id' => $user->id, 'code_hash' => 'h2', 'created_at' => now()]);

    expect(fn () => DB::table('two_factor_recovery_codes')->insert(['user_id' => 999, 'code_hash' => 'h']))
        ->toThrow(QueryException::class);

    $user->delete();
    expect(DB::table('two_factor_recovery_codes')->count())->toBe(0);

    recoveryCodesMigration()->down();
    expect(Schema::hasTable('two_factor_recovery_codes'))->toBeFalse();

    recoveryCodesMigration()->up();
    expect(Schema::hasTable('two_factor_recovery_codes'))->toBeTrue();
});
