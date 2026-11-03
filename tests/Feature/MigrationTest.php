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
    expect($row->channel)->toBe('email')
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
