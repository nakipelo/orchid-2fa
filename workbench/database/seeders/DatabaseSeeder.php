<?php

declare(strict_types=1);

namespace Workbench\Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Orchid\Support\Facades\Dashboard;
use Workbench\App\Models\User;

class DatabaseSeeder extends Seeder
{
    public const ADMIN_EMAIL = 'admin@example.com';

    public const ADMIN_PASSWORD = 'password';

    /**
     * Test administrator, as `php artisan orchid:admin` would create it.
     */
    public function run(): void
    {
        User::query()->updateOrCreate(
            ['email' => self::ADMIN_EMAIL],
            [
                'name' => 'admin',
                'password' => Hash::make(self::ADMIN_PASSWORD),
                'permissions' => Dashboard::getAllowAllPermission(),
            ],
        );
    }
}
