<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Spec 0.2 §4.9: `channel` null means "no method enrolled"; existing rows keep `email`.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('two_factor_authentications', function (Blueprint $table): void {
            $table->string('channel', 32)->nullable()->default(null)->change();
        });
    }

    public function down(): void
    {
        DB::table('two_factor_authentications')->whereNull('channel')->update(['channel' => 'email']);

        Schema::table('two_factor_authentications', function (Blueprint $table): void {
            $table->string('channel', 32)->nullable(false)->default('email')->change();
        });
    }
};
