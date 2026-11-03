<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Recovery codes (spec 0.2 §4.7, §4.9): only hashes of the application hasher.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('two_factor_recovery_codes', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->unsignedBigInteger('user_id')->index();
            $table->string('code_hash', 255);
            $table->timestamp('used_at')->nullable();
            $table->timestamp('created_at')->nullable();

            $table->foreign('user_id')->references('id')->on('users')->cascadeOnDelete();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('two_factor_recovery_codes');
    }
};
