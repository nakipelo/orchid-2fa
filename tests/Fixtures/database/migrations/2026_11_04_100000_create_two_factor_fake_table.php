<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The table of the test driver FakeVerifierChannel (spec 0.2 §10.1).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('two_factor_fake', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->unsignedBigInteger('user_id')->unique();
            $table->string('secret', 64);
            $table->timestamp('confirmed_at')->nullable();
            $table->unsignedBigInteger('last_step')->nullable();
            $table->timestamps();

            $table->foreign('user_id')->references('id')->on('users')->cascadeOnDelete();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('two_factor_fake');
    }
};
