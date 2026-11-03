<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Fixtures;

use Illuminate\Support\ServiceProvider;

/**
 * Registers the test driver `fake` in boot(), as a driver package does (the conformance suite).
 */
class RegisterFakeVerifierProvider extends ServiceProvider
{
    public function boot(): void
    {
        FakeVerifierChannel::register();
    }
}
