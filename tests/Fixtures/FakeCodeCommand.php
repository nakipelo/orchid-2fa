<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\Fixtures;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * The current code of the fake authenticator of a user (manual checks in the workbench).
 */
class FakeCodeCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'orchid-2fa-fake:code {email}';

    /**
     * @var string
     */
    protected $description = 'Print the current code of the fake authenticator of a user (workbench)';

    public function handle(): int
    {
        $userId = DB::table('users')->where('email', (string) $this->argument('email'))->value('id');
        $secret = $userId === null ? null : DB::table(FakeVerifierChannel::TABLE)->where('user_id', $userId)->value('secret');

        if (! is_string($secret)) {
            $this->error('No fake authenticator for this user.');

            return self::FAILURE;
        }

        $this->line(FakeVerifierChannel::codeFor($secret));

        return self::SUCCESS;
    }
}
