<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Console;

use Illuminate\Console\Command;
use Nakipelo\Orchid2FA\TwoFactorManager;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * Run once after installing the package (spec §4.5): remember cookies issued before it would
 * let users in without the second factor. Clears `remember_token` of all users of the Orchid
 * guard's model in one query; active sessions are not ended.
 */
#[AsCommand(name: 'orchid-2fa:rotate-remember-tokens')]
class RotateRememberTokensCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'orchid-2fa:rotate-remember-tokens
        {--force : Rotate without asking for confirmation}';

    /**
     * @var string
     */
    protected $description = 'Invalidate the "remember me" cookies of all users of the admin panel';

    public function handle(TwoFactorManager $manager): int
    {
        if (! $this->option('force')
            && ! $this->components->confirm('All "remember me" cookies of the admin panel users will stop working. Continue?')) {
            $this->components->warn('Cancelled, nothing has been changed.');

            return self::FAILURE;
        }

        $count = $manager->forgetAllRememberTokens();

        $this->components->info(sprintf('Remember tokens cleared for %d user(s).', $count));

        return self::SUCCESS;
    }
}
