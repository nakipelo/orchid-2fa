<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Console;

use Illuminate\Console\Command;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TwoFactorManager;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * The emergency access of v0.1 (spec §4.8): after the administrator fixes the address,
 * the next login of the user sends a code to it. Does not check Orchid permissions.
 */
#[AsCommand(name: 'orchid-2fa:reset')]
class ResetTwoFactorCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'orchid-2fa:reset
        {email : The e-mail address the user signs in with}
        {--force : Reset without asking for confirmation}';

    /**
     * @var string
     */
    protected $description = 'Reset two-factor authentication of a user: disable it, sign out of trusted devices, remove the active code and limits';

    public function handle(TwoFactorManager $manager): int
    {
        $email = (string) $this->argument('email');
        $user = $email === '' ? null : Orchid::guard()->getProvider()->retrieveByCredentials(['email' => $email]);

        if ($user === null) {
            $this->components->error(sprintf('No user with the e-mail address [%s].', $email));

            return self::FAILURE;
        }

        if (! $this->option('force')
            && ! $this->components->confirm(sprintf('Reset two-factor authentication of [%s]?', $email))) {
            $this->components->warn('Cancelled, nothing has been changed.');

            return self::FAILURE;
        }

        $manager->reset($user);

        $this->components->info(sprintf('Two-factor authentication of [%s] has been reset.', $email));

        return self::SUCCESS;
    }
}
