<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TwoFactorManager;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * The emergency access (spec §4.8 of 0.1, §5.10 of 0.2): reset one user by the e-mail address, or
 * every user of a channel with `--channel=<name>` (e.g. after its driver was removed; the name is
 * not checked against the registry). Does not check Orchid permissions.
 */
#[AsCommand(name: 'orchid-2fa:reset')]
class ResetTwoFactorCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'orchid-2fa:reset
        {email? : The e-mail address of the user (the attribute from orchid-2fa.channels.email.attribute)}
        {--channel= : Reset every user whose method is this channel instead}
        {--force : Reset without asking for confirmation}';

    /**
     * @var string
     */
    protected $description = 'Reset two-factor authentication of a user (or of every user of a channel): remove the method, recovery codes, trusted devices, the active code and limits';

    public function handle(TwoFactorManager $manager, Repository $config, ChannelRegistry $channels): int
    {
        $email = $this->argument('email');
        $email = is_string($email) ? trim($email) : '';
        $channel = $this->option('channel');
        $channel = is_string($channel) ? trim($channel) : '';

        if (($email === '') === ($channel === '')) {
            $this->components->error('Pass either the e-mail address of a user or --channel=<name>, not both.');

            return self::FAILURE;
        }

        return $channel !== ''
            ? $this->resetChannel($manager, $channels, $channel)
            : $this->resetUser($manager, $config, $email);
    }

    protected function resetUser(TwoFactorManager $manager, Repository $config, string $email): int
    {
        $attribute = $config->get('orchid-2fa.channels.email.attribute');
        $attribute = is_string($attribute) && $attribute !== '' ? $attribute : 'email';
        $user = Orchid::guard()->getProvider()->retrieveByCredentials([$attribute => $email]);

        if ($user === null) {
            $this->components->error(sprintf('No user with the e-mail address [%s].', $email));

            return self::FAILURE;
        }

        if (! $this->confirmed(sprintf('Reset two-factor authentication of [%s]?', $email))) {
            return self::FAILURE;
        }

        $manager->reset($user);

        $this->components->info(sprintf('Two-factor authentication of [%s] has been reset.', $email));

        return self::SUCCESS;
    }

    protected function resetChannel(TwoFactorManager $manager, ChannelRegistry $channels, string $channel): int
    {
        $count = TwoFactorAuthentication::query()->where('channel', $channel)->count();

        if ($count === 0) {
            $this->components->info(sprintf('No user has the two-factor channel [%s], nothing to reset.', $channel));

            return self::SUCCESS;
        }

        if (! $channels->has($channel)) {
            $this->components->warn(sprintf(
                'The channel [%s] is not registered: only the data of nakipelo/orchid-2fa are reset, the data of its driver stay in its tables.',
                $channel,
            ));
        }

        if (! $this->confirmed(sprintf('Reset two-factor authentication of %d user(s) of the channel [%s]?', $count, $channel))) {
            return self::FAILURE;
        }

        $skipped = 0;

        $reset = $manager->resetChannel($channel, function (int|string $userId) use (&$skipped): void {
            $skipped++;
            $this->components->warn(sprintf('Skipped the record of the user #%s: the user provider did not return the user.', $userId));
        });

        $this->components->info(sprintf('Reset: %d user(s), skipped: %d.', $reset, $skipped));

        return self::SUCCESS;
    }

    /**
     * `--force` skips the question; without it a non-interactive run is refused.
     */
    protected function confirmed(string $question): bool
    {
        if ($this->option('force')) {
            return true;
        }

        if (! $this->input->isInteractive()) {
            $this->components->error('Refusing to reset without confirmation in a non-interactive run: pass --force.');

            return false;
        }

        if (! $this->components->confirm($question)) {
            $this->components->warn('Cancelled, nothing has been changed.');

            return false;
        }

        return true;
    }
}
