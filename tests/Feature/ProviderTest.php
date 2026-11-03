<?php

declare(strict_types=1);

use Illuminate\Support\ServiceProvider;
use Nakipelo\Orchid2FA\Concerns\HasTwoFactor;
use Nakipelo\Orchid2FA\Orchid2FAServiceProvider;
use Workbench\App\Models\User;

it('merges the default config', function () {
    expect(config('orchid-2fa'))->toMatchArray([
        'enforce_all' => false,
        'channel' => 'email',
        'pending_ttl' => 600,
    ])
        ->and(config('orchid-2fa.channels.email'))->toBe([
            'driver' => 'Nakipelo\\Orchid2FA\\Channels\\EmailChannel',
            'attribute' => 'email',
        ])
        ->and(config('orchid-2fa.notification'))->toBe([
            'class' => 'Nakipelo\\Orchid2FA\\Notifications\\TwoFactorCodeNotification',
            'email_changed_class' => 'Nakipelo\\Orchid2FA\\Notifications\\TwoFactorEmailChangedNotification',
            'queue' => false,
            'connection' => null,
            'queue_name' => null,
        ])
        ->and(config('orchid-2fa.code'))->toBe(['length' => 6, 'ttl' => 600, 'max_attempts' => 5])
        ->and(config('orchid-2fa.resend'))->toBe(['cooldown' => 60, 'max_per_hour' => 5])
        ->and(config('orchid-2fa.trusted_devices'))->toBe(['enabled' => true, 'lifetime_days' => 30, 'cookie' => 'orchid_2fa_trusted'])
        ->and(config('orchid-2fa.cache.store'))->toBeNull()
        ->and(config('orchid-2fa.routes.throttle'))->toBe('10,1')
        ->and(config('orchid-2fa.menu.enabled'))->toBeFalse()
        ->and(config('orchid-2fa.log'))->toBe(['enabled' => false, 'channel' => null]);
});

it('does not warn about the trait when the user model uses HasTwoFactor', function () {
    expect(class_uses_recursive(User::class))->toContain(HasTwoFactor::class);

    $warnings = array_filter(
        $this->logHandler()->getRecords(),
        fn ($record) => str_contains($record->message, 'HasTwoFactor'),
    );

    expect($warnings)->toBeEmpty();
});

it('warns in local/testing when the user model lacks HasTwoFactor', function () {
    config(['auth.providers.users.model' => Orchid\Platform\Models\User::class]);
    app('auth')->forgetGuards();

    $this->app->register(Orchid2FAServiceProvider::class, force: true);

    expect($this->logHandler()->hasWarningThatContains('does not use the Nakipelo\Orchid2FA\Concerns\HasTwoFactor trait'))->toBeTrue();
});

it('registers publish tags', function () {
    expect(ServiceProvider::pathsToPublish(Orchid2FAServiceProvider::class, 'orchid-2fa-config'))->toHaveCount(1)
        ->and(ServiceProvider::pathsToPublish(Orchid2FAServiceProvider::class, 'orchid-2fa-migrations'))->toHaveCount(1);
});

it('registers the translations tag', function () {
    $paths = ServiceProvider::pathsToPublish(Orchid2FAServiceProvider::class, 'orchid-2fa-translations');

    expect($paths)->toHaveCount(1)
        ->and(array_values($paths)[0])->toBe(app()->langPath('vendor/orchid-2fa'));
});

it('publishes the migration under its own name, so the copy replaces the package file', function () {
    $source = realpath(dirname(__DIR__, 2).'/database/migrations');

    $paths = ServiceProvider::pathsToPublish(Orchid2FAServiceProvider::class, 'orchid-2fa-migrations');

    // publishesMigrations() would register the path here and rename the copy with a new timestamp.
    expect(array_map('realpath', array_keys($paths)))->toBe([$source])
        ->and(array_values($paths))->toBe([database_path('migrations')])
        ->and(array_map('realpath', ServiceProvider::publishableMigrationPaths()))->not->toContain($source);

    $copy = sys_get_temp_dir().'/orchid-2fa-migrations-'.uniqid();
    mkdir($copy);

    try {
        foreach (glob($source.'/*.php') ?: [] as $file) {
            copy($file, $copy.'/'.basename($file));
        }

        $files = app('migrator')->getMigrationFiles([$source, $copy]);

        expect($files)->toHaveCount(1)
            ->and(dirname((string) reset($files)))->toBe($copy);
    } finally {
        array_map('unlink', glob($copy.'/*.php') ?: []);
        rmdir($copy);
    }
});
