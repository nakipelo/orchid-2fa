<?php

declare(strict_types=1);

use Illuminate\Foundation\Console\AboutCommand;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Monolog\Level;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Facades\TwoFactor;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierChannel;
use Psr\Log\LoggerInterface;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §4.3, §10.1 "registry": `channels.allowed`, ignored names, an empty result, `about`.
 */
beforeEach(function () {
    Notification::fake();
});

it('ignores names without a driver and warns about them in local/testing', function () {
    // The default ['email', 'totp'] without the TOTP driver: totp is ignored, logged at boot.
    expect(TwoFactor::allowed())->toBe(['email'])
        ->and(TwoFactor::ignored())->toBe(['totp'])
        ->and($this->logHandler()->hasWarningThatContains('they are ignored: totp'))->toBeTrue();
});

it('does not warn about ignored names outside local/testing', function () {
    $this->logHandler()->reset();

    app(ChannelRegistry::class)->check(false, app('log')->channel());

    expect($this->logHandler()->getRecords())->toBeEmpty();
});

it('throws in local/testing when no channel is allowed', function () {
    config(['orchid-2fa.channels.allowed' => ['typo']]);

    expect(fn () => app(ChannelRegistry::class)->check(true, app('log')->channel()))
        ->toThrow(InvalidArgumentException::class, 'no two-factor channel is allowed');
});

it('logs a critical error elsewhere and fails closed only for users who need the second factor', function () {
    Event::fake([TwoFactorFailed::class]);
    config(['orchid-2fa.channels.allowed' => ['typo']]);

    app(ChannelRegistry::class)->check(false, app('log')->channel());

    expect(collect($this->logHandler()->getRecords())->contains(fn ($record) => $record->level === Level::Critical
        && str_contains($record->message, 'no two-factor channel is allowed')))->toBeTrue();

    tfEnforcedUser();
    tfLogin()->assertRedirect('/admin/login')
        ->assertSessionHasErrors(['email' => 'Your sign-in method is not available. Please contact your administrator.']);
    $this->assertGuest();
    expect(session()->has('orchid-2fa.pending'))->toBeFalse();
    Event::assertDispatched(TwoFactorFailed::class, fn ($event) => $event->reason === 'channel_unavailable');

    tfUser('plain@example.com');
    tfLogin('plain@example.com')->assertRedirect(route('platform.main'));
});

it('shows the channels in php artisan about', function () {
    FakeVerifierChannel::register();
    config(['orchid-2fa.channels.allowed' => ['fake', 'totp']]);

    // The resolvers of `php artisan about` (the command itself also runs Orchid's section, which
    // needs published assets on some versions).
    $resolvers = (new ReflectionProperty(AboutCommand::class, 'customDataResolvers'))->getValue();

    foreach ($resolvers as $resolver) {
        try {
            $resolver();
        } catch (Throwable) {
            // another package's section
        }
    }

    $data = (new ReflectionProperty(AboutCommand::class, 'data'))->getValue();
    $section = collect($data['Orchid 2FA'] ?? [])
        ->flatMap(fn ($row) => is_callable($row) ? $row() : [$row[0] => value($row[1])])
        ->all();

    expect($section)->toMatchArray([
        'Default channel' => 'email',
        'Registered channels' => 'email, fake',
        'Allowed channels' => 'fake',
        'Ignored channels' => 'totp',
    ]);

    expect(TwoFactor::registered())->toBe(['email', 'fake'])
        ->and(TwoFactor::allowed())->toBe(['fake'])
        ->and(TwoFactor::ignored())->toBe(['totp']);
});

it('creates a record with the default channel only when it is allowed', function () {
    tfUseFake(['fake']);
    $user = tfEnforcedUser();

    tfLogin()->assertRedirect(route('platform.two-factor.enroll'));

    expect(TwoFactorAuthentication::query()->where('user_id', $user->id)->value('channel'))->toBeNull()
        ->and(TwoFactor::initialName())->toBeNull();

    config(['orchid-2fa.channels.allowed' => ['email', 'fake']]);
    expect(TwoFactor::initialName())->toBe('email');
});

it('accepts a logger for the check', function () {
    $logger = Mockery::mock(LoggerInterface::class);
    $logger->shouldReceive('warning')->once();

    app(ChannelRegistry::class)->check(true, $logger);
});

it('throws in local/testing when an allowed driver cannot be created', function () {
    config([
        'orchid-2fa.channels.allowed' => ['email', 'plain'],
        'orchid-2fa.channels.plain.driver' => stdClass::class,
    ]);

    expect(fn () => app(ChannelRegistry::class)->check(true, app('log')->channel()))
        ->toThrow(InvalidArgumentException::class, 'the two-factor channel [plain] in [orchid-2fa.channels.allowed] cannot be created');

    TwoFactor::extend('closure', fn () => new stdClass);
    config(['orchid-2fa.channels.allowed' => ['email', 'closure']]);

    expect(fn () => app(ChannelRegistry::class)->check(true, app('log')->channel()))
        ->toThrow(InvalidArgumentException::class, '[closure] in [orchid-2fa.channels.allowed] cannot be created');
});

it('ignores an allowed driver that cannot be created elsewhere, with a warning and without an error page', function () {
    config([
        'orchid-2fa.channels.allowed' => ['plain', 'email'],
        'orchid-2fa.channels.plain.driver' => stdClass::class,
    ]);
    $this->logHandler()->reset();

    app(ChannelRegistry::class)->check(false, app('log')->channel());

    expect($this->logHandler()->hasWarningThatContains('the two-factor channel [plain] in [orchid-2fa.channels.allowed] cannot be created'))->toBeTrue()
        ->and(TwoFactor::allowed())->toBe(['email'])
        ->and(TwoFactor::ignored())->toBe(['plain']);

    // The users go on with the allowed e-mail; a user of the broken channel fails closed.
    tfEnforcedUser();
    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));

    $this->newBrowser();
    $broken = tfEnforcedUser('broken@example.com');
    TwoFactorAuthentication::query()->create(['user_id' => $broken->id, 'channel' => 'plain', 'confirmed_at' => now()]);
    tfLogin('broken@example.com')->assertRedirect('/admin/login')
        ->assertSessionHasErrors(['email' => 'Your sign-in method is not available. Please contact your administrator.']);
});
