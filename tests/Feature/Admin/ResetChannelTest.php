<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Events\TwoFactorChannelChanged;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Notifications\TwoFactorSecurityNotification;
use Nakipelo\Orchid2FA\Recovery\RecoveryCodes;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierChannel;
use Nakipelo\Orchid2FA\TwoFactorManager;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §5.10, §10.1 "reset": the reset of a verifier user, `orchid-2fa:reset --channel`.
 */
beforeEach(function () {
    Notification::fake();
    tfUseFake();
});

function rcRecord(User $user): TwoFactorAuthentication
{
    return TwoFactorAuthentication::query()->where('user_id', $user->id)->firstOrFail();
}

/**
 * Forget the driver `fake`, as if its package had been removed.
 */
function rcRemoveFake(): void
{
    $registry = app(ChannelRegistry::class);
    $extensions = new ReflectionProperty($registry, 'extensions');
    $extensions->setValue($registry, array_diff_key($extensions->getValue($registry), ['fake' => true]));
    $registry->forgetChannels();
}

it('resets a verifier user: driver data, recovery codes, channel, version, remember token, event and notice', function () {
    Event::fake([TwoFactorChannelChanged::class]);
    $user = tfFakeUser();
    $user->forceFill(['remember_token' => 'old-token'])->save();
    app(RecoveryCodes::class)->generate($user);

    app(TwoFactorManager::class)->reset($user);

    $record = rcRecord($user);
    expect($record->channel)->toBe('email')
        ->and($record->confirmed_at)->toBeNull()
        ->and($record->trusted_devices_version)->toBe(2)
        ->and(app(FakeVerifierChannel::class)->isAvailableFor($user))->toBeFalse()
        ->and(app(RecoveryCodes::class)->exists($user))->toBeFalse()
        ->and($user->refresh()->remember_token)->not->toBe('old-token');
    Event::assertDispatched(TwoFactorChannelChanged::class, fn ($event) => $event->from === 'fake' && $event->to === null && $event->reason === 'reset');

    $notice = Notification::sent(new AnonymousNotifiable, TwoFactorSecurityNotification::class)->first();
    expect($notice->event)->toBe('channel_changed')
        ->and($notice->context['reason'])->toBe('reset');

    // Enforced: the next login sends a code to the address.
    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    expect(tfSentCodes())->toHaveCount(1);
});

it('resets to no method when e-mail is not allowed, so the next login enrolls one', function () {
    config(['orchid-2fa.channels.allowed' => ['fake']]);
    $user = tfFakeUser();

    app(TwoFactorManager::class)->reset($user);

    expect(rcRecord($user)->channel)->toBeNull();
    tfLogin()->assertRedirect(route('platform.two-factor.enroll'));
});

/*
 * One rule for disabling (§4.8, §5.8) and a reset (§5.10): the record gets the default channel
 * (`orchid-2fa.channel`) when it is allowed and registered, otherwise null.
 */
it('gives the record the default channel after a reset and after disabling', function (string $operation, string $default, array $allowed, ?string $expected) {
    config(['orchid-2fa.channel' => $default, 'orchid-2fa.channels.allowed' => $allowed]);
    $user = tfFakeUser(enforced: $operation === 'reset');

    app(TwoFactorManager::class)->{$operation}($user);

    expect(rcRecord($user)->channel)->toBe($expected);
})->with([
    'reset, default e-mail' => ['reset', 'email', ['email', 'fake'], 'email'],
    'disable, default e-mail' => ['disable', 'email', ['email', 'fake'], 'email'],
    'reset, default fake' => ['reset', 'fake', ['email', 'fake'], 'fake'],
    'disable, default fake' => ['disable', 'fake', ['email', 'fake'], 'fake'],
    'reset, default not allowed' => ['reset', 'email', ['fake'], null],
    'disable, default not allowed' => ['disable', 'email', ['fake'], null],
    'reset, default allowed but not registered' => ['reset', 'sms', ['sms', 'email', 'fake'], null],
    'disable, default allowed but not registered' => ['disable', 'sms', ['sms', 'email', 'fake'], null],
]);

it('does not send the security notice when it is disabled', function () {
    config(['orchid-2fa.notification.security.enabled' => false]);

    app(TwoFactorManager::class)->reset(tfFakeUser());

    Notification::assertNothingSentTo(new AnonymousNotifiable);
});

it('uses the configured security notification class', function () {
    $class = new class('x') extends TwoFactorSecurityNotification {};
    config(['orchid-2fa.notification.security_class' => $class::class]);

    app(TwoFactorManager::class)->reset(tfFakeUser());

    Notification::assertSentOnDemand($class::class);
});

it('resets every user of a channel and only them with --force', function () {
    $a = tfFakeUser('a@example.com');
    $b = tfFakeUser('b@example.com', enforced: false);
    $email = tfEnforcedUser('c@example.com');
    TwoFactorAuthentication::query()->create(['user_id' => $email->id, 'channel' => 'email', 'confirmed_at' => now()]);

    $this->artisan('orchid-2fa:reset', ['--channel' => 'fake', '--force' => true])
        ->expectsOutputToContain('Reset: 2 user(s), skipped: 0.')
        ->assertSuccessful();

    expect(rcRecord($a)->channel)->toBe('email')
        ->and(rcRecord($b)->enabled_at)->toBeNull()
        ->and(rcRecord($email)->confirmed_at)->not->toBeNull()
        ->and(DB::table('two_factor_fake')->count())->toBe(0)
        ->and(Notification::sent(new AnonymousNotifiable, TwoFactorSecurityNotification::class))->toHaveCount(2);
});

it('asks for the confirmation with the number of users', function () {
    tfFakeUser('a@example.com');

    $this->artisan('orchid-2fa:reset', ['--channel' => 'fake'])
        ->expectsConfirmation('Reset two-factor authentication of 1 user(s) of the channel [fake]?', 'no')
        ->assertFailed();

    expect(TwoFactorAuthentication::query()->value('channel'))->toBe('fake');

    $this->artisan('orchid-2fa:reset', ['--channel' => 'fake'])
        ->expectsConfirmation('Reset two-factor authentication of 1 user(s) of the channel [fake]?', 'yes')
        ->assertSuccessful();

    expect(TwoFactorAuthentication::query()->value('channel'))->toBe('email');
});

it('refuses without --force in a non-interactive run', function () {
    tfFakeUser('a@example.com');

    $this->artisan('orchid-2fa:reset', ['--channel' => 'fake', '--no-interaction' => true])
        ->expectsOutputToContain('pass --force')
        ->assertExitCode(1);

    expect(TwoFactorAuthentication::query()->value('channel'))->toBe('fake');
});

it('refuses both an e-mail address and --channel, or neither', function (array $arguments) {
    tfFakeUser('a@example.com');

    $this->artisan('orchid-2fa:reset', $arguments + ['--force' => true])
        ->expectsOutputToContain('not both')
        ->assertExitCode(1);

    expect(TwoFactorAuthentication::query()->value('channel'))->toBe('fake');
})->with([
    'both' => [['email' => 'a@example.com', '--channel' => 'email']],
    'neither' => [[]],
]);

it('reports when no user has the channel', function () {
    $this->artisan('orchid-2fa:reset', ['--channel' => 'sms'])
        ->expectsOutputToContain('No user has the two-factor channel [sms]')
        ->assertSuccessful();
});

it('resets the users of a removed driver: only the data of the package, with a warning', function () {
    $user = tfFakeUser();
    app(RecoveryCodes::class)->generate($user);
    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    $this->newBrowser();

    rcRemoveFake();

    // Fail-closed until the reset (spec 0.2 §4.5 item 3).
    tfLogin()->assertSessionHasErrors('email');

    $this->artisan('orchid-2fa:reset', ['--channel' => 'fake', '--force' => true])
        ->expectsOutputToContain('The channel [fake] is not registered')
        ->expectsOutputToContain('Reset: 1 user(s), skipped: 0.')
        ->assertSuccessful();

    expect(rcRecord($user)->channel)->toBe('email')
        ->and(app(RecoveryCodes::class)->exists($user))->toBeFalse()
        // The table of the driver is not touched.
        ->and(DB::table('two_factor_fake')->where('user_id', $user->id)->exists())->toBeTrue()
        ->and($this->logHandler()->hasWarningThatContains('the two-factor channel [fake] is not registered'))->toBeTrue();

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    expect(tfSentCodes())->toHaveCount(1);
});

it('skips a record whose user the provider does not return', function () {
    tfFakeUser('a@example.com');
    $hidden = tfFakeUser('hidden@example.com');
    // The provider does not return the user (e.g. a global scope of the model).
    User::addGlobalScope('hidden', fn ($query) => $query->where('email', '!=', 'hidden@example.com'));

    try {
        $this->artisan('orchid-2fa:reset', ['--channel' => 'fake', '--force' => true])
            ->expectsOutputToContain('Skipped the record of the user #'.$hidden->id)
            ->expectsOutputToContain('Reset: 1 user(s), skipped: 1.')
            ->assertSuccessful();
    } finally {
        // Global scopes are static: do not leak into the next tests.
        User::clearBootedModels();
    }
});

it('still resets one user by the e-mail address', function () {
    $user = tfFakeUser('a@example.com');

    $this->artisan('orchid-2fa:reset', ['email' => 'a@example.com', '--force' => true])->assertSuccessful();

    expect(rcRecord($user)->channel)->toBe('email');
});

it('shows the method of a verifier user in the reset block, without an address', function () {
    $user = tfFakeUser();
    $admin = tfUser('admin@example.com', ['platform.index' => true, 'platform.systems.users' => true, 'platform.systems.users.2fa-reset' => true]);

    $this->actingAs($admin)
        ->get(route('platform.systems.users.edit', $user))
        ->assertOk()
        ->assertSee('Fake authenticator')
        ->assertDontSee('e***@example.com');
});
