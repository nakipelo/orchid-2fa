<?php

declare(strict_types=1);

use Illuminate\Contracts\Container\Container;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Nakipelo\Orchid2FA\Challenge\Challenge;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\EmailChannel;
use Nakipelo\Orchid2FA\Exceptions\UnknownChannelException;
use Nakipelo\Orchid2FA\Facades\TwoFactor;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeDeliveryChannel;
use Nakipelo\Orchid2FA\Tests\Fixtures\ProbeVerifierChannel;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §4.1–§4.3, §10.1 "Registry": the channel registry and the base classes.
 */
beforeEach(function () {
    FakeDeliveryChannel::reset();
});

/**
 * An e-mail channel of an application registered with the 0.1 key `channels.email.class`.
 */
class LegacyEmailChannel extends EmailChannel {}

it('resolves the default e-mail channel from channels.email.driver and caches it', function () {
    $registry = app(ChannelRegistry::class);
    $email = $registry->channel('email');

    expect($email)->toBeInstanceOf(EmailChannel::class)
        ->and($registry->channel('email'))->toBe($email)
        ->and(TwoFactor::channel('email'))->toBe($email)
        ->and($email->name())->toBe('email')
        ->and($email->label())->toBe('E-mail')
        ->and($email->requiresDelivery())->toBeTrue()
        ->and($email->needsRecoveryCodes())->toBeFalse()
        ->and($email->challengeView())->toBeNull()
        ->and($email->enrollmentView())->toBeNull()
        ->and($email->codeInput()->length)->toBe(6)
        ->and($email->codeInput()->pattern)->toBe('\d{6}')
        ->and($email->codeInput()->inputmode)->toBe('numeric')
        ->and($email->codeInput()->autocomplete)->toBe('one-time-code')
        ->and($email->prompt(tfUser()))->toBe('We have sent a code to u***@example.com.')
        ->and($registry->has('email'))->toBeTrue()
        ->and($registry->registered())->toBe(['email'])
        ->and($registry->defaultName())->toBe('email');

    app()->setLocale('ru');
    expect($email->label())->toBe('Почта');
});

it('registers a driver with extend() and boots it with its name and config', function () {
    config(['orchid-2fa.channels.fake' => ['option' => 'value']]);
    $received = null;

    TwoFactor::extend('fake', function (Container $app, array $config) use (&$received) {
        $received = [$app, $config];

        return new FakeDeliveryChannel;
    });

    $channel = TwoFactor::channel('fake');

    expect($channel)->toBeInstanceOf(FakeDeliveryChannel::class)
        ->and($channel->name())->toBe('fake')
        ->and($channel->bootedConfig())->toBe(['option' => 'value'])
        ->and($received[0])->toBe(app())
        ->and($received[1])->toBe(['option' => 'value'])
        ->and(TwoFactor::has('fake'))->toBeTrue()
        ->and(TwoFactor::registered())->toBe(['email', 'fake']);
});

it('uses an extension name or a class-string as channels.<name>.driver', function () {
    TwoFactor::extend('fake', fn () => new FakeDeliveryChannel);
    config([
        'orchid-2fa.channels.sms' => ['driver' => 'fake', 'sender' => 'ACME'],
        'orchid-2fa.channels.phone' => ['driver' => FakeDeliveryChannel::class],
    ]);

    $sms = TwoFactor::channel('sms');
    $phone = TwoFactor::channel('phone');

    expect($sms)->toBeInstanceOf(FakeDeliveryChannel::class)
        ->and($sms->name())->toBe('sms')
        ->and($sms->bootedConfig())->toBe(['driver' => 'fake', 'sender' => 'ACME'])
        ->and($phone)->toBeInstanceOf(FakeDeliveryChannel::class)
        ->and($phone->name())->toBe('phone')
        ->and($phone)->not->toBe($sms)
        ->and(TwoFactor::registered())->toBe(['email', 'sms', 'phone', 'fake']);
});

it('reads the 0.1 key channels.<name>.class when driver is not set', function () {
    // A published config of 0.1: mergeConfigFrom() keeps the published `channels` as a whole.
    config(['orchid-2fa.channels' => ['email' => ['class' => LegacyEmailChannel::class, 'attribute' => 'email']]]);

    expect(TwoFactor::channel('email'))->toBeInstanceOf(LegacyEmailChannel::class)
        ->and(TwoFactor::registered())->toBe(['email']);

    TwoFactor::forgetChannels();
    config(['orchid-2fa.channels.email.driver' => EmailChannel::class]);

    expect(TwoFactor::channel('email'))->not->toBeInstanceOf(LegacyEmailChannel::class);
});

it('refuses a driver that does not extend a base class', function () {
    config(['orchid-2fa.channels.plain.driver' => stdClass::class]);
    TwoFactor::extend('closure', fn () => new stdClass);

    expect(fn () => TwoFactor::channel('plain'))->toThrow(InvalidArgumentException::class, 'must be a driver registered')
        ->and(fn () => TwoFactor::channel('closure'))->toThrow(InvalidArgumentException::class, 'must extend');
});

it('refuses an unknown channel name', function () {
    expect(TwoFactor::has('missing'))->toBeFalse()
        ->and(fn () => TwoFactor::channel('missing'))->toThrow(UnknownChannelException::class, '[missing]');
});

it('intersects channels.allowed with the registered channels in its order', function () {
    expect(TwoFactor::allowed())->toBe(['email']);

    TwoFactor::extend('fake', fn () => new FakeDeliveryChannel);
    config(['orchid-2fa.channels.allowed' => ['fake', 'missing', 'email']]);

    expect(TwoFactor::allowed())->toBe(['fake', 'email'])
        ->and(TwoFactor::registered())->toBe(['email', 'fake']);
});

it('picks the channel of the user record, otherwise the default channel', function () {
    TwoFactor::extend('fake', fn () => new FakeDeliveryChannel);
    config(['orchid-2fa.channels.allowed' => ['email', 'fake']]);
    $user = tfUser();

    expect(TwoFactor::for($user)?->name())->toBe('email');

    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'channel' => 'fake']);
    expect(TwoFactor::for($user)?->name())->toBe('fake');

    // A channel whose driver is gone: no method, the login fails closed (spec 0.2 §4.5 item 3).
    TwoFactorAuthentication::query()->where('user_id', $user->id)->update(['channel' => 'gone']);
    expect(TwoFactor::for($user))->toBeNull()
        ->and(TwoFactor::methodFor($user)->state)->toBe('unavailable');

    TwoFactorAuthentication::query()->where('user_id', $user->id)->update(['channel' => null]);
    config(['orchid-2fa.channel' => 'fake']);
    expect(TwoFactor::for($user)?->name())->toBe('fake');

    config(['orchid-2fa.channel' => 'nothing']);
    expect(TwoFactor::for($user))->toBeNull()
        ->and(TwoFactor::methodFor($user)->state)->toBe('none');
});

it('issues a verifier challenge without side effects and fails closed on a driver error', function () {
    $channel = new ProbeVerifierChannel;
    $channel->bootChannel('probe', []);
    $user = tfUser();

    $challenge = $channel->issue($user, 'login');

    expect($challenge)->toBeInstanceOf(Challenge::class)
        ->and($challenge->channel)->toBe('probe')
        ->and($challenge->context)->toBe('login')
        ->and($challenge->expiresAt)->toBeNull()
        ->and(strlen($challenge->id))->toBe(40)
        ->and($channel->issue($user, 'login')->id)->not->toBe($challenge->id)
        ->and($channel->requiresDelivery())->toBeFalse()
        ->and($channel->needsRecoveryCodes())->toBeTrue()
        ->and($channel->allowsEmailFallback($user))->toBeFalse()
        ->and($channel->prompt($user))->toBe('Enter the code from your authenticator app.')
        ->and($channel->label())->toBe('Probe')
        ->and($channel->verify($user, $challenge, ' 424-242 '))->toBe(VerificationResult::Passed)
        ->and($channel->verify($user, $challenge, '000000'))->toBe(VerificationResult::Invalid)
        ->and($channel->verify($user, $challenge, ' - '))->toBe(VerificationResult::Invalid)
        ->and($channel->calls)->toBe(2);

    $channel->failWith = new RuntimeException('secret storage is down');

    expect($channel->verify($user, $challenge, '424242'))->toBe(VerificationResult::Invalid)
        ->and($this->logHandler()->hasErrorThatContains('the two-factor channel failed to verify a code'))->toBeTrue();
});

it('needs the registry to boot a channel before it has a name', function () {
    expect(fn () => (new ProbeVerifierChannel)->name())->toThrow(LogicException::class);
});

it('keeps the enrollment state bound to the user, channel and context', function () {
    $session = app('session')->driver();
    $user = tfUser();
    $other = tfUser('other@example.com');

    $state = EnrollmentState::start($session, $user, 'fake', 'enroll');
    $state->put('secret', 's3cr3t');

    $restored = EnrollmentState::fromSession($session, $user, 'fake', 'enroll', 900);

    expect($restored?->challengeId())->toBe($state->challengeId())
        ->and($restored?->get('secret'))->toBe('s3cr3t')
        ->and($restored?->get('missing', 'default'))->toBe('default')
        ->and(EnrollmentState::fromSession($session, $other, 'fake', 'enroll', 900))->toBeNull()
        ->and(EnrollmentState::fromSession($session, $user, 'email', 'enroll', 900))->toBeNull()
        ->and(EnrollmentState::fromSession($session, $user, 'fake', 'switch', 900))->toBeNull();

    $this->travel(900)->seconds();
    expect(EnrollmentState::fromSession($session, $user, 'fake', 'enroll', 900))->toBeNull();

    EnrollmentState::forget($session);
    expect($session->has(EnrollmentState::SESSION_KEY))->toBeFalse();
});
