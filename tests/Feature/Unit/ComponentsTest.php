<?php

declare(strict_types=1);

use Illuminate\Foundation\Auth\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\ServiceProvider;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\CodeStore;
use Nakipelo\Orchid2FA\Challenge\PendingLogin;
use Nakipelo\Orchid2FA\Challenge\StoredCode;
use Nakipelo\Orchid2FA\Channels\EmailChannel;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Notifications\TwoFactorCodeNotification;
use Nakipelo\Orchid2FA\Orchid2FAServiceProvider;
use Nakipelo\Orchid2FA\Policy\TwoFactorPolicy;
use Nakipelo\Orchid2FA\Support\Orchid;
use Orchid\Access\UserAccess;

uses(RefreshDatabase::class);

it('masks the address', function (string $address, string $masked) {
    expect(EmailChannel::mask($address))->toBe($masked);
})->with([
    ['egor@gmail.com', 'e***@gmail.com'],
    ['e@example.com', 'e***@example.com'],
    ['юзер@почта.рф', 'ю***@почта.рф'],
    ['a+b@c@example.com', 'a***@example.com'],
    ['nodomain', 'n***'],
    ['', ''],
]);

it('reads the address from the configured attribute', function () {
    $user = tfUser();
    $channel = app(EmailChannel::class);

    expect($channel->name())->toBe('email')
        ->and($channel->destination($user))->toBe('user@example.com')
        ->and($channel->isAvailableFor($user))->toBeTrue();

    config(['orchid-2fa.channels.email.attribute' => 'name']);
    expect($channel->destination($user))->toBe('user');

    config(['orchid-2fa.channels.email.attribute' => 'missing']);
    expect($channel->isAvailableFor($user))->toBeFalse();
});

it('stores only an HMAC of the code', function () {
    Notification::fake();
    $user = tfEnforcedUser();

    $challenge = app(ChallengeManager::class)->issue($user);
    $code = tfLastCode();

    $raw = cache()->get('orchid-2fa:code:'.$user->id);
    expect($raw)->toBeArray()->toHaveKeys(['hash', 'challenge_id', 'destination_hash', 'expires_at'])
        ->and($raw['challenge_id'])->toBe($challenge)
        ->and(json_encode($raw))->not->toContain($code)
        ->and($raw['hash'])->toBe(hash_hmac('sha256', $code.'|'.$challenge, config('app.key')))
        ->and($raw['destination_hash'])->toBe(hash_hmac('sha256', 'enforced@example.com', config('app.key')));
});

it('uses the configured cache store', function () {
    config(['cache.stores.codes' => ['driver' => 'array'], 'orchid-2fa.cache.store' => 'codes']);
    $store = app(CodeStore::class);

    $store->put(1, new StoredCode('h', 'c', 'd', now()->addMinute()->getTimestamp()));

    expect(cache()->store('codes')->get('orchid-2fa:code:1'))->not->toBeNull()
        ->and(cache()->store()->get('orchid-2fa:code:1'))->toBeNull()
        ->and($store->get(1)?->challengeId)->toBe('c');
});

it('drops expired and malformed records', function () {
    $store = app(CodeStore::class);

    $store->put(1, new StoredCode('h', 'c', 'd', now()->addSeconds(10)->getTimestamp()));
    $this->travel(11)->seconds();
    expect($store->get(1))->toBeNull();

    cache()->put('orchid-2fa:code:2', ['hash' => 1]);
    expect($store->get(2))->toBeNull();
});

it('claims a code once', function () {
    $store = app(CodeStore::class);
    $code = new StoredCode('h', 'c', 'd', now()->addMinute()->getTimestamp());

    expect($store->claim(1, $code))->toBeTrue()
        ->and($store->claim(1, $code))->toBeFalse()
        ->and($store->claim(2, $code))->toBeTrue();
});

it('generates codes of the configured length with leading zeros', function () {
    Notification::fake();
    config(['orchid-2fa.code.length' => 8, 'orchid-2fa.resend.cooldown' => 0, 'orchid-2fa.resend.max_per_hour' => 100]);
    $user = tfEnforcedUser();

    foreach (range(1, 30) as $i) {
        app(ChallengeManager::class)->issue($user);
    }

    expect(tfSentCodes())->each->toMatch('/^\d{8}$/');
});

it('keeps the pending login in the session', function () {
    $session = app('session')->driver();
    $pending = new PendingLogin(5, true, now()->getTimestamp(), 'challenge');

    $pending->store($session);

    expect($session->get('orchid-2fa.pending'))->toBe([
        'user_id' => 5, 'remember' => true, 'created_at' => now()->getTimestamp(), 'challenge_id' => 'challenge',
    ])
        ->and(PendingLogin::fromSession($session))->toEqual($pending)
        ->and($pending->isExpired(600))->toBeFalse()
        ->and($pending->withChallenge('other')->challengeId)->toBe('other');

    $this->travel(600)->seconds();
    expect($pending->isExpired(600))->toBeTrue();

    $session->put('orchid-2fa.pending', ['user_id' => 5]);
    expect(PendingLogin::fromSession($session))->toBeNull();

    PendingLogin::forget($session);
    expect($session->has('orchid-2fa.pending'))->toBeFalse();
});

it('decides who needs 2FA', function () {
    $policy = app(TwoFactorPolicy::class);
    $plain = tfUser();
    $enforced = tfEnforcedUser();
    $voluntary = tfUser('voluntary@example.com');
    TwoFactorAuthentication::query()->create(['user_id' => $voluntary->id, 'enabled_at' => now()]);

    expect($policy->requires($plain))->toBeFalse()
        ->and($policy->isEnforced($enforced))->toBeTrue()
        ->and($policy->isEnabled($enforced))->toBeFalse()
        ->and($policy->requires($enforced))->toBeTrue()
        ->and($policy->isEnforced($voluntary))->toBeFalse()
        ->and($policy->isEnabled($voluntary))->toBeTrue()
        ->and($policy->requires($voluntary))->toBeTrue();

    config(['orchid-2fa.enforce_all' => true]);
    expect($policy->isEnforced($plain))->toBeTrue();
});

it('renders the code notification', function () {
    $this->freezeTime();
    $mail = (new TwoFactorCodeNotification('012345', now()->addMinutes(10)))->toMail(null);

    expect($mail->subject)->toBe('Your sign-in code')
        ->and($mail->introLines)->toBe([
            'Your verification code: 012345',
            'The code is valid for 10 min.',
            'If you did not try to sign in, change your password.',
        ]);
});

it('names the package routes through the adapter', function () {
    expect(Orchid::challengeRoute())->toBe('platform.two-factor.challenge')
        ->and(route(Orchid::challengeRoute(), absolute: false))->toBe('/admin/two-factor')
        ->and(route(Orchid::verifyRoute(), absolute: false))->toBe('/admin/two-factor')
        ->and(route(Orchid::resendRoute(), absolute: false))->toBe('/admin/two-factor/resend')
        ->and(route(Orchid::cancelRoute(), absolute: false))->toBe('/admin/two-factor/cancel')
        ->and(Orchid::requiredPermission())->toBe('platform.2fa.required')
        ->and(Orchid::lockCookieName())->toBe(Orchid::guard()->getName().'__orchid_lock');

    foreach (['challenge', 'verify', 'resend', 'cancel'] as $name) {
        expect(app('router')->getRoutes()->getByName('platform.two-factor.'.$name)->gatherMiddleware())
            ->toContain('web')
            ->toContain(Orchid::guestMiddleware());
    }
});

it('registers the view and translation publish tags', function () {
    expect(ServiceProvider::pathsToPublish(Orchid2FAServiceProvider::class, 'orchid-2fa-views'))->toHaveCount(1)
        ->and(ServiceProvider::pathsToPublish(Orchid2FAServiceProvider::class, 'orchid-2fa-translations'))->toHaveCount(1)
        ->and(view()->exists('orchid-2fa::challenge'))->toBeTrue()
        ->and(__('orchid-2fa::messages.challenge.title', [], 'ru'))->toBe('Двухфакторная аутентификация');
});

it('has the same translation keys in en and ru', function () {
    $keys = fn (string $locale) => array_keys(Arr::dot(require dirname(__DIR__, 3)."/lang/{$locale}/messages.php"));

    expect($keys('ru'))->toBe($keys('en'));
});

it('reads Orchid permissions of any user model', function () {
    $orchidTrait = new class extends User
    {
        use UserAccess;

        protected $table = 'users';

        protected $casts = ['permissions' => 'array'];
    };
    $orchidTrait->forceFill(['id' => 999, 'permissions' => ['platform.2fa.required' => true]]);

    $plain = new class extends User {};

    expect(Orchid::userHasPermission(tfEnforcedUser(), 'platform.2fa.required'))->toBeTrue()
        ->and(Orchid::userHasPermission(tfUser(), 'platform.2fa.required'))->toBeFalse()
        ->and(Orchid::userHasPermission($orchidTrait, 'platform.2fa.required'))->toBeTrue()
        ->and(Orchid::userHasPermission($plain, 'platform.2fa.required'))->toBeFalse();
});
