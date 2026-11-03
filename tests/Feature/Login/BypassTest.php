<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\CodeStore;
use Nakipelo\Orchid2FA\Challenge\PendingLogin;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;

uses(RefreshDatabase::class);

/**
 * Spec §9, §10 "Попытки обхода" (stage 2 part).
 */
beforeEach(function () {
    Notification::fake();
});

it('keeps the admin panel closed while the login is pending', function () {
    tfEnforcedUser();
    tfLogin();

    $this->get(route('platform.main'))->assertRedirect(route('platform.login'));
    $this->get('/admin/users')->assertRedirect(route('platform.login'));
    $this->getJson(route('platform.main'))->assertUnauthorized();
    $this->assertGuest();
});

it('does not accept a used code again', function () {
    tfFixCodes('111111', '222222');
    tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();
    expect($code)->toBe('111111');
    tfVerify($code)->assertRedirect(route('platform.main'));

    $this->post('/admin/logout');
    $this->assertGuest();
    $this->travel(61)->seconds();

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    // A used code is not "active": the new login sends a new one.
    expect(tfSentCodes())->toBe(['111111', '222222']);

    tfVerify($code)->assertSessionHasErrors('code');
    $this->assertGuest();
});

it('does not accept a code of a previous challenge', function () {
    tfFixCodes('111111', '222222');
    config(['orchid-2fa.resend.cooldown' => 0]);
    tfEnforcedUser();
    tfLogin();
    $old = tfLastCode();

    $this->post(route('platform.two-factor.resend'));
    $new = tfLastCode();
    expect([$old, $new])->toBe(['111111', '222222']);

    tfVerify($old)->assertSessionHasErrors('code');
    $this->assertGuest();

    tfVerify($new)->assertRedirect(route('platform.main'));
});

it('does not accept a code from another session', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();

    // Another session of the same user with a different challenge id.
    $pending = PendingLogin::fromSession(session()->driver());
    $pending->withChallenge('another-challenge')->store(session()->driver());

    tfVerify($code)->assertSessionHasErrors(['code' => 'The code is no longer valid. Please request a new one.']);
    $this->assertGuest();
});

it('ignores user_id in the request', function () {
    $victim = tfEnforcedUser('victim@example.com');
    $attacker = tfEnforcedUser('attacker@example.com');

    tfLogin('attacker@example.com');
    $code = tfLastCode('attacker@example.com');

    tfVerify($code, ['user_id' => $victim->id, 'email' => 'victim@example.com'])
        ->assertRedirect(route('platform.main'));

    $this->assertAuthenticatedAs($attacker);
});

it('does not let a code of one user in as another', function () {
    tfFixCodes('111111', '222222');
    tfEnforcedUser('victim@example.com');
    tfEnforcedUser('attacker@example.com');

    tfLogin('victim@example.com');
    $victimCode = tfLastCode('victim@example.com');
    $this->post(route('platform.two-factor.cancel'));

    tfLogin('attacker@example.com');
    $attackerCode = tfLastCode('attacker@example.com');
    expect([$victimCode, $attackerCode])->toBe(['111111', '222222']);

    tfVerify($victimCode)->assertSessionHasErrors('code');
    $this->assertGuest();
});

it('rejects verify without a pending login', function () {
    tfEnforcedUser();

    tfVerify('123456', ['user_id' => 1])->assertRedirect(route('platform.login'));
    $this->assertGuest();
});

it('rejects the code after the e-mail address changed', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();

    $user->forceFill(['email' => 'new@example.com'])->save();

    tfVerify($code)->assertSessionHasErrors(['code' => 'The code is no longer valid. Please request a new one.']);
    $this->assertGuest();
    expect(cache()->get('orchid-2fa:code:'.$user->id))->toBeNull();
});

it('consumes a code only once under parallel verification', function () {
    $user = tfEnforcedUser();
    $manager = app(ChallengeManager::class);
    $challenge = $manager->issue($user);
    $code = tfLastCode();

    $stored = app(CodeStore::class)->get($user->id);
    // The other request claimed the code between the comparison and the claim.
    expect(app(CodeStore::class)->claim($user->id, $stored))->toBeTrue()
        ->and($manager->verify($user, $challenge, $code))->toBe(VerificationResult::Expired);
});

it('refuses a second, sequential verification with the same code', function () {
    config(['orchid-2fa.resend.cooldown' => 0]);
    $user = tfEnforcedUser();
    $manager = app(ChallengeManager::class);
    $challenge = $manager->issue($user);
    $code = tfLastCode();

    expect($manager->verify($user, $challenge, $code))->toBe(VerificationResult::Passed)
        ->and($manager->verify($user, $challenge, $code))->toBe(VerificationResult::Expired);
});

it('counts the attempt before comparing', function () {
    $user = tfEnforcedUser();
    $manager = app(ChallengeManager::class);
    $challenge = $manager->issue($user);
    $code = tfLastCode();

    // Parallel wrong guesses already used up the attempts: even the right code is refused.
    $key = 'orchid-2fa:verify:'.$user->id.':'.$challenge;
    foreach (range(1, 5) as $i) {
        app(RateLimiter::class)->hit($key, 600);
    }

    expect($manager->verify($user, $challenge, $code))->toBe(VerificationResult::Expired)
        ->and(app(CodeStore::class)->get($user->id))->toBeNull();
});

it('ends the pending login when the password changes before the code', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();

    // For example, an administrator changes a compromised password while the code step is pending.
    $user->forceFill(['password' => Hash::make('completely-new')])->save();

    tfVerify($code)
        ->assertRedirect(route('platform.login'))
        ->assertSessionHasErrors(['email' => 'Your password has been changed. Please sign in again.']);
    $this->assertGuest();
    expect(PendingLogin::fromSession(session()->driver()))->toBeNull();

    // The pending login is gone: the code does not work afterwards either.
    tfVerify($code)->assertRedirect(route('platform.login'));
    $this->assertGuest();
});

it('does not resend the code or show the code screen after the password changed', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $user->forceFill(['password' => Hash::make('completely-new')])->save();

    $this->get(route('platform.two-factor.challenge'))
        ->assertRedirect(route('platform.login'))
        ->assertSessionHasErrors(['email' => 'Your password has been changed. Please sign in again.']);

    tfLogin(password: 'completely-new')->assertRedirect(route('platform.two-factor.challenge'));
    $user->forceFill(['password' => Hash::make('another-one')])->save();
    $this->travel(61)->seconds();

    $this->post(route('platform.two-factor.resend'))
        ->assertRedirect(route('platform.login'))
        ->assertSessionHasErrors(['email' => 'Your password has been changed. Please sign in again.']);
    expect(tfSentCodes())->toHaveCount(1);
});

it('answers JSON clients when the password changed before the code', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();
    $user->forceFill(['password' => Hash::make('completely-new')])->save();

    $this->postJson('/admin/two-factor', ['code' => $code])
        ->assertUnprocessable()
        ->assertJsonValidationErrors(['code' => 'Your password has been changed. Please sign in again.']);
    $this->assertGuest();
});

it('keeps the pending login when only the password hash is rehashed at the password step', function () {
    $user = tfEnforcedUser();
    $user->forceFill(['password' => Hash::make('password', ['rounds' => 4])])->save();
    $old = $user->password;

    tfLogin();
    expect($user->refresh()->password)->not->toBe($old);

    tfVerify(tfLastCode())->assertRedirect(route('platform.main'));
    $this->assertAuthenticatedAs($user);
});

it('does not keep the password hash in the session', function () {
    $user = tfEnforcedUser();
    tfLogin();

    $session = json_encode(session()->all());
    expect($session)->not->toContain($user->refresh()->getAuthPassword())
        ->and($session)->not->toContain(json_encode($user->getAuthPassword()));
});
