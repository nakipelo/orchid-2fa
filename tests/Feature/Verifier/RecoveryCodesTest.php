<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Events\RecoveryCodeUsed;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Models\TwoFactorRecoveryCode;
use Nakipelo\Orchid2FA\Notifications\TwoFactorSecurityNotification;
use Nakipelo\Orchid2FA\Recovery\RecoveryCodes;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §4.7, §5.3, §10.1 "recovery codes".
 */
beforeEach(function () {
    Notification::fake();
    tfUseFake();
});

it('issues 8 codes xxxx-xxxx from the alphabet without 0/o/1/l/i and keeps only hashes', function () {
    $user = tfFakeUser();

    $codes = app(RecoveryCodes::class)->generate($user);

    expect($codes)->toHaveCount(8)
        ->each->toMatch('/^[23456789abcdefghjkmnpqrstuvwxyz]{4}-[23456789abcdefghjkmnpqrstuvwxyz]{4}$/')
        ->and(array_unique($codes))->toHaveCount(8);

    $rows = TwoFactorRecoveryCode::query()->where('user_id', $user->id)->get();
    expect($rows)->toHaveCount(8)
        ->and($rows->pluck('code_hash')->intersect($codes))->toBeEmpty()
        ->and(Hash::check(str_replace('-', '', $codes[0]), $rows->first()->code_hash))->toBeTrue();

    // A new set replaces the old one.
    $new = app(RecoveryCodes::class)->generate($user);
    expect(TwoFactorRecoveryCode::query()->where('user_id', $user->id)->count())->toBe(8)
        ->and(app(RecoveryCodes::class)->consume($user, $codes[0]))->toBeFalse()
        ->and(app(RecoveryCodes::class)->consume($user, $new[0]))->toBeTrue();
});

it('consumes a code once, ignoring case, spaces and the dash', function () {
    $user = tfFakeUser();
    $recovery = app(RecoveryCodes::class);
    $code = $recovery->generate($user)[3];

    expect($recovery->consume($user, ' '.strtoupper(str_replace('-', ' ', $code)).' '))->toBeTrue()
        ->and($recovery->consume($user, $code))->toBeFalse()
        ->and($recovery->remaining($user))->toBe(7)
        ->and($recovery->consume(tfUser('other@example.com'), $recovery->generate($user)[0]))->toBeFalse();
});

it('signs in with a recovery code without a trusted device cookie, even if asked', function () {
    Event::fake([TwoFactorPassed::class, RecoveryCodeUsed::class]);
    $user = tfFakeUser();
    $codes = app(RecoveryCodes::class)->generate($user);
    tfLogin();

    $response = $this->from(route('platform.two-factor.challenge'))
        ->post(route('platform.two-factor.recovery'), ['recovery_code' => $codes[0], 'trust_device' => '1']);

    $response->assertRedirect(route('platform.main'))
        ->assertCookieMissing(app(TrustedDeviceCookie::class)->name($user->id));
    $this->assertAuthenticatedAs($user);

    expect(session('orchid-2fa.recovery_login'))->toBeTrue();
    Event::assertDispatched(TwoFactorPassed::class, fn ($event) => $event->via === 'recovery_code' && ! $event->trustedDeviceIssued && $event->channel === 'fake');
    Event::assertDispatched(RecoveryCodeUsed::class, fn ($event) => $event->remaining === 7 && $event->context === 'login' && $event->channel === 'fake');

    $notice = Notification::sent(new AnonymousNotifiable, TwoFactorSecurityNotification::class)->first();
    expect($notice->event)->toBe('recovery_code_used')
        ->and($notice->context)->toMatchArray(['remaining' => 7, 'context' => 'login']);

    // The method stays; the profile shows the banner.
    $this->get(route('platform.profile.two-factor'))
        ->assertSee('You have signed in with a recovery code. Recovery codes left: 7.');
});

it('refuses a wrong recovery code and counts it against the user', function () {
    Event::fake([TwoFactorFailed::class]);
    $user = tfFakeUser();
    app(RecoveryCodes::class)->generate($user);
    tfLogin();

    $this->from(route('platform.two-factor.challenge'))
        ->post(route('platform.two-factor.recovery'), ['recovery_code' => 'aaaa-aaaa'])
        ->assertRedirect(route('platform.two-factor.challenge'))
        ->assertSessionHasErrors(['recovery_code' => 'The recovery code is incorrect. Attempts left: 4.']);

    $this->assertGuest();
    expect(cache()->get('orchid-2fa:verifier:'.$user->id))->toBe(1);
    Event::assertDispatched(TwoFactorFailed::class, fn ($event) => $event->reason === 'invalid_recovery_code');
});

it('offers the recovery code even without codes left and refuses any input then', function () {
    $user = tfFakeUser();
    tfLogin();

    $this->get(route('platform.two-factor.challenge'))->assertSee(route('platform.two-factor.recovery'), false);

    $this->post(route('platform.two-factor.recovery'), ['recovery_code' => 'aaaa-aaaa'])->assertSessionHasErrors('recovery_code');
    $this->assertGuest();
});

it('has no recovery code form for e-mail', function () {
    tfEnforcedUser();
    tfLogin();

    $this->get(route('platform.two-factor.challenge'))
        ->assertOk()
        ->assertDontSee(route('platform.two-factor.recovery'), false)
        ->assertSee(route('platform.two-factor.resend'), false);
});

it('drops the pending login after 5 wrong recovery codes', function () {
    $user = tfFakeUser();
    app(RecoveryCodes::class)->generate($user);
    tfLogin();

    foreach (range(1, 4) as $ignored) {
        $this->post(route('platform.two-factor.recovery'), ['recovery_code' => 'aaaa-aaaa'])->assertSessionHasErrors('recovery_code');
    }

    $this->post(route('platform.two-factor.recovery'), ['recovery_code' => 'aaaa-aaaa'])
        ->assertRedirect(route('platform.login'));
    expect(session()->has('orchid-2fa.pending'))->toBeFalse();
});
