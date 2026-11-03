<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Testing\TestResponse;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\ProfileChallenge;
use Nakipelo\Orchid2FA\Events\RecoveryCodesRegenerated;
use Nakipelo\Orchid2FA\Events\RecoveryCodeUsed;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorChannelChanged;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Notifications\TwoFactorSecurityNotification;
use Nakipelo\Orchid2FA\Recovery\RecoveryCodes;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierChannel;
use Orchid\Alert\Toast;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §5.5–§5.9, §6.3, §10.1 "profile transitions": enabling, switching, rebinding, disabling and
 * regenerating; the password; the recovery code.
 */
beforeEach(function () {
    Notification::fake();
    tfUseFake();
});

function ptUrl(?string $method = null): string
{
    return route('platform.profile.two-factor', $method === null ? [] : ['method' => $method]);
}

/**
 * @param  array<string, mixed>  $data
 */
function ptPost(string $method, array $data = []): TestResponse
{
    return test()->from(ptUrl())->post(ptUrl($method), $data);
}

function ptRecord(User $user): TwoFactorAuthentication
{
    return TwoFactorAuthentication::query()->where('user_id', $user->id)->firstOrFail();
}

function ptEmailUser(bool $enforced = false): User
{
    $user = $enforced ? tfEnforcedUser('user@example.com') : tfUser();
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'channel' => 'email', 'confirmed_at' => now(), 'enabled_at' => $enforced ? null : now()]);

    return $user;
}

function ptProfileSecret(User $user, string $context): string
{
    $state = EnrollmentState::fromSession(session()->driver(), $user, 'fake', $context, 600);

    expect($state)->not->toBeNull();

    return (string) $state->get('secret');
}

/**
 * @return list<string>
 */
function ptSecurityEvents(): array
{
    return Notification::sent(new AnonymousNotifiable, TwoFactorSecurityNotification::class)
        ->map(fn (TwoFactorSecurityNotification $notification) => $notification->event.':'.($notification->context['reason'] ?? ''))
        ->values()->all();
}

it('offers the allowed methods to enable', function () {
    $this->actingAs(tfUser())
        ->get(ptUrl())
        ->assertOk()
        ->assertSee('Enable: E-mail')
        ->assertSee('Enable: Fake authenticator')
        ->assertSee(ptUrl('chooseChannel'), false);
});

it('enables a verifier method voluntarily and shows the recovery codes once (§5.5)', function () {
    Event::fake([TwoFactorChannelChanged::class]);
    $user = tfUser();
    $this->actingAs($user);

    ptPost('chooseChannel', ['channel' => 'fake'])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Set up Fake authenticator and enter the code.');

    $this->get(ptUrl())
        ->assertSee('data-fake-enrollment', false)
        ->assertSee('Confirm enabling')
        ->assertSee(ptUrl('enable'), false);

    ptPost('enable', ['code' => FakeVerifierChannel::codeFor(ptProfileSecret($user, 'enable'))])
        ->assertSessionHasNoErrors()
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Two-factor authentication is enabled.');

    $record = ptRecord($user);
    expect($record->channel)->toBe('fake')
        ->and($record->enabled_at)->not->toBeNull()
        ->and(app(RecoveryCodes::class)->remaining($user))->toBe(8);
    Event::assertDispatched(TwoFactorChannelChanged::class, fn ($event) => $event->to === 'fake' && $event->reason === 'enrolled');

    $codes = session('orchid-2fa.recovery_codes.codes');
    $this->get(ptUrl())->assertSee($codes[0])->assertSee('I have saved the codes');

    ptPost('acknowledgeRecoveryCodes');
    $this->get(ptUrl())->assertDontSee($codes[0])->assertSee('Recovery codes left: 8.');
});

it('switches from e-mail to the verifier with the password and an e-mail code (§5.6)', function () {
    Event::fake([TwoFactorChannelChanged::class, TwoFactorChallengeSent::class]);
    $user = ptEmailUser();
    $user->forceFill(['remember_token' => 'old-token'])->save();
    $this->actingAs($user);

    $this->get(ptUrl())->assertSee('Change to Fake authenticator');

    ptPost('startSwitch', ['channel' => 'fake'])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'A verification code has been sent to u***@example.com.');
    Event::assertDispatched(TwoFactorChallengeSent::class, fn ($event) => $event->context === 'switch');

    $this->get(ptUrl())
        ->assertSee('Confirm the change of the method')
        ->assertSee('name="password"', false)
        ->assertSee('autocomplete="current-password"', false)
        ->assertDontSee('name="recovery_code"', false);

    ptPost('confirmCurrent', ['password' => 'password', 'code' => tfLastCode()])->assertSessionHasNoErrors();

    $this->get(ptUrl())->assertSee('data-fake-enrollment', false);

    ptPost('confirmEnrollment', ['code' => FakeVerifierChannel::codeFor(ptProfileSecret($user, 'switch'))])
        ->assertSessionHasNoErrors()
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The sign-in method has been changed to Fake authenticator.');

    $record = ptRecord($user);
    expect($record->channel)->toBe('fake')
        ->and($record->trusted_devices_version)->toBe(2)
        ->and($record->enabled_at)->not->toBeNull()
        ->and($user->refresh()->remember_token)->not->toBe('old-token')
        ->and(app(RecoveryCodes::class)->remaining($user))->toBe(8)
        ->and(session()->has(ProfileChallenge::SESSION_KEY))->toBeFalse();
    Event::assertDispatched(TwoFactorChannelChanged::class, fn ($event) => $event->from === 'email' && $event->to === 'fake' && $event->reason === 'switched');
});

it('lets an enforced user switch from the verifier to e-mail with a recovery code (§5.6)', function () {
    Event::fake([RecoveryCodeUsed::class]);
    $user = tfFakeUser('user@example.com');
    $codes = app(RecoveryCodes::class)->generate($user);
    $this->actingAs($user);

    ptPost('startSwitch', ['channel' => 'email'])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Enter your password and a code from Fake authenticator.');
    $this->get(ptUrl())->assertSee('name="recovery_code"', false)->assertDontSee(ptUrl('sendConfirmCode'), false);

    ptPost('confirmCurrent', ['password' => 'password', 'recovery_code' => $codes[1]])->assertSessionHasNoErrors();
    Event::assertDispatched(RecoveryCodeUsed::class, fn ($event) => $event->context === 'profile');

    ptPost('confirmEnrollment', ['code' => tfLastCode()])->assertSessionHasNoErrors();

    $record = ptRecord($user);
    expect($record->channel)->toBe('email')
        ->and(app(FakeVerifierChannel::class)->isAvailableFor($user))->toBeFalse()
        ->and(app(RecoveryCodes::class)->exists($user))->toBeFalse()
        ->and(ptSecurityEvents())->toContain('recovery_code_used:', 'channel_changed:switched');
});

it('requires the password: a missing one is a validation error, a wrong one counts and does not consume the code', function () {
    $user = ptEmailUser();
    $this->actingAs($user);
    ptPost('startSwitch', ['channel' => 'fake']);
    $code = tfLastCode();

    ptPost('confirmCurrent', ['code' => $code])->assertSessionHasErrors('password');

    ptPost('confirmCurrent', ['password' => 'wrong', 'code' => $code])
        ->assertSessionHasErrors(['password' => 'The password is incorrect. Attempts left: 4.']);

    // The code was not checked nor consumed, the attempt was counted.
    ptPost('confirmCurrent', ['password' => 'password', 'code' => tfWrongCode($code)])
        ->assertSessionHasErrors(['code' => 'The code is incorrect. Attempts left: 3.']);
    ptPost('confirmCurrent', ['password' => 'password', 'code' => $code])->assertSessionHasNoErrors();
});

it('does not consume a recovery code with a wrong password and counts it against the user', function () {
    $user = tfFakeUser('user@example.com');
    $codes = app(RecoveryCodes::class)->generate($user);
    $this->actingAs($user);
    ptPost('startSwitch', ['channel' => 'email']);

    ptPost('confirmCurrent', ['password' => 'wrong', 'recovery_code' => $codes[0]])->assertSessionHasErrors('password');

    expect(app(RecoveryCodes::class)->remaining($user))->toBe(8)
        ->and(cache()->get('orchid-2fa:verifier:'.$user->id))->toBe(1);
});

it('drops the confirmation after 5 wrong passwords', function () {
    $user = ptEmailUser();
    $this->actingAs($user);
    ptPost('startSwitch', ['channel' => 'fake']);
    $code = tfLastCode();

    foreach (range(1, 4) as $ignored) {
        ptPost('confirmCurrent', ['password' => 'wrong', 'code' => $code])->assertSessionHasErrors('password');
    }

    ptPost('confirmCurrent', ['password' => 'wrong', 'code' => $code])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');
    ptPost('confirmCurrent', ['password' => 'password', 'code' => $code])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');

    expect(ptRecord($user)->channel)->toBe('email');
});

it('lets the confirmation expire after profile.confirmation_ttl', function () {
    $user = ptEmailUser();
    $this->actingAs($user);
    ptPost('startSwitch', ['channel' => 'fake']);
    ptPost('confirmCurrent', ['password' => 'password', 'code' => tfLastCode()]);
    $secret = ptProfileSecret($user, 'switch');

    $this->travel(601)->seconds();

    ptPost('confirmEnrollment', ['code' => FakeVerifierChannel::codeFor($secret)])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');
    expect(ptRecord($user)->channel)->toBe('email');
});

it('does not switch to a method that is not allowed or to the current one', function () {
    $user = ptEmailUser();
    $this->actingAs($user);

    ptPost('startSwitch', ['channel' => 'totp'])->assertSessionHas(Toast::SESSION_MESSAGE, 'This method is not available.');
    ptPost('startSwitch', ['channel' => 'email'])->assertSessionHas(Toast::SESSION_MESSAGE, 'This method is not available.');

    expect(tfSentCodes())->toBe([]);
});

it('rebinds the verifier with the password and a code; the old binding works until the new one is confirmed (§5.7)', function () {
    Event::fake([TwoFactorChannelChanged::class]);
    $user = tfFakeUser('user@example.com', enforced: false);
    $old = DB::table('two_factor_fake')->where('user_id', $user->id)->value('secret');
    $this->actingAs($user);

    $this->get(ptUrl())->assertSee(ptUrl('startRebind'), false);

    ptPost('startRebind');
    ptPost('confirmCurrent', ['password' => 'password', 'code' => tfFakeCode($user)])->assertSessionHasNoErrors();

    expect(app(FakeVerifierChannel::class)->isAvailableFor($user))->toBeTrue()
        ->and(DB::table('two_factor_fake')->where('user_id', $user->id)->value('secret'))->toBe($old);

    $this->travel(FakeVerifierChannel::STEP)->seconds();
    ptPost('confirmEnrollment', ['code' => FakeVerifierChannel::codeFor(ptProfileSecret($user, 'rebind'))])
        ->assertSessionHasNoErrors()
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Fake authenticator has been set up again.');

    expect(DB::table('two_factor_fake')->where('user_id', $user->id)->value('secret'))->not->toBe($old)
        ->and(ptRecord($user)->trusted_devices_version)->toBe(2)
        ->and(app(RecoveryCodes::class)->remaining($user))->toBe(8);
    Event::assertDispatched(TwoFactorChannelChanged::class, fn ($event) => $event->from === 'fake' && $event->to === 'fake' && $event->reason === 'rebound');
});

it('has no rebinding for e-mail', function () {
    $this->actingAs(ptEmailUser())->get(ptUrl())->assertDontSee(ptUrl('startRebind'), false);

    ptPost('startRebind')->assertSessionHas(Toast::SESSION_MESSAGE, 'This method is not available.');
});

it('disables the verifier with the password and a recovery code (§5.8)', function () {
    Event::fake([TwoFactorChannelChanged::class]);
    $user = tfFakeUser('user@example.com', enforced: false);
    $codes = app(RecoveryCodes::class)->generate($user);
    $this->actingAs($user);

    ptPost('sendDisableCode')->assertSessionHas(Toast::SESSION_MESSAGE, 'Enter your password and a code from Fake authenticator.');
    expect(tfSentCodes())->toBe([]);

    ptPost('disable', ['password' => 'password', 'recovery_code' => $codes[0]])
        ->assertSessionHasNoErrors()
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Two-factor authentication is disabled.');

    $record = ptRecord($user);
    expect($record->enabled_at)->toBeNull()
        ->and($record->confirmed_at)->toBeNull()
        ->and($record->channel)->toBe('email')
        ->and($record->trusted_devices_version)->toBe(2)
        ->and(app(FakeVerifierChannel::class)->isAvailableFor($user))->toBeFalse()
        ->and(app(RecoveryCodes::class)->exists($user))->toBeFalse()
        ->and(ptSecurityEvents())->toContain('channel_changed:disabled');
    Event::assertDispatched(TwoFactorChannelChanged::class, fn ($event) => $event->from === 'fake' && $event->to === null && $event->reason === 'disabled');
});

it('does not disable without the password or with a wrong one', function () {
    $user = ptEmailUser();
    $this->actingAs($user);
    ptPost('sendDisableCode');
    $code = tfLastCode();

    ptPost('disable', ['code' => $code])->assertSessionHasErrors('password');
    ptPost('disable', ['code' => $code, 'password' => 'wrong'])->assertSessionHasErrors('password');

    expect(ptRecord($user)->enabled_at)->not->toBeNull();

    ptPost('disable', ['code' => $code, 'password' => 'password'])->assertSessionHasNoErrors();
    expect(ptRecord($user)->enabled_at)->toBeNull();
});

it('issues new recovery codes only with the password and a code of the method, not a recovery code (§5.9)', function () {
    Event::fake([RecoveryCodesRegenerated::class]);
    $user = tfFakeUser('user@example.com');
    $old = app(RecoveryCodes::class)->generate($user);
    $this->actingAs($user);

    $this->get(ptUrl())->assertSee('Recovery codes left: 8.')->assertSee(ptUrl('startRegenerate'), false);

    ptPost('startRegenerate');
    $this->get(ptUrl())->assertSee('Confirm new recovery codes')->assertDontSee('name="recovery_code"', false);

    ptPost('confirmCurrent', ['password' => 'password', 'recovery_code' => $old[0]])->assertSessionHasErrors('code');
    expect(app(RecoveryCodes::class)->remaining($user))->toBe(8);

    ptPost('confirmCurrent', ['password' => 'password', 'code' => tfFakeCode($user)])
        ->assertSessionHasNoErrors()
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'New recovery codes have been issued. The old ones no longer work.');

    $new = session('orchid-2fa.recovery_codes.codes');
    expect($new)->toHaveCount(8)
        ->and(app(RecoveryCodes::class)->consume($user, $old[1]))->toBeFalse();
    Event::assertDispatched(RecoveryCodesRegenerated::class, fn ($event) => $event->count === 8 && $event->channel === 'fake');
    $this->get(ptUrl())->assertSee($new[0]);
});

it('warns when 2 or fewer recovery codes are left', function () {
    $user = tfFakeUser('user@example.com');
    $codes = app(RecoveryCodes::class)->generate($user);

    foreach (array_slice($codes, 0, 6) as $code) {
        app(RecoveryCodes::class)->consume($user, $code);
    }

    $this->actingAs($user)->get(ptUrl())->assertSee('Only 2 recovery code(s) left. Issue new ones.');
});

it('shows the method of the user and not_enrolled for a user without one', function () {
    $this->actingAs(tfFakeUser('user@example.com'))
        ->get(ptUrl())
        ->assertSee('Fake authenticator')
        ->assertDontSee('Codes are sent to');

    config(['orchid-2fa.channels.allowed' => ['fake']]);
    $this->actingAs(tfEnforcedUser('other@example.com'))
        ->get(ptUrl())
        ->assertSee('Required, no method set up yet')
        ->assertSee(ptUrl('sendEnableCode'), false);
});

it('lets an enforced user without a method enroll one in the profile', function () {
    config(['orchid-2fa.channels.allowed' => ['fake']]);
    $user = tfEnforcedUser('user@example.com');
    $this->actingAs($user);

    ptPost('sendEnableCode');
    ptPost('enable', ['code' => FakeVerifierChannel::codeFor(ptProfileSecret($user, 'enable'))])->assertSessionHasNoErrors();

    expect(ptRecord($user)->channel)->toBe('fake')
        ->and(ptRecord($user)->enabled_at)->toBeNull();
});

it('cancels a pending change', function () {
    $user = ptEmailUser();
    $this->actingAs($user);
    ptPost('startSwitch', ['channel' => 'fake']);
    ptPost('confirmCurrent', ['password' => 'password', 'code' => tfLastCode()]);

    ptPost('cancelCode');

    expect(session()->has(ProfileChallenge::SESSION_KEY))->toBeFalse()
        ->and(session()->has(EnrollmentState::SESSION_KEY))->toBeFalse();
    $this->get(ptUrl())->assertDontSee('data-fake-enrollment', false);
});
