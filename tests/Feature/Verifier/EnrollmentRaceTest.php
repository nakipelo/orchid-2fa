<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Monolog\Level;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\Context;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\UserMethod;
use Nakipelo\Orchid2FA\Events\TwoFactorChannelChanged;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Recovery\RecoveryCodes;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierChannel;
use Nakipelo\Orchid2FA\TrustedDevice\TrustedDeviceCookie;
use Nakipelo\Orchid2FA\TwoFactorManager;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

/**
 * Review of 0.2.0: the enrollment at the login must not replace a method that appeared after the step
 * started (spec 0.2 §5.4, §9), its counters, "send again", the trust checkbox, `confirmed_at` of the
 * proof and an exception of the driver while confirming.
 */
beforeEach(function () {
    Notification::fake();
    tfUseFake(['fake']);
});

function erSecret(User $user, string $context = Context::ENROLL): string
{
    $state = EnrollmentState::fromSession(session()->driver(), $user, 'fake', $context, 900);

    expect($state)->not->toBeNull();

    return (string) $state->get('secret');
}

/**
 * The pending login and the enrollment step of this browser, to continue them in another one.
 *
 * @return array<string, mixed>
 */
function erSession(): array
{
    return [
        'orchid-2fa.pending' => session('orchid-2fa.pending'),
        'orchid-2fa.enrollment' => session('orchid-2fa.enrollment'),
    ];
}

/**
 * The victim enrolls the fake authenticator elsewhere (another browser, the profile).
 *
 * @return list<string>|null
 */
function erVictimEnrolls(User $user, string $secret = 'victim-secret-victim-secret-xxxxxx'): ?array
{
    FakeVerifierChannel::enrollUser($user, $secret);

    return app(TwoFactorManager::class)->commitEnrollment($user, app(ChannelRegistry::class)->channel('fake'), TwoFactorChannelChanged::ENROLLED);
}

function erTrustVersion(User $user): int
{
    return (int) TwoFactorAuthentication::query()->where('user_id', $user->id)->value('trusted_devices_version');
}

it('refuses an enrollment step without a method (A) once a method was enrolled meanwhile', function () {
    $user = tfEnforcedUser();

    // Browser 1 (someone with the password): variant A, the step starts.
    tfLogin()->assertRedirect(route('platform.two-factor.enroll'));
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']))->assertOk();
    $attackerSecret = erSecret($user);
    $attacker = erSession();

    // Meanwhile the owner enrolls the method.
    $victimCodes = erVictimEnrolls($user);
    expect(app(ChannelRegistry::class)->methodFor($user)->state)->toBe(UserMethod::ACTIVE);

    $this->newBrowser();
    $this->withSession($attacker)
        ->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => FakeVerifierChannel::codeFor($attackerSecret)])
        ->assertRedirect(route('platform.login'))
        ->assertSessionHasErrors(['email' => 'Your sign-in session has expired. Please sign in again.']);

    expect(session()->has('orchid-2fa.pending'))->toBeFalse()
        ->and(session()->has('orchid-2fa.enrollment'))->toBeFalse();
    $this->post(route('platform.two-factor.recovery-codes.confirm'))->assertRedirect(route('platform.login'));
    $this->assertGuest();

    // The owner's binding and recovery codes stay.
    expect(DB::table('two_factor_fake')->where('user_id', $user->id)->value('secret'))->toBe('victim-secret-victim-secret-xxxxxx')
        ->and(app(RecoveryCodes::class)->consume($user, $victimCodes[0]))->toBeTrue();
});

it('refuses to show the enrollment step (A) once a method was enrolled meanwhile', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']))->assertOk();

    erVictimEnrolls($user);

    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']))->assertRedirect(route('platform.login'));
    $this->get(route('platform.two-factor.enroll'))->assertRedirect(route('platform.login'));
});

it('refuses an enrollment step after the proof (B) once an allowed method was enrolled meanwhile', function () {
    $user = tfEnforcedUser();
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'channel' => 'email', 'confirmed_at' => now()]);

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    tfVerify(tfLastCode())->assertRedirect(route('platform.two-factor.enroll'));
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']))->assertOk();
    $secret = erSecret($user);
    $first = erSession();

    // The owner (the same proof in another browser) has enrolled the allowed method already.
    erVictimEnrolls($user);
    $version = erTrustVersion($user);

    $this->newBrowser();
    $this->withSession($first)
        ->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => FakeVerifierChannel::codeFor($secret)])
        ->assertRedirect(route('platform.login'));

    $this->assertGuest();
    expect(DB::table('two_factor_fake')->where('user_id', $user->id)->value('secret'))->toBe('victim-secret-victim-secret-xxxxxx')
        ->and(erTrustVersion($user))->toBe($version);
});

it('ends the recovery codes step when the enrolled method was reset meanwhile', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']));
    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => FakeVerifierChannel::codeFor(erSecret($user))])
        ->assertRedirect(route('platform.two-factor.recovery-codes'));

    app(TwoFactorManager::class)->reset($user);

    $this->get(route('platform.two-factor.recovery-codes'))->assertRedirect(route('platform.login'));
    $this->post(route('platform.two-factor.recovery-codes.confirm'))->assertRedirect(route('platform.login'));
    $this->assertGuest();
});

it('signs out of the trusted devices when an enrollment replaces a recorded method', function () {
    $user = tfFakeUser();
    $version = erTrustVersion($user);

    app(TwoFactorManager::class)->commitEnrollment($user, app(ChannelRegistry::class)->channel('fake'), TwoFactorChannelChanged::ENROLLED);

    expect(erTrustVersion($user))->toBe($version + 1);
});

it('counts the attempts of an enrollment step as long as the step lives', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']));
    $state = EnrollmentState::fromSession(session()->driver(), $user, 'fake', Context::ENROLL, 900);
    $challenge = app(ChallengeManager::class)->enrollmentChallenge(app(ChannelRegistry::class)->channel('fake'), $state);
    $wrong = FakeVerifierChannel::codeFor(erSecret($user)) === '000000' ? '111111' : '000000';

    foreach (range(1, 4) as $ignored) {
        $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => $wrong])->assertSessionHasErrors('code');
    }

    // Past code.ttl (600 s), within enrollment_ttl (900 s): the attempts of the step are not back.
    $this->travel(601)->seconds();
    expect(app(ChallengeManager::class)->attemptsLeft($user, $challenge, false))->toBe(1);

    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => $wrong])
        ->assertRedirect(route('platform.login'))
        ->assertSessionHasErrors(['email' => 'Too many wrong codes. Please sign in again.']);
});

it('counts the attempts of a profile enrollment step for profile.confirmation_ttl', function () {
    config(['orchid-2fa.profile.confirmation_ttl' => 900]);
    $user = tfUser();
    $state = EnrollmentState::start(session()->driver(), $user, 'fake', Context::ENABLE);
    $channel = app(ChannelRegistry::class)->channel('fake');
    $challenges = app(ChallengeManager::class);
    $challenges->startEnrollment($user, $channel, $state);
    $wrong = FakeVerifierChannel::codeFor((string) $state->get('secret')) === '000000' ? '111111' : '000000';

    foreach (range(1, 4) as $ignored) {
        $challenges->confirmEnrollment($user, $channel, $state, $wrong);
    }

    $this->travel(601)->seconds();
    expect($challenges->attemptsLeft($user, $challenges->enrollmentChallenge($channel, $state), false))->toBe(1);

    $this->travel(300)->seconds();
    expect($challenges->attemptsLeft($user, $challenges->enrollmentChallenge($channel, $state), false))->toBe(5);
});

it('does not generate a new secret on "send again" of a verifier step', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']));
    $secret = erSecret($user);

    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['resend' => '1'])
        ->assertRedirect(route('platform.two-factor.enroll', ['channel' => 'fake']))
        ->assertSessionHas('orchid-2fa.error', 'Your sign-in method does not send codes.');

    expect(erSecret($user))->toBe($secret);
});

it('confirms the record only at the final login after the proof (B)', function () {
    config(['orchid-2fa.channels.allowed' => ['email']]);
    $user = tfFakeUser();
    TwoFactorAuthentication::query()->where('user_id', $user->id)->update(['confirmed_at' => null]);
    expect(app(ChannelRegistry::class)->methodFor($user)->state)->toBe(UserMethod::PROOF);

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));
    tfVerify(tfFakeCode($user))->assertRedirect(route('platform.two-factor.enroll'));

    // An abandoned enrollment leaves the record unconfirmed.
    expect(TwoFactorAuthentication::query()->where('user_id', $user->id)->value('confirmed_at'))->toBeNull();

    // The proof was a code: the trust checkbox is offered, the cookie is issued.
    $this->get(route('platform.two-factor.enroll', ['channel' => 'email']))->assertOk()->assertSee('name="trust_device"', false);
    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'email']), ['code' => tfLastCode(), 'trust_device' => '1'])
        ->assertRedirect(route('platform.main'))
        ->assertCookie(app(TrustedDeviceCookie::class)->name($user->id));

    $record = TwoFactorAuthentication::query()->where('user_id', $user->id)->first();
    expect($record->channel)->toBe('email')
        ->and($record->confirmed_at)->not->toBeNull();
});

it('neither offers nor issues a trusted device cookie for an enrollment with the password only (A)', function () {
    config(['orchid-2fa.channels.allowed' => ['fake', 'email'], 'orchid-2fa.channel' => 'fake']);
    $user = tfEnforcedUser();
    tfLogin()->assertRedirect(route('platform.two-factor.enroll'));

    $this->get(route('platform.two-factor.enroll', ['channel' => 'email']))->assertOk()->assertDontSee('name="trust_device"', false);
    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'email']), ['code' => tfLastCode(), 'trust_device' => '1'])
        ->assertRedirect(route('platform.main'))
        ->assertCookieMissing(app(TrustedDeviceCookie::class)->name($user->id));
});

it('counts an exception of the driver while confirming the enrollment as a wrong code', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']));
    $secret = erSecret($user);
    FakeVerifierChannel::$failEnrollmentWith = new RuntimeException('driver is down');

    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => FakeVerifierChannel::codeFor($secret)])
        ->assertRedirect(route('platform.two-factor.enroll', ['channel' => 'fake']))
        ->assertSessionHasErrors(['code' => 'The code is incorrect. Attempts left: 4.']);

    $records = collect($this->logHandler()->getRecords())->filter(fn ($record) => $record->level === Level::Error
        && str_contains($record->message, 'failed to check a code'));
    expect($records)->toHaveCount(1)
        ->and($records->first()->context)->toMatchArray(['user_id' => $user->id, 'channel' => 'fake', 'context' => 'enroll'])
        ->and(json_encode(array_diff_key($records->first()->context, ['exception' => true])))->not->toContain($secret)
        ->and(json_encode(array_diff_key($records->first()->context, ['exception' => true])))->not->toContain(FakeVerifierChannel::codeFor($secret))
        ->and(app(FakeVerifierChannel::class)->isAvailableFor($user))->toBeFalse();

    // The driver is back: the same step goes on.
    FakeVerifierChannel::$failEnrollmentWith = null;
    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => FakeVerifierChannel::codeFor($secret)])
        ->assertRedirect(route('platform.two-factor.recovery-codes'));
});
