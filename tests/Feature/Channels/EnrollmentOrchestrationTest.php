<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierChannel;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §4.4, §4.6: the enrollment of every channel goes through the ChallengeManager — the code of
 * a delivery channel is issued with the limits and the events of the orchestrator, the confirmation
 * is counted before the channel is asked.
 */
beforeEach(function () {
    Notification::fake();
});

it('issues the enrollment code of a delivery channel through the orchestrator', function () {
    Event::fake([TwoFactorChallengeSent::class, TwoFactorLockedOut::class]);
    $user = tfUser();
    $email = app(ChannelRegistry::class)->channel('email');
    $state = EnrollmentState::start(session()->driver(), $user, 'email', 'enroll');

    app(ChallengeManager::class)->startEnrollment($user, $email, $state);

    expect($state->get('challenge_id'))->toBeString()
        ->and(tfSentCodes())->toHaveCount(1);
    Event::assertDispatched(TwoFactorChallengeSent::class, fn ($event) => $event->context === 'enroll' && $event->channel === 'email');

    // The send limits of the orchestrator: a lockout event, not a silent failure.
    expect(fn () => $email->startEnrollment($user, $state))->toThrow(SendLimitExceededException::class);
    Event::assertDispatched(TwoFactorLockedOut::class, fn ($event) => $event->reason === 'send_limit');
});

it('turns a delivery failure of the enrollment into DeliveryFailedException with the event', function () {
    Event::fake([TwoFactorFailed::class]);
    $user = tfUser();
    $user->forceFill(['email' => ''])->save();
    $state = EnrollmentState::start(session()->driver(), $user, 'email', 'enroll');

    expect(fn () => app(ChallengeManager::class)->startEnrollment($user, app(ChannelRegistry::class)->channel('email'), $state))
        ->toThrow(DeliveryFailedException::class);
    Event::assertDispatched(TwoFactorFailed::class, fn ($event) => $event->reason === 'delivery_failed');
});

it('counts the enrollment confirmation of a delivery channel before the channel and annuls the code', function () {
    Event::fake([TwoFactorFailed::class, TwoFactorLockedOut::class]);
    $user = tfUser();
    $email = app(ChannelRegistry::class)->channel('email');
    $manager = app(ChallengeManager::class);
    $state = EnrollmentState::start(session()->driver(), $user, 'email', 'enroll');
    $manager->startEnrollment($user, $email, $state);
    $code = tfLastCode();

    foreach (range(1, 4) as $ignored) {
        expect($manager->confirmEnrollment($user, $email, $state, tfWrongCode($code)))->toBe(VerificationResult::Invalid);
    }

    expect($manager->confirmEnrollment($user, $email, $state, tfWrongCode($code)))->toBe(VerificationResult::LockedOut)
        ->and($manager->confirmEnrollment($user, $email, $state, $code))->not->toBe(VerificationResult::Passed);
    Event::assertDispatched(TwoFactorFailed::class, fn ($event) => $event->reason === 'invalid_code');
    Event::assertDispatched(TwoFactorLockedOut::class, fn ($event) => $event->reason === 'attempts_exceeded');
});

it('counts the enrollment confirmation of a verifier channel against the user limits', function () {
    tfUseFake();
    $user = tfUser();
    $fake = app(ChannelRegistry::class)->channel('fake');
    $manager = app(ChallengeManager::class);
    $state = EnrollmentState::start(session()->driver(), $user, 'fake', 'enroll');
    $manager->startEnrollment($user, $fake, $state);
    $wrong = FakeVerifierChannel::codeFor((string) $state->get('secret')) === '000000' ? '111111' : '000000';

    expect($manager->confirmEnrollment($user, $fake, $state, $wrong))->toBe(VerificationResult::Invalid)
        ->and(cache()->get('orchid-2fa:verifier:'.$user->id))->toBe(1)
        ->and(cache()->get('orchid-2fa:verifier-day:'.$user->id))->toBe(1)
        ->and($manager->attemptsLeft($user, $manager->enrollmentChallenge($fake, $state), true))->toBe(4);
});
