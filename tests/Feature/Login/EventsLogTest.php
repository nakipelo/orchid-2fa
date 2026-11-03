<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Nakipelo\Orchid2FA\Events\TwoFactorLockedOut;
use Nakipelo\Orchid2FA\Events\TwoFactorPassed;
use Nakipelo\Orchid2FA\Listeners\LogTwoFactorEvents;
use Nakipelo\Orchid2FA\Orchid2FAServiceProvider;

uses(RefreshDatabase::class);

/**
 * Spec §5.7: the optional logging listener.
 */
beforeEach(function () {
    Notification::fake();
});

it('does not subscribe the logger by default', function () {
    foreach ([TwoFactorChallengeSent::class, TwoFactorPassed::class, TwoFactorFailed::class, TwoFactorLockedOut::class] as $event) {
        expect(Event::hasListeners($event))->toBeFalse();
    }
});

it('logs the events when log.enabled, without the code', function () {
    config(['orchid-2fa.log.enabled' => true]);
    $this->app->register(Orchid2FAServiceProvider::class, force: true);

    expect(Event::hasListeners(TwoFactorPassed::class))->toBeTrue();

    $user = tfEnforcedUser();
    tfLogin();
    $code = tfLastCode();
    tfVerify(tfWrongCode($code));
    $this->travel(10)->seconds();
    $this->post(route('platform.two-factor.resend'));
    tfVerify($code);

    $log = $this->logHandler();
    expect($log->hasInfoThatContains('Two-factor code sent.'))->toBeTrue()
        ->and($log->hasWarningThatContains('Two-factor authentication failed.'))->toBeTrue()
        ->and($log->hasWarningThatContains('Two-factor authentication locked out.'))->toBeTrue()
        ->and($log->hasInfoThatContains('Two-factor authentication passed.'))->toBeTrue();

    $records = collect($log->getRecords())->filter(fn ($r) => str_starts_with($r->message, 'Two-factor'));
    expect($records->every(fn ($r) => $r->context['user_id'] === $user->id && $r->context['guard'] === 'web'))->toBeTrue()
        ->and($records->first()->context)->toMatchArray(['channel' => 'email', 'destination' => 'e***@example.com', 'context' => 'login'])
        ->and(json_encode($records->map->context->all()))->not->toContain($code);
});

it('writes to the configured log channel', function () {
    config([
        'orchid-2fa.log.channel' => 'orchid-2fa-test',
        'logging.default' => 'null',
    ]);

    app(LogTwoFactorEvents::class)->handleFailed(new TwoFactorFailed(tfEnforcedUser(), 'web', 'invalid_code'));

    expect($this->logHandler()->hasWarningThatContains('Two-factor authentication failed.'))->toBeTrue();
});
