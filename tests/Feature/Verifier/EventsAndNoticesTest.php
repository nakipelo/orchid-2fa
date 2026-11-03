<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Notification;
use Nakipelo\Orchid2FA\Events\RecoveryCodesRegenerated;
use Nakipelo\Orchid2FA\Events\RecoveryCodeUsed;
use Nakipelo\Orchid2FA\Events\TwoFactorChannelChanged;
use Nakipelo\Orchid2FA\Listeners\LogTwoFactorEvents;
use Nakipelo\Orchid2FA\Notifications\TwoFactorSecurityNotification;
use Nakipelo\Orchid2FA\TwoFactorManager;

uses(RefreshDatabase::class);

/**
 * Spec 0.2 §8: the new events in the log, the security notices.
 */
beforeEach(function () {
    Notification::fake();
    tfUseFake();
});

it('logs the new events without codes or addresses', function () {
    $user = tfFakeUser();
    $listener = app(LogTwoFactorEvents::class);

    $listener->handleChannelChanged(new TwoFactorChannelChanged($user, 'web', 'email', 'fake', 'switched'));
    $listener->handleRecoveryCodeUsed(new RecoveryCodeUsed($user, 'web', 'fake', 5, 'login'));
    $listener->handleRecoveryCodesRegenerated(new RecoveryCodesRegenerated($user, 'web', 'fake', 8));

    $log = $this->logHandler();
    expect($log->hasInfoThatContains('Two-factor method changed.'))->toBeTrue()
        ->and($log->hasWarningThatContains('Two-factor recovery code used.'))->toBeTrue()
        ->and($log->hasInfoThatContains('Two-factor recovery codes regenerated.'))->toBeTrue();

    $contexts = collect($log->getRecords())->filter(fn ($record) => str_starts_with($record->message, 'Two-factor'))->map->context->values();
    expect($contexts[0])->toMatchArray(['user_id' => $user->id, 'from' => 'email', 'to' => 'fake', 'reason' => 'switched'])
        ->and($contexts[1])->toMatchArray(['remaining' => 5, 'context' => 'login'])
        ->and(json_encode($contexts))->not->toContain('@example.com');
});

it('subscribes the log listener to the new events', function () {
    expect(app(LogTwoFactorEvents::class)->subscribe())->toHaveKeys([
        TwoFactorChannelChanged::class, RecoveryCodeUsed::class, RecoveryCodesRegenerated::class,
    ]);
});

it('renders every security notice in English and Russian', function (string $event, array $context, string $en, string $ru) {
    $notice = new TwoFactorSecurityNotification($event, $context);

    $mail = $notice->toMail(new AnonymousNotifiable);
    expect(implode(' ', $mail->introLines).' '.implode(' ', $mail->outroLines).' '.$mail->subject)->toContain($en);

    app()->setLocale('ru');
    $mail = $notice->toMail(new AnonymousNotifiable);
    expect(implode(' ', $mail->introLines).' '.$mail->subject)->toContain($ru);
})->with([
    'recovery code' => ['recovery_code_used', ['remaining' => 3, 'context' => 'login'], 'Recovery codes left: 3.', 'Осталось резервных кодов: 3.'],
    'switched' => ['channel_changed', ['from' => 'email', 'to' => 'fake', 'from_label' => 'E-mail', 'to_label' => 'Fake', 'reason' => 'switched'], 'from E-mail to Fake', 'E-mail → Fake'],
    'disabled' => ['channel_changed', ['from' => 'fake', 'to' => null, 'reason' => 'disabled'], 'has been disabled', 'выключена'],
    'reset' => ['channel_changed', ['from' => 'fake', 'to' => null, 'reason' => 'reset'], 'reset by an administrator', 'Администратор сбросил'],
    'guessing' => ['attempts_exceeded', ['channel' => 'fake', 'limit' => 'window', 'available_in' => 600], 'is trying to guess the sign-in code', 'подбирает код'],
]);

it('passes the labels of the channels to the notice of a change', function () {
    $user = tfFakeUser();

    app(TwoFactorManager::class)->disable($user);

    $notice = Notification::sent(new AnonymousNotifiable, TwoFactorSecurityNotification::class)->first();
    expect($notice->context)->toMatchArray(['from' => 'fake', 'from_label' => 'Fake authenticator', 'reason' => 'disabled']);
});

it('logs a failed security notice and does not break the action', function () {
    $user = tfFakeUser();
    config(['orchid-2fa.notification.security_class' => 'Missing\\Notification']);

    app(TwoFactorManager::class)->reset($user);

    expect($this->logHandler()->hasErrorThatContains('the security notice could not be sent'))->toBeTrue();
});

it('sends no notice to a user without an address', function () {
    $user = tfFakeUser();
    $user->forceFill(['email' => ''])->saveQuietly();

    app(TwoFactorManager::class)->reset($user->refresh());

    Notification::assertNothingSentTo(new AnonymousNotifiable);
});
