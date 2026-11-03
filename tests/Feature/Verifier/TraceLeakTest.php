<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Monolog\Formatter\LineFormatter;
use Monolog\LogRecord;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\Context;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierChannel;
use Nakipelo\Orchid2FA\Tests\Fixtures\ThrowingFakeVerifierChannel;

uses(RefreshDatabase::class);

/**
 * Re-review of 0.2.0: an exception of the driver is logged with its trace (Laravel writes it to the
 * log; with zend.exception_ignore_args=0 — with the arguments). The core's frames must not carry the
 * code: its parameters are #[\SensitiveParameter].
 */
beforeEach(function () {
    Notification::fake();
    tfUseFake(['fake']);
    ThrowingFakeVerifierChannel::register();
    $this->ignoreArgs = ini_get('zend.exception_ignore_args');
    ini_set('zend.exception_ignore_args', '0');
});

afterEach(function () {
    ini_set('zend.exception_ignore_args', (string) $this->ignoreArgs);
    ThrowingFakeVerifierChannel::$throw = false;
});

/**
 * The log as Laravel's default line formatter of `single` / `daily` writes it (with the trace), and
 * the arguments of all frames of the logged exceptions.
 *
 * @return array{string, list<mixed>}
 */
function tlLog(): array
{
    $formatter = new LineFormatter(null, 'Y-m-d H:i:s', true, true);
    $formatter->includeStacktraces();
    $records = test()->logHandler()->getRecords();
    $args = [];

    foreach ($records as $record) {
        /** @var LogRecord $record */
        $exception = $record->context['exception'] ?? null;

        for (; $exception instanceof Throwable; $exception = $exception->getPrevious()) {
            foreach ($exception->getTrace() as $frame) {
                array_push($args, ...($frame['args'] ?? []));
            }
        }
    }

    expect($records)->not->toBeEmpty();

    return [implode("\n", array_map(fn ($record) => $formatter->format($record), $records)), $args];
}

it('keeps the enrollment code out of the logged trace of a driver exception', function () {
    $user = tfEnforcedUser();
    tfLogin();
    $this->get(route('platform.two-factor.enroll', ['channel' => 'fake']))->assertOk();
    $state = EnrollmentState::fromSession(session()->driver(), $user, 'fake', Context::ENROLL, 900);
    $code = FakeVerifierChannel::codeFor((string) $state?->get('secret'));
    ThrowingFakeVerifierChannel::$throw = true;

    $this->post(route('platform.two-factor.enroll.confirm', ['channel' => 'fake']), ['code' => $code])
        ->assertSessionHasErrors('code');

    [$log, $args] = tlLog();
    expect($log)->toContain('driver is down (enroll)')->and($log)->toContain('SensitiveParameterValue')
        ->and($log)->not->toContain($code)
        ->and($args)->not->toContain($code);
});

it('keeps the login code out of the logged trace of a driver exception', function () {
    $user = tfFakeUser();
    $code = tfFakeCode($user);
    ThrowingFakeVerifierChannel::$throw = true;
    $manager = app(ChallengeManager::class);

    $challenge = $manager->issue($user, Context::LOGIN, app(ChannelRegistry::class)->channel('fake'));

    expect($manager->verify($user, $challenge, $code))->toBe(VerificationResult::Invalid);

    [$log, $args] = tlLog();
    expect($log)->toContain('driver is down (verify)')->and($log)->toContain('SensitiveParameterValue')
        ->and($log)->not->toContain($code)
        ->and($args)->not->toContain($code);
});
