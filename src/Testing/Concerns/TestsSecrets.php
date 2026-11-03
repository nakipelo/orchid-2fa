<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Nakipelo\Orchid2FA\Challenge\Context;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;
use Stringable;

/**
 * No codes or secrets in the logs and the events (spec 0.2 §8, §9), also while the enrollment step
 * is shown: the string values of enrollmentData() (at least 8 characters: a secret, a key, an URI)
 * must not reach the log.
 *
 * @mixin ChannelConformanceTestCase
 */
trait TestsSecrets
{
    public function test_no_codes_or_secrets_reach_the_logs_or_the_events(): void
    {
        $payloads = [];
        $this->application()->make('events')->listen('Nakipelo\Orchid2FA\Events\*', static function (string $name, array $data) use (&$payloads): void {
            $payloads[] = serialize(array_map(static fn ($event) => array_filter(get_object_vars($event), static fn ($value): bool => ! is_object($value)), $data));
        });

        $user = $this->enrolledUser();
        $this->login($user);
        $wrong = $this->invalidCode($user);
        $this->verifyCode($wrong);
        $code = $this->validCode($user);
        $this->verifyCode($code);

        $other = $this->makeUser('enroll@example.com');
        $session = $this->application()->make('session.store');

        if ($this->isDelivery() && $this->channel()->enrollmentView() === null) {
            // The default delivery channel has no enrollment step at the login.
            $state = EnrollmentState::start($session, $other, $this->channelName(), Context::ENROLL);
            $this->challenges()->startEnrollment($other, $this->channel(), $state);
        } else {
            // The step as the user sees it: the partial gets enrollmentData().
            $this->newBrowser();
            $this->login($other);
            $this->get(route(Orchid::enrollRoute(), ['channel' => $this->channelName()]))->assertOk();
            $state = EnrollmentState::fromSession($session, $other, $this->channelName(), Context::ENROLL, 900)
                ?? $this->fail('The enrollment step did not start.');
        }

        $shown = [];
        $data = $this->channel()->enrollmentData($other, $state);
        array_walk_recursive(
            $data,
            static function (mixed $value) use (&$shown): void {
                if (is_string($value) || $value instanceof Stringable) {
                    $shown[] = (string) $value;
                }
            },
        );

        $enrollmentCode = $this->completeEnrollmentCode($other, $state);
        $this->challenges()->confirmEnrollment($other, $this->channel(), $state, $enrollmentCode);

        $secret = $state->get('secret');
        $secrets = array_filter([$code, $wrong, $enrollmentCode, is_string($secret) ? $secret : ''], static fn (string $value): bool => strlen($value) >= 4);
        $logs = serialize(array_map(static fn ($record) => [$record->message, $record->context], $this->logHandler()->getRecords()));

        $this->assertNotSame([], $payloads);

        foreach ($secrets as $secret) {
            $this->assertStringNotContainsString($secret, $logs);

            foreach ($payloads as $payload) {
                $this->assertStringNotContainsString($secret, $payload);
            }
        }

        foreach (array_filter($shown, static fn (string $value): bool => strlen($value) >= 8) as $value) {
            $this->assertStringNotContainsString($value, $logs, 'A value of enrollmentData() reached the log.');
        }
    }
}
