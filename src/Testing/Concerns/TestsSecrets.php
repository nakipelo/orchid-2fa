<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing\Concerns;

use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Testing\ChannelConformanceTestCase;

/**
 * No codes or secrets in the logs and the events (spec 0.2 §8, §9).
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
        $state = EnrollmentState::start($this->application()->make('session.store'), $other, $this->channelName(), TwoFactorChallengeSent::CONTEXT_ENROLL);
        $this->challenges()->startEnrollment($other, $this->channel(), $state);
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
    }
}
