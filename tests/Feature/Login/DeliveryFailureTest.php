<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;
use Nakipelo\Orchid2FA\Challenge\PendingLogin;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Events\TwoFactorFailed;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mailer\Transport\AbstractTransport;

uses(RefreshDatabase::class);

/**
 * Spec §4.10: a transport error does not let the user in (fail-closed).
 */
beforeEach(function () {
    $this->mailDown = true;

    Mail::extend('flaky', fn () => new class($this) extends AbstractTransport
    {
        public function __construct(private readonly object $test)
        {
            parent::__construct();
        }

        protected function doSend(SentMessage $message): void
        {
            if ($this->test->mailDown) {
                throw new TransportException('Connection to smtp.example.com:25 refused.');
            }

            $this->test->delivered[] = $message;
        }

        public function __toString(): string
        {
            return 'flaky://';
        }
    });

    config(['mail.mailers.flaky' => ['transport' => 'flaky'], 'mail.default' => 'flaky']);
    $this->delivered = [];
});

it('keeps the user out when the code cannot be sent', function () {
    Event::fake([TwoFactorFailed::class, TwoFactorChallengeSent::class]);
    $user = tfEnforcedUser();

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));

    $this->assertGuest();
    expect(PendingLogin::fromSession(session()->driver()))->not->toBeNull()
        ->and(cache()->get('orchid-2fa:code:'.$user->id))->toBeNull();

    Event::assertDispatched(TwoFactorFailed::class, fn ($e) => $e->user->is($user) && $e->reason === 'delivery_failed');
    Event::assertNotDispatched(TwoFactorChallengeSent::class);
    expect($this->logHandler()->hasErrorThatContains('the two-factor code could not be sent'))->toBeTrue();

    $this->get(route('platform.two-factor.challenge'))
        ->assertOk()
        ->assertSee('We could not send the code. Please try again later.');

    $this->get(route('platform.main'))->assertRedirect(route('platform.login'));
});

it('lets the user resend after a failed send, within the limits', function () {
    $user = tfEnforcedUser();
    tfLogin();

    // A failed send counts: the cooldown applies.
    $this->post(route('platform.two-factor.resend'))->assertRedirect(route('platform.two-factor.challenge'));
    $this->get(route('platform.two-factor.challenge'))->assertSee('Please try again later (in 1 min).');

    $this->mailDown = false;
    $this->travel(61)->seconds();

    $this->post(route('platform.two-factor.resend'))->assertSessionHas('orchid-2fa.status');
    expect($this->delivered)->toHaveCount(1);

    tfVerify(tfCodeFromMail($this->delivered[0]->getOriginalMessage()))->assertRedirect(route('platform.main'));
    $this->assertAuthenticatedAs($user);
});

it('reports a failed resend', function () {
    tfEnforcedUser();
    tfLogin();
    $this->travel(61)->seconds();

    $this->post(route('platform.two-factor.resend'))
        ->assertRedirect(route('platform.two-factor.challenge'))
        ->assertSessionHas('orchid-2fa.error', 'We could not send the code. Please try again later.');

    $this->postJson(route('platform.two-factor.resend'))->assertUnprocessable();
    $this->assertGuest();
});

it('fails closed for a user without an address', function () {
    Event::fake([TwoFactorFailed::class]);
    $user = tfEnforcedUser();
    config(['orchid-2fa.channels.email.attribute' => 'backup_email']);

    tfLogin()->assertRedirect(route('platform.two-factor.challenge'));

    $this->assertGuest();
    Event::assertDispatched(TwoFactorFailed::class, fn ($e) => $e->user->is($user) && $e->reason === 'delivery_failed');
});
