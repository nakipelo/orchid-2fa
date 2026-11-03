<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Mail\Transport\ArrayTransport;
use Symfony\Component\Mailer\SentMessage;

uses(RefreshDatabase::class);

/**
 * The whole login with the real mail stack and the `array` mailer (no fakes).
 */
function tfMailbox(): array
{
    /** @var ArrayTransport $transport */
    $transport = app('mail.manager')->mailer('array')->getSymfonyTransport();

    return $transport->messages()->all();
}

it('logs in with the code from a real e-mail', function () {
    config(['mail.default' => 'array']);
    $user = tfEnforcedUser();

    $this->get('/admin/login')->assertOk();
    tfLogin(extra: ['remember' => 'true'])->assertRedirect(route('platform.two-factor.challenge'));
    $this->get(route('platform.two-factor.challenge'))->assertOk()->assertSee('e***@example.com');

    $mails = tfMailbox();
    expect($mails)->toHaveCount(1);

    /** @var SentMessage $sent */
    $sent = $mails[0];
    $email = $sent->getOriginalMessage();
    expect($email->getTo()[0]->getAddress())->toBe('enforced@example.com')
        ->and($email->getSubject())->toBe('Your sign-in code');

    $html = (string) $email->getHtmlBody();
    expect($html)->toContain('The code is valid for 10 min.')
        ->not->toContain('e***@example.com')
        ->not->toContain('127.0.0.1');

    tfVerify(tfCodeFromMail($email))->assertRedirect(route('platform.main'));

    $this->assertAuthenticatedAs($user);
    $this->get(route('platform.profile'))->assertOk();
});

it('sends the e-mail in the application locale', function () {
    config(['mail.default' => 'array']);
    app()->setLocale('ru');
    tfEnforcedUser();

    tfLogin();

    $email = tfMailbox()[0]->getOriginalMessage();
    expect($email->getSubject())->toBe('Код для входа')
        ->and((string) $email->getHtmlBody())->toContain('Ваш код подтверждения:')
        ->toContain('Код действует 10 мин.');
});
