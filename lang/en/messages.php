<?php

declare(strict_types=1);

return [

    'challenge' => [
        'title' => 'Two-factor authentication',
        'heading' => 'Enter the verification code',
        'sent_to' => 'We have sent a code to :destination.',
        'code' => 'Verification code',
        'submit' => 'Sign in',
        'resend' => 'Send the code again',
        'resend_in' => 'Send again in :time',
        'resent' => 'A new code has been sent.',
        'another_user' => 'Sign in as a different user',
    ],

    'errors' => [
        'session_expired' => 'Your sign-in session has expired. Please sign in again.',
        'invalid_code' => 'The code is incorrect. Attempts left: :attempts.',
        'code_expired' => 'The code is no longer valid. Please request a new one.',
        'send_limit' => 'Too many codes have been requested. Please try again later (in :minutes min).',
        'delivery_failed' => 'We could not send the code. Please try again later.',
    ],

    'notification' => [
        'subject' => 'Your sign-in code',
        'greeting' => 'Hello!',
        'line' => 'Your verification code: :code',
        'expires' => 'The code is valid for :minutes min.',
        'ignore' => 'If you did not try to sign in, change your password.',
    ],

    'permissions' => [
        'group' => 'Two-factor authentication',
        'required' => 'Two-factor authentication is required',
    ],

];
