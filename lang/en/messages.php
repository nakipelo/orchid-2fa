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
        'trust_device' => 'Trust this device for :days day|Trust this device for :days days',
    ],

    'errors' => [
        'session_expired' => 'Your sign-in session has expired. Please sign in again.',
        'password_changed' => 'Your password has been changed. Please sign in again.',
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

    'status' => [
        'required' => 'Required for your account',
        'enabled' => 'Enabled',
        'disabled' => 'Disabled',
    ],

    'profile' => [
        'title' => 'Two-factor authentication',
        'description' => 'A one-time code sent by e-mail is asked for at sign-in, in addition to the password.',
        'status_title' => 'Status',
        'status' => 'Status',
        'destination' => 'Codes are sent to',
        'confirmed' => ':destination (confirmed)',
        'unconfirmed' => ':destination (not confirmed yet: the next sign-in confirms it)',
        'status_description' => [
            'required' => 'Two-factor authentication is required for your account and cannot be disabled.',
            'enabled' => 'You have enabled two-factor authentication. Disabling it is confirmed with a code.',
            'disabled' => 'Enable two-factor authentication to protect your account. Enabling it is confirmed with a code.',
        ],
        'enable' => 'Enable',
        'disable' => 'Disable',
        'confirm_enable' => 'Confirm enabling',
        'confirm_disable' => 'Confirm disabling',
        'confirm_description' => 'Enter the code from the e-mail.',
        'confirm' => 'Confirm',
        'cancel' => 'Cancel',
        'code_sent' => 'A verification code has been sent to :destination.',
        'enabled' => 'Two-factor authentication is enabled.',
        'disabled' => 'Two-factor authentication is disabled.',
        'already_enabled' => 'Two-factor authentication is already enabled.',
        'not_enabled' => 'Two-factor authentication is not enabled.',
        'enforced' => 'Two-factor authentication is required for your account and cannot be changed.',
        'trusted_title' => 'Trusted devices',
        'trusted_description' => 'Devices where you checked "Trust this device" sign in without a code.',
        'trusted_text' => 'Signing out of all trusted devices makes every device ask for a code at the next sign-in, this one included.',
        'trusted_forget' => 'Sign out of all trusted devices',
        'trusted_confirm' => 'Every trusted device will ask for a code at the next sign-in. Continue?',
        'trusted_forgotten' => 'Signed out of all trusted devices.',
    ],

    'profile_link' => [
        'description' => 'A one-time code by e-mail at sign-in, trusted devices.',
        'manage' => 'Manage',
    ],

    'reset' => [
        'description' => 'Resetting disables two-factor authentication enabled by the user, signs out of all trusted devices and removes the active code and limits. If two-factor authentication is required for the user, the next sign-in sends a code to the current address.',
        'status' => [
            'required' => 'Required',
            'enabled' => 'Enabled by the user',
            'disabled' => 'Disabled',
        ],
        'button' => 'Reset 2FA',
        'confirm' => 'Reset two-factor authentication of this user?',
        'done' => 'Two-factor authentication has been reset.',
    ],

    'email_changed' => [
        'subject' => 'The e-mail address of your account has been changed',
        'greeting' => 'Hello!',
        'line' => 'The e-mail address of your account has been changed to :address. Sign-in codes will be sent there.',
        'line_removed' => 'The e-mail address of your account has been removed.',
        'ignore' => 'If you did not make this change, contact your administrator immediately.',
    ],

    'permissions' => [
        'group' => 'Two-factor authentication',
        'required' => 'Two-factor authentication is required',
        'reset' => 'Reset two-factor authentication of users',
    ],

];
