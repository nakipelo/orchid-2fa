<?php

declare(strict_types=1);

return [

    'challenge' => [
        'title' => 'Two-factor authentication',
        'heading' => 'Enter the verification code',
        'sent_to' => 'We have sent a code to :destination.',
        'app_prompt' => 'Enter the code from your authenticator app.',
        'code' => 'Verification code',
        'submit' => 'Sign in',
        'resend' => 'Send the code again',
        'resend_in' => 'Send again in :time',
        'resent' => 'A new code has been sent.',
        'another_user' => 'Sign in as a different user',
        'trust_device' => 'Trust this device for :days day|Trust this device for :days days',
        'fallback' => 'Send a code by e-mail instead',
        'fallback_sent' => 'A code has been sent to your e-mail address.',
    ],

    'channels' => [
        'email' => 'E-mail',
    ],

    'errors' => [
        'session_expired' => 'Your sign-in session has expired. Please sign in again.',
        'password_changed' => 'Your password has been changed. Please sign in again.',
        'invalid_code' => 'The code is incorrect. Attempts left: :attempts.',
        'code_expired' => 'The code is no longer valid. Please request a new one.',
        'send_limit' => 'Too many codes have been requested. Please try again later (in :minutes min).',
        'delivery_failed' => 'We could not send the code. Please try again later.',
        'too_many_attempts' => 'Too many wrong codes. Please sign in again.',
        'too_many_attempts_wait' => 'Too many wrong codes. Please try again in :minutes min.',
        'too_many_attempts_today' => 'Too many wrong codes today. Please try again in :hours h.',
        'channel_unavailable' => 'Your sign-in method is not available. Please contact your administrator.',
        'invalid_recovery_code' => 'The recovery code is incorrect. Attempts left: :attempts.',
        'invalid_password' => 'The password is incorrect. Attempts left: :attempts.',
        'browser_required' => 'This step is available only in a browser.',
        'resend_unavailable' => 'Your sign-in method does not send codes.',
        'fallback_unavailable' => 'A code by e-mail is not available for your account.',
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
        'not_enrolled' => 'Required, no method set up yet',
    ],

    'enroll' => [
        'title' => 'Set up two-factor authentication',
        'heading' => 'Set up a sign-in method',
        'choose' => 'Two-factor authentication is required for your account. Choose how you will confirm your sign-ins.',
        'choose_proof' => 'Your current sign-in method is no longer available. Choose a new one.',
        'intro' => 'Set up :method and enter the code to finish.',
        'intro_proof' => 'Your current sign-in method is no longer available. Set up :method and enter the code to finish.',
        'submit' => 'Confirm',
        'another_method' => 'Choose another method',
    ],

    'recovery' => [
        'title' => 'Recovery codes',
        'use' => 'Use a recovery code',
        'code' => 'Recovery code',
        'save_hint' => 'Save these codes in a safe place. Each code works once and lets you sign in if you lose access to your device. They are shown only now.',
        'saved' => 'I have saved the codes',
        'once' => 'The codes are shown only once.',
    ],

    'profile' => [
        'title' => 'Two-factor authentication',
        'description' => 'A one-time code (by e-mail or from an app) is asked for at sign-in, in addition to the password.',
        'status_title' => 'Status',
        'status' => 'Status',
        'destination' => 'Codes are sent to',
        'method' => 'Method',
        'password' => 'Current password',
        'confirmed' => ':destination (confirmed)',
        'unconfirmed' => ':destination (not confirmed yet: the next sign-in confirms it)',
        'status_description' => [
            'required' => 'Two-factor authentication is required for your account and cannot be disabled.',
            'enabled' => 'You have enabled two-factor authentication. Disabling it is confirmed with your current password and a code.',
            'disabled' => 'Enable two-factor authentication to protect your account. Enabling it is confirmed with a code.',
            'not_enrolled' => 'Two-factor authentication is required for your account: set up a method.',
        ],
        'enable' => 'Enable',
        'disable' => 'Disable',
        'confirm_enable' => 'Confirm enabling',
        'confirm_disable' => 'Confirm disabling',
        'confirm_switch' => 'Confirm the change of the method',
        'confirm_rebind' => 'Confirm the new binding of the method',
        'confirm_regenerate' => 'Confirm new recovery codes',
        'confirm_current_description' => 'Enter your current password and a code of your current method.',
        'recovery_code_help' => 'Lost your device? Enter a recovery code instead of the code.',
        'enroll_title' => 'Set up :method',
        'enroll_description' => 'Follow the steps and enter the code to finish.',
        'enroll_code_help' => 'The code from :method.',
        'enroll_started' => 'Set up :method and enter the code.',
        'enter_current_code' => 'Enter your password and a code from :method.',
        'enable_with' => 'Enable: :method',
        'switch_to' => 'Change to :method',
        'rebind' => 'Set up again',
        'regenerate' => 'New recovery codes',
        'regenerated' => 'New recovery codes have been issued. The old ones no longer work.',
        'switched' => 'The sign-in method has been changed to :method.',
        'rebound' => ':method has been set up again.',
        'method_not_allowed' => 'This method is not available.',
        'recovery_login' => 'You have signed in with a recovery code. Recovery codes left: :count. If you lost your device, set up your method again.',
        'recovery_remaining' => 'Recovery codes left: :count.',
        'recovery_warning' => 'Only :count recovery code(s) left. Issue new ones.',
        'recovery_description' => 'One-time codes to sign in when your device is not at hand.',
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
        'description' => 'A one-time code at sign-in (by e-mail or from an app), trusted devices.',
        'manage' => 'Manage',
    ],

    'reset' => [
        'description' => 'Resetting disables two-factor authentication enabled by the user, removes the sign-in method and the recovery codes, signs out of all trusted devices and removes the active code and limits. If two-factor authentication is required for the user, the next sign-in sends a code to the current address or asks to set up a method.',
        'status' => [
            'required' => 'Required',
            'enabled' => 'Enabled by the user',
            'disabled' => 'Disabled',
            'not_enrolled' => 'Required, no method set up',
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

    'security' => [
        'greeting' => 'Hello!',
        'ignore' => 'If it was not you, change your password and contact your administrator.',
        'change_password' => 'If it was not you, change your password now.',
        'recovery_code_used' => [
            'subject' => 'A recovery code was used',
            'line' => 'A recovery code of your account has just been used.',
            'remaining' => 'Recovery codes left: :count.',
        ],
        'channel_changed' => [
            'subject' => 'Your two-factor authentication has changed',
            'enrolled' => 'Two-factor authentication has been set up: :to.',
            'switched' => 'The sign-in method has been changed from :from to :to.',
            'rebound' => 'The sign-in method :to has been set up again.',
            'disabled' => 'Two-factor authentication has been disabled.',
            'reset' => 'Two-factor authentication of your account has been reset by an administrator.',
        ],
        'attempts_exceeded' => [
            'subject' => 'Someone is trying to sign in to your account',
            'line' => 'Someone entered your password and is trying to guess the sign-in code. Sign-in with a code is paused for a while.',
        ],
    ],

    'permissions' => [
        'group' => 'Two-factor authentication',
        'required' => 'Two-factor authentication is required',
        'reset' => 'Reset two-factor authentication of users',
    ],

];
