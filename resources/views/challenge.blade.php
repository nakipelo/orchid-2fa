{{--
    Code step of the sign-in (nakipelo/orchid-2fa). Publish with:
    php artisan vendor:publish --tag=orchid-2fa-views
--}}
@extends($layout)

@section('title', __('orchid-2fa::messages.challenge.title'))

@section('content')
    <h1 class="h4 text-body-emphasis mb-3">{{ __('orchid-2fa::messages.challenge.heading') }}</h1>

    @if ($status)
        <div class="alert alert-success small" role="status">{{ $status }}</div>
    @endif

    @if ($error)
        <div class="alert alert-danger small" role="alert">{{ $error }}</div>
    @endif

    @php($canResend = $canResend ?? true)

    <p class="text-muted small mb-3" data-orchid-2fa-destination>
        {{ $prompt ?? __('orchid-2fa::messages.challenge.sent_to', ['destination' => $destination]) }}
    </p>

    <form method="POST" action="{{ $verifyUrl }}" data-turbo="false">
        @csrf

        @if (! empty($challengeView))
            @include($challengeView, ['channel' => $channel, 'user' => $user, 'codeInput' => $codeInput])
        @else
            @include('orchid-2fa::partials.code-input', [
                'codeInput' => $codeInput ?? new \Nakipelo\Orchid2FA\Challenge\CodeInput($codeLength, $codePattern),
            ])
        @endif

        @if ($trustDevice)
            @include('orchid-2fa::partials.trust-device')
        @endif

        <button type="submit" class="btn btn-default btn-block w-100">
            {{ __('orchid-2fa::messages.challenge.submit') }}
        </button>
    </form>

    @if (! empty($recoveryUrl))
        {{-- No trust checkbox: a login with a recovery code issues no trusted device cookie (spec 0.2 §5.3). --}}
        <details class="mt-3 small" @if ($errors->has('recovery_code')) open @endif>
            <summary>{{ __('orchid-2fa::messages.recovery.use') }}</summary>
            <form method="POST" action="{{ $recoveryUrl }}" data-turbo="false" class="mt-2">
                @csrf
                <div class="mb-2">
                    <label class="form-label" for="orchid-2fa-recovery-code">{{ __('orchid-2fa::messages.recovery.code') }}</label>
                    <input id="orchid-2fa-recovery-code"
                           name="recovery_code"
                           type="text"
                           class="form-control @error('recovery_code') is-invalid @enderror"
                           autocomplete="off"
                           autocapitalize="none"
                           spellcheck="false"
                           maxlength="64"
                           required>
                    @error('recovery_code')
                        <div class="invalid-feedback d-block">{{ $message }}</div>
                    @enderror
                </div>
                <button type="submit" class="btn btn-default btn-block w-100">
                    {{ __('orchid-2fa::messages.challenge.submit') }}
                </button>
            </form>
        </details>
    @endif

    <div class="d-flex flex-column flex-sm-row justify-content-between gap-2 mt-3 small">
        @if ($canResend)
            <form method="POST" action="{{ $resendUrl }}" data-turbo="false">
                @csrf
                <button type="submit"
                        class="btn btn-link p-0 small"
                        data-orchid-2fa-resend
                        data-available-in="{{ $resendAvailableIn }}"
                        data-label="{{ __('orchid-2fa::messages.challenge.resend') }}"
                        data-label-countdown="{{ __('orchid-2fa::messages.challenge.resend_in', ['time' => ':time']) }}"
                        @disabled($resendAvailableIn > 0)>
                    @if ($resendAvailableIn > 0)
                        {{ __('orchid-2fa::messages.challenge.resend_in', ['time' => sprintf('%d:%02d', intdiv($resendAvailableIn, 60), $resendAvailableIn % 60)]) }}
                    @else
                        {{ __('orchid-2fa::messages.challenge.resend') }}
                    @endif
                </button>
            </form>
        @endif

        @if (! empty($fallbackUrl))
            <form method="POST" action="{{ $fallbackUrl }}" data-turbo="false">
                @csrf
                <button type="submit" class="btn btn-link p-0 small">
                    {{ __('orchid-2fa::messages.challenge.fallback') }}
                </button>
            </form>
        @endif

        <form method="POST" action="{{ $cancelUrl }}" data-turbo="false">
            @csrf
            <button type="submit" class="btn btn-link p-0 small">
                {{ __('orchid-2fa::messages.challenge.another_user') }}
            </button>
        </form>
    </div>

    <script>
        (function () {
            var button = document.querySelector('[data-orchid-2fa-resend]');
            if (!button) {
                return;
            }
            var left = parseInt(button.getAttribute('data-available-in'), 10) || 0;
            var format = function (seconds) {
                var rest = seconds % 60;
                return Math.floor(seconds / 60) + ':' + (rest < 10 ? '0' : '') + rest;
            };
            var tick = function () {
                if (left <= 0) {
                    button.disabled = false;
                    button.textContent = button.getAttribute('data-label');
                    return;
                }
                button.disabled = true;
                button.textContent = button.getAttribute('data-label-countdown').replace(':time', format(left));
                left -= 1;
                setTimeout(tick, 1000);
            };
            tick();
        })();
    </script>
@endsection
