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

    <p class="text-muted small mb-3" data-orchid-2fa-destination>
        {{ __('orchid-2fa::messages.challenge.sent_to', ['destination' => $destination]) }}
    </p>

    <form method="POST" action="{{ $verifyUrl }}" data-turbo="false">
        @csrf

        <div class="mb-3">
            <label class="form-label" for="orchid-2fa-code">{{ __('orchid-2fa::messages.challenge.code') }}</label>
            <input id="orchid-2fa-code"
                   name="code"
                   type="text"
                   class="form-control @error('code') is-invalid @enderror"
                   autocomplete="one-time-code"
                   inputmode="numeric"
                   pattern="{{ $codePattern }}"
                   maxlength="{{ $codeLength }}"
                   required
                   autofocus>
            @error('code')
                <div class="invalid-feedback d-block">{{ $message }}</div>
            @enderror
        </div>

        <button type="submit" class="btn btn-default btn-block w-100">
            {{ __('orchid-2fa::messages.challenge.submit') }}
        </button>
    </form>

    <div class="d-flex flex-column flex-sm-row justify-content-between gap-2 mt-3 small">
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
