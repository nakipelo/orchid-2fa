{{--
    The recovery codes after the enrollment at the sign-in (nakipelo/orchid-2fa, spec 0.2 §5.4).
    Publish with: php artisan vendor:publish --tag=orchid-2fa-views
--}}
@extends($layout)

@section('title', __('orchid-2fa::messages.recovery.title'))

@section('content')
    <h1 class="h4 text-body-emphasis mb-3">{{ __('orchid-2fa::messages.recovery.title') }}</h1>

    @include('orchid-2fa::partials.recovery-codes', ['codes' => $codes])

    <form method="POST" action="{{ $confirmUrl }}" data-turbo="false">
        @csrf

        @if ($trustDevice)
            @include('orchid-2fa::partials.trust-device')
        @endif

        <button type="submit" class="btn btn-default btn-block w-100">
            {{ __('orchid-2fa::messages.recovery.saved') }}
        </button>
    </form>

    <div class="mt-3 small">
        <form method="POST" action="{{ $cancelUrl }}" data-turbo="false">
            @csrf
            <button type="submit" class="btn btn-link p-0 small">
                {{ __('orchid-2fa::messages.challenge.another_user') }}
            </button>
        </form>
    </div>
@endsection
