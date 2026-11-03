{{--
    Enrollment of a method at the sign-in (nakipelo/orchid-2fa, spec 0.2 §5.4, §6.2): the choice of
    the method or the step of one method. Publish with:
    php artisan vendor:publish --tag=orchid-2fa-views
--}}
@extends($layout)

@section('title', __('orchid-2fa::messages.enroll.title'))

@section('content')
    <h1 class="h4 text-body-emphasis mb-3">{{ __('orchid-2fa::messages.enroll.heading') }}</h1>

    @if ($status)
        <div class="alert alert-success small" role="status">{{ $status }}</div>
    @endif

    @if ($error)
        <div class="alert alert-danger small" role="alert">{{ $error }}</div>
    @endif

    @if ($channel === null)
        <p class="text-muted small mb-3">{{ __($proof ? 'orchid-2fa::messages.enroll.choose_proof' : 'orchid-2fa::messages.enroll.choose') }}</p>

        <div class="d-grid gap-2" data-orchid-2fa-choices>
            @foreach ($choices as $choice)
                <a href="{{ $choice['url'] }}" class="btn btn-default">{{ $choice['label'] }}</a>
            @endforeach
        </div>
    @else
        <p class="text-muted small mb-3">
            {{ __($proof ? 'orchid-2fa::messages.enroll.intro_proof' : 'orchid-2fa::messages.enroll.intro', ['method' => $label]) }}
        </p>

        @if ($enrollmentView)
            <div class="mb-3" data-orchid-2fa-enrollment>
                @include($enrollmentView, $enrollmentData)
            </div>
        @endif

        @if ($prompt)
            <p class="text-muted small mb-3">{{ $prompt }}</p>
        @endif

        <form method="POST" action="{{ $confirmUrl }}" data-turbo="false">
            @csrf

            @include('orchid-2fa::partials.code-input', ['codeInput' => $codeInput])

            @if ($trustDevice)
                @include('orchid-2fa::partials.trust-device')
            @endif

            <button type="submit" class="btn btn-default btn-block w-100">
                {{ __('orchid-2fa::messages.enroll.submit') }}
            </button>
        </form>
    @endif

    <div class="d-flex flex-column flex-sm-row justify-content-between gap-2 mt-3 small">
        @if ($channel !== null && $canResend)
            <form method="POST" action="{{ $confirmUrl }}" data-turbo="false">
                @csrf
                <input type="hidden" name="resend" value="1">
                <button type="submit" class="btn btn-link p-0 small">{{ __('orchid-2fa::messages.challenge.resend') }}</button>
            </form>
        @endif

        @if ($channel !== null && $chooseUrl)
            <a href="{{ $chooseUrl }}" class="btn btn-link p-0 small">{{ __('orchid-2fa::messages.enroll.another_method') }}</a>
        @endif

        <form method="POST" action="{{ $cancelUrl }}" data-turbo="false">
            @csrf
            <button type="submit" class="btn btn-link p-0 small">
                {{ __('orchid-2fa::messages.challenge.another_user') }}
            </button>
        </form>
    </div>
@endsection
