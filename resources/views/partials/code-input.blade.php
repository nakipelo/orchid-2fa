{{--
    The code field of the package (nakipelo/orchid-2fa), spec 0.2 §6.2: attributes from the
    channel's codeInput(). Variables: $codeInput (CodeInput), optional $name (default "code"),
    $id, $autofocus.
--}}
@php($fieldName = $name ?? 'code')
@php($fieldId = $id ?? 'orchid-2fa-code')
<div class="mb-3">
    <label class="form-label" for="{{ $fieldId }}">{{ __('orchid-2fa::messages.challenge.code') }}</label>
    <input id="{{ $fieldId }}"
           name="{{ $fieldName }}"
           type="text"
           class="form-control @error($fieldName) is-invalid @enderror"
           autocomplete="{{ $codeInput->autocomplete }}"
           inputmode="{{ $codeInput->inputmode }}"
           pattern="{{ $codeInput->pattern }}"
           maxlength="{{ $codeInput->length }}"
           required
           @if ($autofocus ?? true) autofocus @endif>
    @error($fieldName)
        <div class="invalid-feedback d-block">{{ $message }}</div>
    @enderror
</div>
