{{-- "Trust this device" (nakipelo/orchid-2fa). Variable: $trustDeviceDays. --}}
<div class="form-check mb-3">
    <input id="orchid-2fa-trust-device"
           name="trust_device"
           type="checkbox"
           value="1"
           class="form-check-input"
           @checked(old('trust_device'))>
    <label class="form-check-label" for="orchid-2fa-trust-device">
        {{ trans_choice('orchid-2fa::messages.challenge.trust_device', $trustDeviceDays, ['days' => $trustDeviceDays]) }}
    </label>
</div>
