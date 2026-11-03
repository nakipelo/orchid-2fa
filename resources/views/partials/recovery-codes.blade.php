{{-- The recovery codes shown once (nakipelo/orchid-2fa, spec 0.2 §4.7). Variable: $codes. --}}
<p class="small mb-2">{{ __('orchid-2fa::messages.recovery.save_hint') }}</p>
<ul class="list-unstyled font-monospace row row-cols-2 g-1 mb-3" data-orchid-2fa-recovery-codes>
    @foreach ($codes as $code)
        <li class="col"><code>{{ $code }}</code></li>
    @endforeach
</ul>
