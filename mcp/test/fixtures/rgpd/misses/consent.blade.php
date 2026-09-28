{{-- A Laravel Blade layout that prints trackers only once consented.
     NOTHING here may fire (the template-condition guard, Blade form). --}}
<!doctype html>
<html lang="{{ app()->getLocale() }}">
<head>
    @if($consent->has('analytics'))
        <script async src="https://www.googletagmanager.com/gtag/js?id={{ config('services.google.analytics_id') }}"></script>
    @endif
    @if(consent('marketing'))
        <script>fbq('init', '{{ config('services.meta.pixel_id') }}');</script>
    @endif
</head>
<body>
    @if($consent->has('marketing'))
        <iframe src="https://www.youtube.com/embed/{{ $videoId }}"></iframe>
    @else
        <p>O video aparece depois de aceitar os cookies de marketing.</p>
    @endif
</body>
</html>
