{{-- A Laravel Blade layout. Each BUG fires rgpd-tracker-ga4-without-consent
     exactly once. --}}
<!doctype html>
<html lang="{{ app()->getLocale() }}">
<head>
    @if(config('services.google.analytics_id'))
        {{-- BUG: a Blade condition, but not a consent one --}}
        <script async src="https://www.googletagmanager.com/gtag/js?id={{ config('services.google.analytics_id') }}"></script>
    @endif
    @if(!$consent->has('analytics'))
        {{-- BUG: a NEGATED consent condition --}}
        <script async src="https://www.googletagmanager.com/gtag/js?id=G-JJJJ0000"></script>
    @endif
</head>
<body>@yield('content')</body>
</html>
