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
    @if($consent->has('analytics'))
        {{-- excluded: the THEN arm is guarded, beside the two bugs below --}}
        <script async src="https://www.googletagmanager.com/gtag/js?id=G-OK000000"></script>
    @elseif(app()->isProduction())
        {{-- BUG: the ELSEIF arm runs when there is NO consent --}}
        <script async src="https://www.googletagmanager.com/gtag/js?id=G-ELSEIF00"></script>
    @else
        {{-- BUG: the ELSE arm of a consent condition --}}
        <script async src="https://www.googletagmanager.com/gtag/js?id=G-ELSE0000"></script>
    @endif
</head>
<body>@yield('content')</body>
</html>
