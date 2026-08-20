// HITS for bugfix-cs-memory-leak-httpclient-per-call: four sites.
//
// A new HttpClient per call exhausts the ephemeral port range under load: each
// disposed client leaves its socket in TIME_WAIT for the OS timeout, so a busy
// service runs out of ports while every individual call looks correct. The
// documented fix is one long-lived instance, or IHttpClientFactory.
//
// NOTE THE INVERSION, which is why two of these four sites are `using`
// statements. Everywhere else in this pack a `using` is the correct handling
// of a disposable and a rule flagging it would be wrong. Here disposing per
// call IS the bug, so this rule deliberately fires INSIDE a `using` — the
// tidier the disposal, the more certainly the socket is leaked.
using System;
using System.Net.Http;

namespace Guardian.Fixtures.Hits;

public sealed class HttpClientPerCall
{
    private readonly HttpClient _client;

    // 1. IN A CONSTRUCTOR, and this is the site that decided the rule's
    //    shape. The obvious scoping clause, `pattern-inside: $R $M(...) { ... }`,
    //    silently excludes constructors — measured — so this assignment
    //    escaped it entirely while the three below were caught. The rule uses
    //    `pattern-not-inside` on the static-field form instead, which has no
    //    such blind spot.
    public HttpClientPerCall()
    {
        _client = new HttpClient();
    }

    // 2. The plain per-call instance.
    public Uri? PerCall()
    {
        var client = new HttpClient();
        return client.BaseAddress;
    }

    // 3. `using var` — a C# 8 using-declaration. Correct-looking disposal,
    //    and the reason the socket is leaked.
    public Uri? PerCallUsingVar()
    {
        using var client = new HttpClient();
        return client.BaseAddress;
    }

    // 4. The classic `using` block, same defect.
    public Uri? PerCallUsingBlock()
    {
        using (var client = new HttpClient())
        {
            return client.BaseAddress;
        }
    }

    public Uri? FieldBase() => _client.BaseAddress;
}
