// NEAR-MISSES for bugfix-cs-memory-leak-httpclient-per-call. Written first.
//
// `HttpClient` is the famous inversion: it implements IDisposable, and
// disposing it per call is exactly the bug. The socket stays in TIME_WAIT
// after Dispose, so a client per request exhausts the ephemeral port range
// under load, while a single long-lived instance is the documented correct
// use. That is why this rule WANTS to fire inside a `using` — see the hits.
using System;
using System.Net.Http;

namespace Guardian.Fixtures.Misses;

/// The shape of `IHttpClientFactory`, declared locally so the fixture builds
/// against the bare SDK — the real interface lives in Microsoft.Extensions.Http,
/// which is a package reference these fixtures deliberately do not carry.
public interface IClientFactory
{
    HttpClient CreateClient(string name);
}

public sealed class HttpClientPerCall
{
    // THE correct form, and the discriminating near-miss for the
    // `pattern-not-inside` clause: it is the only thing keeping the rule off
    // this line. Delete that clause and this fires — on the exact code the
    // rule's own message tells you to write.
    private static readonly HttpClient Shared = new HttpClient();

    private readonly IClientFactory _factory;

    public HttpClientPerCall(IClientFactory factory)
    {
        // Note what is NOT here: `_field = new HttpClient()`. A constructor
        // assignment IS a hit, and it lives in the hits fixture.
        _factory = factory;
    }

    // The other correct form: let the factory own the handler lifetime.
    public HttpClient FromFactory() => _factory.CreateClient("api");

    public Uri? SharedBase() => Shared.BaseAddress;

    // Disposing something that is NOT an HttpClient is not this rule's
    // business, and a `using` over an unrelated type must stay silent.
    public string ReadsStream(System.IO.Stream s)
    {
        using var reader = new System.IO.StreamReader(s);
        return reader.ReadToEnd();
    }
}
