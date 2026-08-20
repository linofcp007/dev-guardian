// THE REAL-BUGS CORPUS.
//
// Everything else in hits/ is one minimal instantiation per rule, written by
// whoever wrote the rule. That proves a rule fires at all. It CANNOT prove
// that an exclusion added later did not eat a real bug, because a minimal hit
// fixture carries no guard shapes for an exclusion to catch on — and the
// near-miss fixtures only ever measure the direction the exclusion was written
// for. So a future wave could close a false positive, silently delete recall,
// and still go green.
//
// This file closes that. It is a plausible order-processing service, written
// as code rather than as snippets, with every defect sitting where it would
// sit in real work: inside a `try`, inside a loop, next to a guard on a
// different variable, in a constructor. Every rule in the pack has at least
// one entry here — the Java round left three rules at zero corpus coverage and
// that was the riskiest gap in the pack.
//
// Its counts are asserted like any other fixture, so every future exclusion
// has to prove it does not eat a real bug before it can be merged.
//
// IT USED TO CARRY EXTRA WEIGHT because ablation axis 3 — the one that
// measures a clause's width against code nobody wrote as a fixture — was N/A
// for the whole C# pack: this repo contains no C# outside this tree. It is no
// longer the only compensation. Axis 3 now runs for this pack against a corpus
// named by `GUARDIAN_CS_SRC`, and the first thing it measured deleted a rule —
// `as-cast-deref`, 6490 findings and no true positives on `dotnet/runtime`.
// Its entry in this file went with it. A fixture corpus written here can only
// probe the shapes its author thought of; that is what axis 3 is for.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace Guardian.Fixtures.Hits;

public sealed class Order
{
    public string Reference { get; init; } = "";

    public int Quantity { get; init; }
}

public sealed class OrderService
{
    // static-random: shared across every request thread.
    private static readonly Random Jitter = new Random();

    private readonly List<Order> _pending = new List<Order>();

    private readonly HttpClient _client;

    private readonly Task _warmup = Task.CompletedTask;

    // httpclient-per-call, IN A CONSTRUCTOR — the placement that escapes a
    // `pattern-inside: $R $M(...)` scoping clause entirely.
    public OrderService()
    {
        _client = new HttpClient();
    }

    // rethrow-loses-stacktrace + empty-catch, both under a `finally`, which is
    // the shape that was invisible to this pack when it first shipped.
    public void Submit(string payload)
    {
        try
        {
            Parse(payload);
        }
        catch (FormatException ex)
        {
            throw ex;
        }
        finally
        {
            Cleanup();
        }

        try { Audit(payload); } catch { } finally { Cleanup(); }
    }

    // async-void: fire-and-forget on a service method. Nothing can await this
    // and nothing can catch what it throws.
    public async void Reconcile()
    {
        await Task.Delay(Jitter.Next(10));
        throw new InvalidOperationException("unreconciled");
    }

    // blocking-on-task on an explicitly-typed local, plus a second block on a
    // plain field. Both deadlock under a captured context.
    public int WaitForWarmup()
    {
        Task<int> pending = LoadCountAsync();
        _warmup.Wait();
        return pending.Result;
    }

    // lock-on-shared-instance: the monitor is reachable by every caller.
    public void Enqueue(Order order)
    {
        lock (this)
        {
            _pending.Add(order);
        }
    }

    // loop-lte-length over an array, with the guard on a DIFFERENT array — the
    // shape a future receiver-restriction has to keep seeing.
    public int TotalLines(string[] lines, string[] headers)
    {
        var total = 0;
        if (headers.Length > 0)
        {
            for (var i = 0; i <= lines.Length; i++) { total += lines[i].Length; }
        }
        return total;
    }

    // loop-lte-count over a List, inside a try, which is where a scoping
    // clause written for method bodies would lose it.
    public int TotalQuantity()
    {
        var total = 0;
        try
        {
            for (var i = 0; i <= _pending.Count; i++) { total += _pending[i].Quantity; }
        }
        catch (ArgumentOutOfRangeException ex)
        {
            Log(ex);
        }
        return total;
    }

    // ordefault-deref behind a guard on a DIFFERENT collection. The guard
    // proves nothing about the sequence being dereferenced.
    public string FirstReference(List<Order> archived)
    {
        if (archived.Count > 0)
        {
            return _pending.Where(o => o.Quantity > 0).FirstOrDefault().Reference;
        }
        return "";
    }

    // modify-during-iteration with the removal inside a `switch` arm followed
    // by `break` — the exact bug Java's fourth wave deleted. The `break`
    // leaves the switch, not the loop.
    public void Prune(int mode)
    {
        foreach (var order in _pending)
        {
            switch (mode)
            {
                case 0:
                    _pending.Remove(order);
                    break;
            }
        }
    }

    private Task<int> LoadCountAsync() => Task.FromResult(_pending.Count);

    private static void Parse(string payload) => int.Parse(payload);

    private static void Audit(string payload) => Console.WriteLine(payload.Length);

    private static void Cleanup() { }

    private static void Log(Exception ex) => Console.Error.WriteLine(ex.Message);
}
