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
// AND IT CARRIES EXTRA WEIGHT THIS ROUND, because ablation axis 3 — the one
// that measures a clause's width against code nobody wrote as a fixture — is
// N/A for the whole C# pack: this repo contains no C# outside this tree. This
// file and the guard-adjacent hits in AsCast.cs are the compensation.
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

    // as-cast-deref: guarded use INSIDE the `if`, unguarded use AFTER it. This
    // is the commonest real spelling of the defect — the author added the
    // guard for the logging line and then forgot that the return is reached
    // whether or not the cast succeeded.
    //
    // It is also the shape that proves the guard exclusion does not OVER-REACH:
    // the exclusion matches this `if` (its then-block does dereference), and
    // `pattern-not-inside` excludes everything inside the matched node — so
    // the return firing is what shows the exclusion stops at the `if`.
    //
    // ANNOTATED FOR THE ABLATION, because this method makes axis 2 flag a
    // clause that is doing its job. Ablating
    // `pattern-not-inside: if ($V != null) { <... $V.$M ...>; }` reveals ONE
    // finding in hits/ — line 155, the GUARDED `Console.WriteLine` below,
    // which is correct code sitting deliberately next to the bug. CLAUDE.md
    // names this exact case: axis 2 fires whenever a hits/ fixture carries the
    // excluded near-miss beside the bug, which the real-bugs files do. It is
    // an attribution, not a defect. Do not "fix" it by deleting the clause.
    //
    // WHAT THIS FILE MEASURED AND THE RULE CANNOT DO, found by writing this
    // corpus rather than by reasoning: if the else arm ALSO dereferences while
    // the then arm does, the else arm is swallowed, because the exclusion has
    // then matched the whole `if` including its else. That is a narrower
    // residual of the same hole the then-block scoping closed — it needs the
    // guarded arm to dereference too, where the original swallowed the else
    // arm unconditionally. Stated in the rule comment; not fixturable here,
    // because a fixture that does not fire cannot be asserted in hits/.
    public string Describe(object raw)
    {
        var order = raw as Order;
        if (order != null)
        {
            Console.WriteLine(order.Reference);
        }
        return order.Reference;
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
