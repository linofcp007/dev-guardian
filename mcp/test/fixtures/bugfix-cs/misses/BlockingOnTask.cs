// NEAR-MISSES for bugfix-cs-race-condition-blocking-on-task. Written first,
// and this is the file that DECIDED the rule's shape rather than merely
// checking it afterwards.
//
// The naive rule is `$V.Result` / `$V.Wait()`. Every method in this file makes
// it fire, and every method in this file is correct code. Two of the four are
// not even close calls — `Result` is a real property name on ordinary objects,
// and `Wait()` is the correct, intended API on two BCL synchronisation
// primitives. That is why the rule ships only in its four-branch form.
using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Guardian.Fixtures.Misses;

/// An ordinary domain object with a `bool Result` property. Nothing about it
/// is a Task, and `Result` is a perfectly good name for the outcome of a
/// validation.
public sealed class ValidationOutcome
{
    public bool Result { get; init; }

    public string? Reason { get; init; }
}

public sealed class BlockingOnTask
{
    private readonly SemaphoreSlim _sem = new SemaphoreSlim(1, 1);
    private readonly CountdownEvent _countdown = new CountdownEvent(1);

    // 1. A POCO property called `Result`. Untyped `$V.Result` fires here.
    public bool ReadsPocoResult(ValidationOutcome outcome)
    {
        return outcome.Result;
    }

    // 2. `Match.Result(string)` is a REAL BCL METHOD — it expands a
    //    substitution pattern against a match. This one matters more than it
    //    looks: it proves untyped `$V.Result` matches a METHOD CALL's
    //    receiver, not only a property read, so the false-positive surface is
    //    wider than "objects with a Result property".
    public string ExpandsRegexResult(string input)
    {
        var m = Regex.Match(input, "(a)(b)");
        return m.Success ? m.Result("$2$1") : string.Empty;
    }

    // 2b. THE SAME CALL WRITTEN INLINE, and it is a different fixture rather
    //     than a stylistic variant of 2. It is the only near-miss that
    //     exercises the `.*Async` regex on the `.Result` branch: that branch
    //     matches `$F(...).Result`, a call IMMEDIATELY followed by `.Result`,
    //     which the two-statement form above never produces.
    //
    //     Without this method the regex ablates DEAD — not because it does
    //     nothing, but because nothing here asks it to. Delete the regex and
    //     this line starts firing on correct BCL code.
    public string ExpandsRegexResultInline(string input)
    {
        return Regex.Match(input, "(a)(b)").Result("$2$1");
    }

    // 3b. The same job for the `.Wait()` branch: a call immediately followed
    //     by `.Wait()`, on a SemaphoreSlim rather than a Task. Correct code,
    //     and silent only because `GetLimiter` does not match `.*Async`.
    public void TakesLimiterInline()
    {
        GetLimiter().Wait();
        try { Console.WriteLine("critical"); }
        finally { _sem.Release(); }
    }

    private SemaphoreSlim GetLimiter() => _sem;

    // 3. `SemaphoreSlim.Wait()` — correct, intended blocking. There is no
    //    async alternative being ignored here; `WaitAsync` is a different
    //    method and this code chose this one.
    public void TakesSemaphore()
    {
        _sem.Wait();
        try { Console.WriteLine("critical"); }
        finally { _sem.Release(); }
    }

    // 4. `CountdownEvent.Wait()` — same, and it has no async form at all.
    public void WaitsForCountdown()
    {
        _countdown.Wait();
    }

    // The correct way to consume a Task, for contrast.
    public async Task<int> AwaitsProperly()
    {
        return await LoadAsync();
    }

    // A Task-typed local that is awaited rather than blocked on.
    public async Task<int> AwaitsAStoredTask()
    {
        Task<int> pending = LoadAsync();
        return await pending;
    }

    private Task<int> LoadAsync() => Task.FromResult(1);
}
