// HITS for bugfix-cs-race-condition-blocking-on-task: six sites, and they are
// laid out one-or-two per BRANCH, because the rule has four branches and a
// branch with no fixture behind it can be deleted without a test moving.
//
// Blocking on a Task deadlocks whenever the continuation needs the context the
// blocking call is holding — the classic ASP.NET / WinForms hang. It also
// wraps the exception in an AggregateException, so the catch clause written
// for the real exception type stops matching.
using System;
using System.Threading.Tasks;

namespace Guardian.Fixtures.Hits;

public sealed class BlockingOnTask
{
    private readonly TaskSource _source = new TaskSource();

    private readonly Task _pending = Task.CompletedTask;

    // --- branch 1: `.Result` on something whose declared type IS Task -------

    // 1. An explicitly-typed local. `Task<int> t = ...` resolves;
    //    `var t = ...` with a CALL initialiser does NOT — see the rule's
    //    stated false negatives. This is the shape that does.
    public int BlocksOnTypedLocal()
    {
        Task<int> pending = _source.LoadAsync(1);
        return pending.Result;
    }

    // 2. A parameter, which resolves for the same reason.
    public int BlocksOnParameter(Task<int> pending)
    {
        return pending.Result;
    }

    // --- branch 2: `.Wait()` on something whose declared type IS Task -------

    // 3. A field receiver — a PLAIN field of this class.
    //
    //    It has to be plain. `_source.Pending.Wait()`, where the Task is a
    //    property of another object, does NOT fire: `metavariable-type`
    //    resolves a local, a parameter or a simple field, but not a dotted
    //    member access. Measured on this very fixture, which is why the field
    //    is here rather than reached through `_source`. The dotted form is
    //    recorded as a false negative in the rule comment instead of being
    //    quietly dropped, and it is NOT in misses/ — it is a real bug the
    //    rule does not catch, and a miss fixture asserting zero would make
    //    that look like a decision.
    public void WaitsOnField()
    {
        _pending.Wait();
    }

    // --- branch 3: `.Result` on a call whose name ends in Async -------------
    //
    // This branch exists because `metavariable-type: Task` kills the four
    // false positives in the misses file AND kills `GetAsync().Result`, which
    // is the commonest spelling of the bug. The name is the only signal left.

    // 4. The bare call.
    public int BlocksOnAsyncCall()
    {
        return FetchDataAsync().Result;
    }

    // 5. A DOTTED call. `$F` binds the whole dotted name, so `_source.LoadAsync`
    //    matches `.*Async` as one token — measured, and the reason this branch
    //    does not need a separate receiver-qualified twin the way the Java
    //    map rules do.
    public int BlocksOnDottedAsyncCall()
    {
        return _source.LoadAsync(2).Result;
    }

    // --- branch 4: `.Wait()` on a call whose name ends in Async -------------

    // 6. Without this fixture the fourth branch is dead weight that nothing
    //    would notice.
    public void WaitsOnAsyncCall()
    {
        FetchDataAsync().Wait();
    }

    private Task<int> FetchDataAsync() => Task.FromResult(1);
}

public sealed class TaskSource
{
    public Task Pending { get; } = Task.CompletedTask;

    public Task<int> LoadAsync(int id) => Task.FromResult(id);
}
