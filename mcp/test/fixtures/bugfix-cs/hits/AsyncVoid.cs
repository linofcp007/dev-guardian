// HITS for bugfix-cs-race-condition-async-void: two sites.
//
// An `async void` method that is not an event handler has nowhere to put its
// exception. The compiler-generated state machine has no Task to fault, so a
// throw after the first `await` is rethrown on the captured SynchronizationContext
// — or, with no context, on a thread-pool thread — and takes the process down.
// The caller cannot await it, cannot observe it, and cannot catch it.
using System;
using System.Threading.Tasks;

namespace Guardian.Fixtures.Hits;

public sealed class AsyncVoid
{
    // 1. The plain fire-and-forget. No parameters at all, so nothing about it
    //    resembles the event-handler shape the rule exempts.
    public async void FireAndForget()
    {
        await Task.Delay(1);
        throw new InvalidOperationException("this kills the process");
    }

    // 2. `static async void`. The interesting part is the MODIFIER: the rule's
    //    pattern says `async void`, with no `static`, and it matches anyway
    //    because Semgrep matches modifiers by SUBSET. That is the same
    //    behaviour the Java pack relies on, and it is worth a fixture because
    //    the day it stops being true this count moves rather than the rule
    //    silently narrowing.
    public static async void StaticFireAndForget()
    {
        await Task.Delay(1);
        Console.WriteLine("done");
    }
}
