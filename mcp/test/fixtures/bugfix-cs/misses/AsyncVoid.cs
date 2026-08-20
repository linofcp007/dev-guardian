// NEAR-MISSES for bugfix-cs-race-condition-async-void. Written first.
//
// `async void` is legitimate in exactly one place: an event handler. The CLR
// has nowhere to deliver the exception from an `async void` method — it goes
// straight to the unhandled-exception path and takes the process with it — but
// the event-handler signature predates async and cannot be changed, so the
// language keeps the escape hatch.
//
// The exclusion is therefore the .NET event-handler CONVENTION, `(object
// sender, TArgs e)`, and how it is written was measured rather than assumed.
// See the rule comment: naming `EventArgs` literally closes ONLY the
// exact-typed handler, and `metavariable-type: EventArgs` does not help
// because it is not subtype-aware here. Both were tried on `OnElapsed` below.
using System;
using System.Threading.Tasks;

namespace Guardian.Fixtures.Misses;

/// A DERIVED event-args type, which is the normal case in real code —
/// `ElapsedEventArgs`, `PropertyChangedEventArgs`, `MouseEventArgs` and every
/// `EventHandler<T>` instantiation are all subclasses, not `EventArgs` itself.
public class ElapsedArgs : EventArgs
{
    public int Ticks { get; set; }
}

public sealed class AsyncVoid
{
    // The textbook handler, typed with `EventArgs` exactly.
    private async void OnClick(object sender, EventArgs e)
    {
        await Task.Delay(1);
    }

    // THE DISCRIMINATING ONE. A handler whose args type is DERIVED from
    // EventArgs. A `pattern-not` written with the literal type name closes
    // OnClick above and leaves this one firing — measured, and it is the
    // reason the exclusion binds the args type as a metavariable instead.
    private async void OnElapsed(object sender, ElapsedArgs e)
    {
        await Task.Delay(1);
    }

    // The correct shape for everything that is not a handler: the caller can
    // await it, and an exception lands on the returned Task.
    public async Task RunAsync()
    {
        await Task.Delay(1);
    }

    public async Task<int> LoadAsync()
    {
        await Task.Delay(1);
        return 1;
    }

    // A plain `void` with no `async` is not this rule's business.
    public void Sync()
    {
        Console.WriteLine("sync");
    }
}
