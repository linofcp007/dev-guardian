// NEAR-MISSES for bugfix-cs-race-condition-lock-on-shared-instance. Written
// first.
//
// The defect is locking on something OTHER CODE CAN ALSO LOCK ON. `lock (this)`
// exposes the monitor to every caller holding a reference to the object;
// `lock ("literal")` is worse, because string literals are interned, so two
// unrelated types locking on the same text share one monitor process-wide.
// Both are deadlocks waiting for a second participant.
//
// The correct form is a private object nobody else can reach, and that is the
// only thing the near-misses here need to show.
using System;

namespace Guardian.Fixtures.Misses;

public sealed class LockShared
{
    // The textbook answer: private, readonly, dedicated, unreachable from
    // outside. Nothing else can take this monitor.
    private readonly object _gate = new object();

    // A static gate is equally correct when the state it guards is static.
    // It is still private, which is the property that matters — `static` is
    // not what makes `lock (this)` wrong.
    private static readonly object StaticGate = new object();

    private int _counter;

    private static int _sharedCounter;

    public void Increment()
    {
        lock (_gate)
        {
            _counter++;
        }
    }

    public static void IncrementShared()
    {
        lock (StaticGate)
        {
            _sharedCounter++;
        }
    }

    public int Read()
    {
        lock (_gate)
        {
            return _counter;
        }
    }

    public static int ReadShared()
    {
        lock (StaticGate)
        {
            return _sharedCounter;
        }
    }

    public override string ToString() => $"{_counter}/{_sharedCounter}";
}
