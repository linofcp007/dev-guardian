// HITS for bugfix-cs-race-condition-lock-on-shared-instance: two sites.
//
// Both lock on a monitor that code outside this type can also take, which is
// what makes them deadlocks waiting for a second participant rather than
// merely untidy.
using System;

namespace Guardian.Fixtures.Hits;

public sealed class LockShared
{
    private int _counter;

    // 1. `lock (this)`. Every caller holding a reference to this object can
    //    `lock` on it too, so the monitor is effectively public API — and
    //    nothing in the type's signature says so.
    public void IncrementLockingThis()
    {
        lock (this)
        {
            _counter++;
        }
    }

    // 2. `lock ("literal")`, which is strictly worse. String literals are
    //    INTERNED, so this monitor is shared by every piece of code in the
    //    process that happens to lock on the same text — including code in a
    //    different assembly that has never heard of this class.
    public void IncrementLockingLiteral()
    {
        lock ("guardian-counter-gate")
        {
            _counter++;
        }
    }

    public int Read() => _counter;
}
