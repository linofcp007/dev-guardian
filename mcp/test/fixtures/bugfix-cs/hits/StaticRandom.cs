// HITS for bugfix-cs-race-condition-static-random: two sites.
//
// `Random` carries mutable internal state and is documented as not thread-safe.
// Two threads inside `Next()` at once corrupt that state, and the failure mode
// is quiet: a run of identical values, or a long run of zeros, rather than an
// exception. It is the kind of defect that reaches production and then cannot
// be reproduced on one thread.
using System;

namespace Guardian.Fixtures.Hits;

public sealed class StaticRandom
{
    // 1. `static readonly`. The `readonly` is what makes this look safe and
    //    is exactly why it is not: the REFERENCE is immutable, the object's
    //    internal state is not.
    private static readonly Random Rng = new Random();

    // 2. Plain `static`, no `readonly`. Present as its own site because the
    //    rule's pattern names neither modifier — it matches by subset — so
    //    both spellings need a fixture to keep that property measured.
    private static Random Mutable = new Random();

    public int Roll() => Rng.Next(1, 7);

    public int RollMutable() => Mutable.Next(1, 7);
}
