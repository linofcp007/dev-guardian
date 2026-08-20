// HITS for bugfix-cs-null-safety-as-cast-deref: nine sites.
//
// `x as T` yields null when the cast fails — that is the whole difference
// between `as` and a direct cast, which throws. Dereferencing the result
// without checking turns a type mismatch into a NullReferenceException at a
// distance from its cause.
//
// TWO OF THESE ARE PLAIN. THE OTHER SEVEN ARE THE POINT.
//
// Sites 3-9 are guaranteed NREs that sit RIGHT NEXT TO a guard — in the `else`
// arm of the check, in the arm of a ternary the condition rules out, in a
// disjunction that proves nothing, behind a guard on a different variable.
// They are here, in hits/, rather than in misses/, because of what ablation
// axis 2 measures: "removing this clause must not REVEAL a finding in hits/".
// An exclusion that swallows a real bug is only visible if that bug is in this
// file.
//
// This is not hypothetical. Measured on this very fixture: writing the two
// `if` exclusions as `if ($V != null) { ... }` — the obvious spelling — closes
// the correct cases in misses/ AND swallows sites 3 and 4 below, because
// `pattern-not-inside` excludes the whole node it matched, `else` arm
// included. Scoping the exclusion to the then-block, `if ($V != null) { <...
// $V.$M ...>; }`, closes the same correct cases and keeps both bugs. The Java
// pack shipped the swallow and found it four waves later; here it never
// shipped, because the fixture existed before the clause did.
using System;

namespace Guardian.Fixtures.Hits;

public sealed class AsCast
{
    // 1. The plain shape.
    public int Bare(object o)
    {
        var s = o as string;
        return s.Length;
    }

    // 2. A method call rather than a property read — `$M` binds either.
    public int BareMethod(object o)
    {
        var s = o as string;
        return s.IndexOf('a');
    }

    // 3. THE ELSE ARM of a null check. The guard proves `s` IS null here, so
    //    this is not merely unguarded — it is guaranteed to throw.
    public int ElseArm(object o)
    {
        var s = o as string;
        if (s != null) { return 0; } else { return s.Length; }
    }

    // 4. The same for the `is not null` spelling, which is a different node
    //    and therefore a different exclusion.
    public int ElseArmIsNotNull(object o)
    {
        var s = o as string;
        if (s is not null) { return 0; } else { return s.Length; }
    }

    // 5. The arm of a ternary the condition RULES OUT.
    public int TernaryFalseArm(object o)
    {
        var s = o as string;
        return s != null ? 0 : s.Length;
    }

    // 6. A POSITIVE-first disjunction: `||` short-circuits, so the right side
    //    runs precisely when `s != null` was FALSE. The test is present and
    //    proves the opposite of what it looks like it proves.
    public bool PositiveDisjunction(object o)
    {
        var s = o as string;
        return s != null || s.Length > 0;
    }

    // 7. A NEGATED guard in a conjunction: `&&` runs the right side only when
    //    the left was true, i.e. only when `s` is null.
    public bool NegatedConjunction(object o)
    {
        var s = o as string;
        return s == null && s.Length > 0;
    }

    // 8. A guard on a DIFFERENT variable. Every clause unifies `$V`, and this
    //    is what proves that unification is load-bearing rather than
    //    decorative: drop it from any clause and this stops firing.
    public int GuardOnDifferentVariable(object o, object p)
    {
        var s = o as string;
        var t = p as string;
        if (t != null) { return s.Length; }
        return 0;
    }

    // 9. The same for the early-exit clauses.
    public int EarlyExitOnDifferentVariable(object o, object p)
    {
        var s = o as string;
        var t = p as string;
        if (t == null) { return 0; }
        return s.Length;
    }
}
