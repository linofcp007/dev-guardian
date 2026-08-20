// NEAR-MISSES for bugfix-cs-null-safety-as-cast-deref. Written first, and this
// is the largest misses file in the pack by design.
//
// The rule's positive pattern is `$V.$M`, the broadest in the pack: once
// `var s = o as string;` is in scope, EVERY later use of `s` is a candidate.
// So the guard list does the whole job, and this file is the specification of
// what a guard looks like.
//
// AND IT IS NOT ENOUGH ON ITS OWN. A near-miss can show that an exclusion
// EXISTS; it can never show that the exclusion is the right WIDTH, because it
// was chosen to be caught by it. The width is measured by the guard-adjacent
// bugs in hits/AsCast.cs, which is where seven guaranteed NREs sit right next
// to the guards that do not protect them. Read the two files together.
//
// Ablation axis 3 — the one that measures width on code nobody wrote as a
// fixture — is unavailable for this whole round: the repo has no C# source
// outside this tree. That is the reason for the size of both files.
using System;

namespace Guardian.Fixtures.Misses;

public sealed class AsCast
{
    // --- one method per exclusion clause. Delete the named clause and only
    // --- that method fires.

    // clause: if ($V != null) { <... $V.$M ...>; }
    public int IfNotNull(object o)
    {
        var s = o as string;
        if (s != null) { return s.Length; }
        return 0;
    }

    // clause: if ($V is not null) { <... $V.$M ...>; }
    public int IsNotNull(object o)
    {
        var s = o as string;
        if (s is not null) { return s.Length; }
        return 0;
    }

    // clause: if ($V == null) { return ...; } ...
    public int EarlyReturn(object o)
    {
        var s = o as string;
        if (s == null) { return 0; }
        return s.Length;
    }

    // clause: if ($V is null) { return ...; } ...
    public int IsNullEarlyReturn(object o)
    {
        var s = o as string;
        if (s is null) { return 0; }
        return s.Length;
    }

    // clause: if ($V == null) { throw ...; } ...
    public int EarlyThrow(object o)
    {
        var s = o as string;
        if (s == null) { throw new ArgumentException("not a string", nameof(o)); }
        return s.Length;
    }

    // clause: if ($V == null) { continue; } ...
    public int EarlyContinue(object[] os)
    {
        var n = 0;
        foreach (var o in os)
        {
            var s = o as string;
            if (s == null) { continue; }
            n += s.Length;
        }
        return n;
    }

    // clause: ArgumentNullException.ThrowIfNull($V); ...
    public int ThrowIfNull(object o)
    {
        var s = o as string;
        ArgumentNullException.ThrowIfNull(s);
        return s.Length;
    }

    // clause: $V != null && <... $V.$M ...>
    public bool Conjunction(object o)
    {
        var s = o as string;
        return s != null && s.Length > 0;
    }

    // clause: $V == null || <... $V.$M ...>
    public bool Disjunction(object o)
    {
        var s = o as string;
        return s == null || s.Length == 0;
    }

    // clause: $V != null ? <... $V.$M ...> : ...
    public int Ternary(object o)
    {
        var s = o as string;
        return s != null ? s.Length : 0;
    }

    // clause: $V == null ? ... : <... $V.$M ...>
    public int TernaryNegated(object o)
    {
        var s = o as string;
        return s == null ? 0 : s.Length;
    }

    // --- FREE, and labelled so nobody mistakes them for evidence. These three
    // --- are silent because of the LANGUAGE, not because of a clause: no
    // --- exclusion mentions them, and deleting every exclusion in the rule
    // --- leaves all three silent. Measured.

    // `?.` is a different node from `.`, so the positive pattern never matches.
    public int NullConditional(object o)
    {
        var s = o as string;
        return s?.Length ?? 0;
    }

    // A pattern match is a different node again, and it is the idiomatic
    // modern replacement for the whole `as`-then-check dance.
    public int IsPattern(object o)
    {
        if (o is string s) { return s.Length; }
        return 0;
    }

    // `o as string ?? "d"` is a coalesce whose left operand is the cast, so
    // the initialiser is not a bare `as` and `pattern-inside` never binds.
    public int Coalesced(object o)
    {
        var s = o as string ?? "default";
        return s.Length;
    }
}
