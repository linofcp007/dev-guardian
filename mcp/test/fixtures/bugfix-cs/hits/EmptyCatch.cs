// HITS for bugfix-cs-error-handling-empty-catch: five sites over the rule's
// three branches.
//
// C# has TWO spellings of an empty catch that Java does not — `catch (E) { }`
// with no identifier and a bare `catch { }` — and a single-branch port of the
// Java rule loses both. One method per branch here, so deleting a branch
// moves a number.
//
// `try { ... } catch (...) { }` does NOT parse: there is no "any catch"
// wildcard, which is why this is three branches and not one.
using System;

namespace Guardian.Fixtures.Hits;

public sealed class EmptyCatch
{
    // Branch 1: a named catch parameter whose name is not one of the three
    // intent markers.
    public void NamedSwallow(string p)
    {
        try { Parse(p); } catch (FormatException ex) { }
    }

    // Branch 2: no identifier at all. C#-only.
    public void UnnamedSwallow(string p)
    {
        try { Parse(p); } catch (FormatException) { }
    }

    // Branch 3: a bare catch, which swallows EVERYTHING, not just one type.
    // C#-only, and the worst of the three.
    public void BareSwallow(string p)
    {
        try { Parse(p); } catch { }
    }

    // The two below are DISCRIMINATING for the `$` inside the negative
    // lookahead, which is the whole reason the regex is written
    // `^(?!(ignore|ignored|expected)$)` and not `^(?!(ignore|ignored|expected))`.
    // A name that merely STARTS with an intent marker is not a declaration of
    // intent, and both of these are still silent swallows. Drop the `$` and
    // both stop firing.
    //
    // The `$` is safe here only because the pattern is already anchored at the
    // start by Semgrep itself — a regex anchored ONLY with `$` matches nothing
    // in Semgrep and looks live while being dead.
    public void PrefixedName(string p)
    {
        try { Parse(p); } catch (FormatException ignoreMe) { }
    }

    public void SuffixedName(string p)
    {
        try { Parse(p); } catch (FormatException expectedly) { }
    }

    private static void Parse(string p) => int.Parse(p);
}
