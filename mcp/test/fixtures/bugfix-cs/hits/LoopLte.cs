// HITS for bugfix-cs-off-by-one-loop-lte-length (4) and
// -loop-lte-count (10). Fourteen sites.
//
// `i <= a.Length` runs one position past the end, and the index `a.Length` is
// always out of bounds — an IndexOutOfRangeException, or in the `.Count` case
// an ArgumentOutOfRangeException.
//
// The Count sites are ONE PER ENUMERATED RECEIVER TYPE, and that is not
// padding. `metavariable-type` is NOT subtype-aware — measured: a receiver
// declared `List<int>` does not match `ICollection<$T>`, and vice versa — so
// every type in the rule's list is its own independent claim. A type with no
// fixture behind it could be deleted, or could silently never have worked,
// without a single number moving.
//
// SITES 9-12 ARE THE SPELLING DIMENSIONS, added 2026-08-21 and written from
// the shape rather than from the pattern. Both rules used to read one spelling
// of each of two independent dimensions, and the fixtures carried only that
// one, so neither gap could ever show up as a number:
//
//   increment: `i++` matched, `++i` did not — different nodes.
//   body:      `{ ... }` did not match a braceless single-statement body.
//
// Neither missing spelling is exotic; both are ordinary C#. Widening the two
// rules to cover them added ZERO findings on 11 800 files of `dotnet/runtime`.
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Guardian.Fixtures.Hits;

public sealed class LoopLte
{
    // --- loop-lte-length: the two types that carry `.Length` ---------------

    // 1. An array. `xs[xs.Length]` throws on the final iteration.
    public int SumPastEndOfArray(int[] xs)
    {
        var s = 0;
        for (var i = 0; i <= xs.Length; i++) { s += xs[i]; }
        return s;
    }

    // 2. A string, which has `.Length` too and indexes the same way.
    public int SumPastEndOfString(string text)
    {
        var s = 0;
        for (var i = 0; i <= text.Length; i++) { s += text[i]; }
        return s;
    }

    // --- loop-lte-count: one per enumerated receiver type ------------------

    // 3.
    public int PastEndOfList(List<int> xs)
    {
        var s = 0;
        for (var i = 0; i <= xs.Count; i++) { s += xs[i]; }
        return s;
    }

    // 4.
    public int PastEndOfIList(IList<int> xs)
    {
        var s = 0;
        for (var i = 0; i <= xs.Count; i++) { s += xs[i]; }
        return s;
    }

    // 5. `ICollection<T>` has no indexer, so the body counts instead of
    //    indexing — the off-by-one is in the loop header either way.
    public int PastEndOfICollection(ICollection<int> xs)
    {
        var s = 0;
        for (var i = 0; i <= xs.Count; i++) { s += i; }
        return s;
    }

    // 6.
    public int PastEndOfIReadOnlyList(IReadOnlyList<int> xs)
    {
        var s = 0;
        for (var i = 0; i <= xs.Count; i++) { s += xs[i]; }
        return s;
    }

    // 7.
    public int PastEndOfDictionary(Dictionary<string, int> map)
    {
        var s = 0;
        for (var i = 0; i <= map.Count; i++) { s += i; }
        return s;
    }

    // 8.
    public int PastEndOfHashSet(HashSet<int> set)
    {
        var s = 0;
        for (var i = 0; i <= set.Count; i++) { s += i; }
        return s;
    }

    // --- the two spelling dimensions, one hit each per rule ----------------

    // 9. PRE-INCREMENT, on the `.Length` rule. `++i` is a different AST node
    //    from `i++`; the shipped pattern read only the second, so this exact
    //    method was a silent false negative. `++i` is common enough in real
    //    C# that `dotnet/runtime` itself writes it in a `<=` loop header.
    public int SumPastEndOfArrayPreIncrement(int[] xs)
    {
        var s = 0;
        for (var i = 0; i <= xs.Length; ++i) { s += xs[i]; }
        return s;
    }

    // 10. PRE-INCREMENT, on the `.Count` rule. Its own method because the two
    //     rules carry separate patterns and a fix to one is invisible to a
    //     fixture that only exercises the other — the same reasoning that
    //     gives each type list its own near-miss in misses/.
    public int PastEndOfListPreIncrement(List<int> xs)
    {
        var s = 0;
        for (var i = 0; i <= xs.Count; ++i) { s += xs[i]; }
        return s;
    }

    // 11. BRACELESS BODY, on the `.Length` rule. A `{ ... }` in the pattern
    //     does not match a single-statement body with no braces — measured.
    public int SumPastEndOfArrayNoBraces(int[] xs)
    {
        var s = 0;
        for (var i = 0; i <= xs.Length; i++) s += xs[i];
        return s;
    }

    // 12. BRACELESS BODY, on the `.Count` rule.
    public int PastEndOfListNoBraces(List<int> xs)
    {
        var s = 0;
        for (var i = 0; i <= xs.Count; i++) s += xs[i];
        return s;
    }

    // --- the two receiver types added 2026-08-21 --------------------------

    // 13. `Collection<T>`: a BCL collection with `Count` and an indexer, and
    //     the type the framework design guidelines tell you to expose from a
    //     public API. Not subtype-matched by any of the six original entries.
    public int PastEndOfCollection(Collection<int> xs)
    {
        var s = 0;
        for (var i = 0; i <= xs.Count; i++) { s += xs[i]; }
        return s;
    }

    // 14. `ObservableCollection<T>`: the collection type of every WPF and MAUI
    //     codebase, which is exactly the C# that a corpus of `dotnet/runtime`
    //     contains none of.
    public int PastEndOfObservableCollection(ObservableCollection<int> xs)
    {
        var s = 0;
        for (var i = 0; i <= xs.Count; i++) { s += xs[i]; }
        return s;
    }
}
