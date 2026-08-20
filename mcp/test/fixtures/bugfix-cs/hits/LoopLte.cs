// HITS for bugfix-cs-off-by-one-loop-lte-length (2) and
// -loop-lte-count (6). Eight sites.
//
// `i <= a.Length` runs one position past the end, and the index `a.Length` is
// always out of bounds — an IndexOutOfRangeException, or in the `.Count` case
// an ArgumentOutOfRangeException.
//
// The six Count sites are ONE PER ENUMERATED RECEIVER TYPE, and that is not
// padding. `metavariable-type` is NOT subtype-aware — measured: a receiver
// declared `List<int>` does not match `ICollection<$T>`, and vice versa — so
// every type in the rule's list is its own independent claim. A type with no
// fixture behind it could be deleted, or could silently never have worked,
// without a single number moving.
using System.Collections.Generic;

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
}
