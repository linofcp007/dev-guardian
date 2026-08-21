// NEAR-MISSES for bugfix-cs-off-by-one-loop-lte-length and -loop-lte-count.
// Written first.
//
// Each method below says which clause it is discriminating FOR, because they
// do not all carry the same weight and pretending they do is how a fixture
// file stops being evidence. The last one is DOCUMENTARY and says so.
using System;
using System.Collections.Generic;

namespace Guardian.Fixtures.Misses;

/// A domain object whose `Length` and `Count` are ordinary int members. This
/// is not contrived: a segment has a length, a batch has a count, and neither
/// is a collection. Untyped, both rules fire on it — the exact defect the Java
/// pack shipped and then had to close.
public sealed class Segment
{
    public int Length { get; init; }

    public int Count { get; init; }
}

public sealed class LoopLte
{
    // DISCRIMINATING for the `<=` operator. Flip the shipped rule's `<=` to
    // `<` — the easiest typo to make in it — and this fires.
    public int InBounds(int[] xs)
    {
        var s = 0;
        for (var i = 0; i < xs.Length; i++) { s += xs[i]; }
        return s;
    }

    // DISCRIMINATING for the `<=` operator IN THE PRE-INCREMENT BRANCH, added
    // 2026-08-21 with that branch, and MUTATION-TESTED rather than asserted:
    // flip the `<=` to `<` in the `++$I` branch alone and this fires while
    // InBounds above stays silent. Measured, both directions.
    //
    // That is the whole point of it. The rule is now a `pattern-either` of two
    // increment spellings and EACH BRANCH CARRIES ITS OWN COPY of the `<=`, so
    // a near-miss written over one spelling is blind to a mutation in the
    // other — the same reason FencePosts and FencePostsByCount below are two
    // methods rather than one.
    public int InBoundsPreIncrement(int[] xs)
    {
        var s = 0;
        for (var i = 0; i < xs.Length; ++i) { s += xs[i]; }
        return s;
    }

    // DOCUMENTARY, not discriminating, and labelled so because the mutation
    // test says so rather than because it looks that way. The body of both
    // branches went from `{ ... }` to `...` on 2026-08-21 so that a braceless
    // single-statement body matches — and once it does, the braced and
    // braceless spellings go through the SAME pattern, so no single-clause
    // mutation fires this one without also firing InBounds. It was written
    // expecting to discriminate; it does not, and saying so is cheaper than
    // leaving a reader to assume every near-miss here carries equal weight.
    //
    // What it does pin is worth one method: the correct half-open loop stays
    // silent in the spelling the widening newly reaches. A widening that went
    // one step further and dropped the bound comparison would fire here.
    public int InBoundsNoBraces(int[] xs)
    {
        var s = 0;
        for (var i = 0; i < xs.Length; i++) s += xs[i];
        return s;
    }

    // DISCRIMINATING for the BOUND EXPRESSION, and it catches a mutation
    // InBounds cannot: widen the bound to `$I <= $BOUND` (any expression
    // rather than `$A.Length`) and this fires while InBounds does not. The
    // loop is correct — it deliberately stops one short.
    public int ToLengthMinusOne(int[] xs)
    {
        var s = 0;
        for (var i = 0; i <= xs.Length - 1; i++) { s += xs[i]; }
        return s;
    }

    // DISCRIMINATING for the `metavariable-type` clause on the LENGTH rule,
    // and for nothing else: delete that clause and this fires alone, on a
    // loop with no array and no string in it. The inclusive bound is
    // deliberate — it counts fence posts along a segment rather than indexing
    // anything.
    public int FencePosts(Segment seg)
    {
        var total = 0;
        for (var i = 0; i <= seg.Length; i++) { total += i; }
        return total;
    }

    // The same, for the COUNT rule's type clause. It needs its own method
    // because the two rules have separate type lists, and a mutation to one
    // list is invisible to a fixture that only exercises the other.
    public int FencePostsByCount(Segment seg)
    {
        var total = 0;
        for (var i = 0; i <= seg.Count; i++) { total += i; }
        return total;
    }

    // DISCRIMINATING for the SENTINEL-LOOP exclusion added 2026-08-21, and it
    // is the only near-miss here that came from real code rather than from
    // imagination: axis 3 of the ablation found that the `$I++` branch of the
    // LENGTH rule produced exactly two findings on 11 800 files of
    // `dotnet/runtime`, and that both were this shape.
    //
    // The loop runs one past the end ON PURPOSE. The extra position is not an
    // index — the body compares `i` against the bound first and takes the
    // end branch, which is how you flush a trailing token without duplicating
    // the flush after the loop. `ConfigPathUtility.IsValid` is this method,
    // near enough to copy.
    //
    // It carries the `<` comparison in the `i++` spelling; SentinelSwitch
    // below carries `==` in the `++i` spelling. The pairing is CROSSED on
    // purpose: the exclusion is a `pattern-not` holding a two-branch
    // increment `pattern-either` and a two-branch comparison
    // `pattern-either`, so a single near-miss covering one cell of that 2x2
    // would leave three clauses with nothing to prove them and they would
    // read DEAD. Two crossed cells reach all four. Mutation-tested: delete
    // any ONE of the four branches and exactly one of these two methods
    // fires.
    public bool SentinelTernary(char[] xs)
    {
        var start = -1;
        for (var i = 0; i <= xs.Length; i++)
        {
            var ch = i < xs.Length ? xs[i] : ';';
            if (ch == ';')
            {
                if (i == start + 1) { return false; }
                start = i;
            }
        }

        return true;
    }

    // DISCRIMINATING for the same exclusion, in the other two cells of the
    // 2x2: the `==` comparison and the `++i` increment. Modelled on
    // `XslNumber.ParseFormat`, the second of the two real sites.
    public int SentinelSwitch(char[] xs)
    {
        var tokens = 0;
        var startOfToken = 0;
        for (var i = 0; i <= xs.Length; ++i)
        {
            if (i == xs.Length || xs[i] == ',')
            {
                tokens += i - startOfToken;
                startOfToken = i;
            }
        }

        return tokens;
    }

    // DOCUMENTARY, not discriminating, and worth labelling so a reader does
    // not assume every near-miss carries the same weight. A `foreach` has no
    // `var $I = 0; $I <= $A.Length; $I++` header at all — it is a
    // structurally different node, so no mutation of the pattern could make
    // it fire. It records that rewriting the loop is the safe fix; it proves
    // nothing about the rule.
    public int ForEach(int[] xs)
    {
        var s = 0;
        foreach (var x in xs) { s += x; }
        return s;
    }

    // Also documentary: the correct half-open loop over a List.
    public int ListInBounds(List<int> xs)
    {
        var s = 0;
        for (var i = 0; i < xs.Count; i++) { s += xs[i]; }
        return s;
    }
}
