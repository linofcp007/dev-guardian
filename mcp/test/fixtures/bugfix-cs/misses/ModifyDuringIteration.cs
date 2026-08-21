// NEAR-MISSES for bugfix-cs-edge-case-modify-during-iteration. Written first.
//
// Removing and then LEAVING the loop is correct: the enumerator is never
// advanced again, so it is never asked to notice the modification. That is the
// whole exclusion set, and it is also where this rule's only unsoundness
// lives — see hits/ site 8, and read the two files together.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace Guardian.Fixtures.Misses;

public sealed class ModifyDuringIteration
{
    // clause: $RM; return ...;
    public void ThenReturn(List<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); return; } }
    }

    // clause: $RM; $S1; return ...;
    public void ThenStatementThenReturn(List<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); Console.WriteLine(x); return; } }
    }

    // clause: $RM; throw ...;
    public void ThenThrow(List<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); throw new InvalidOperationException("bad"); } }
    }

    // clause: $RM; $S1; throw ...;
    public void ThenStatementThenThrow(List<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); Console.WriteLine(x); throw new InvalidOperationException("bad"); } }
    }

    // clause: $RM; break;  (the third branch of the switch-aware disjunct)
    public void ThenBreak(List<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); break; } }
    }

    // clause: $RM; $S1; break;
    public void ThenStatementThenBreak(List<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); Console.WriteLine(x); break; } }
    }

    // DISCRIMINATING for binding the removal method to `$RM`. With the
    // exclusions naming `Remove` literally while the positive pattern also
    // accepted `RemoveAt`, this correct method was a FALSE POSITIVE: no
    // exclusion could match it. Measured, and the reason the rule unifies the
    // method name rather than repeating it.
    public void RemoveAtThenBreak(List<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.RemoveAt(0); break; } }
    }

    // THE EXIT EXCLUSIONS ON A NEWLY ENUMERATED TYPE. `ObservableCollection<T>`
    // joined the type list on 2026-08-21, and a type list and an exclusion list
    // are independent: nothing about adding a type says the exclusions still
    // reach it. They unify `$COLL` structurally rather than by type, so they
    // do — but that is a claim, and this is the fixture that holds it. Written
    // for `ObservableCollection` rather than for `Collection` because it is the
    // one a real WPF codebase would carry.
    //
    // NOT UNIQUELY DISCRIMINATING TODAY, and said rather than left to be
    // assumed: because the exclusions are type-blind, no single-clause mutation
    // fires this without also firing ThenBreak above. It earns its place the
    // day someone writes a type-dependent exclusion, which is exactly the day
    // nobody would think to check.
    public void NewTypeThenBreak(ObservableCollection<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); break; } }
    }

    // THE OPPOSITE NESTING, and the reason the re-inclusion in the rule is
    // written as switch-INSIDE-foreach rather than as bare lexical containment
    // in a `switch`. Here the `foreach` is inside the `case`, so `break`
    // leaves the LOOP and the removal is safe. A re-inclusion written as
    // "somewhere inside a switch" would fire here.
    public void LoopInsideSwitchCase(List<int> xs, int mode)
    {
        switch (mode)
        {
            case 0:
                foreach (var x in xs)
                {
                    if (x > 1) { xs.Remove(x); break; }
                }
                break;
            default:
                break;
        }
    }

    // DISCRIMINATING for the `metavariable-regex` on `$RM`. The rule binds the
    // removal method to a metavariable so the exclusions can unify it, which
    // means the regex is the ONLY thing keeping the positive pattern from
    // matching every method called on the iterated collection. Reading the
    // collection during a `foreach` is correct and common; delete the regex
    // and this fires.
    public int ReadsDuringIteration(List<int> xs)
    {
        var total = 0;
        foreach (var x in xs) { total += xs.IndexOf(x); }
        return total;
    }

    // --- FREE, and labelled: silent because of the shape, not a clause ------

    // Iterating a COPY is the standard fix. `$COLL` never unifies, because the
    // loop enumerates `xs.ToList()` and the removal targets `xs`.
    public void OverACopy(List<int> xs)
    {
        foreach (var x in xs.ToList()) { if (x > 1) { xs.Remove(x); } }
    }

    // `RemoveAll` is the better fix and a different method name.
    public void RemoveAll(List<int> xs)
    {
        xs.RemoveAll(x => x > 1);
    }

    // Removing from a DIFFERENT collection is not this rule's business.
    public void OtherCollection(List<int> xs, List<int> ys)
    {
        foreach (var x in xs) { ys.Remove(x); }
    }

    // DICTIONARY, and this one is a deliberate design decision rather than an
    // accident of the type list. Removing from a Dictionary while enumerating
    // it has been DOCUMENTED SAFE since .NET Core 3.0, so a `Dictionary`
    // branch would fire on correct code. It is left out, and this method is
    // here to keep it out.
    public void DictionaryRemovalIsSafe(Dictionary<string, int> map)
    {
        foreach (var kv in map)
        {
            if (kv.Value > 1) { map.Remove(kv.Key); }
        }
    }
}
