// HITS for bugfix-cs-edge-case-modify-during-iteration: eleven sites.
//
// Removing from a collection while a `foreach` is enumerating it invalidates
// the enumerator: the next `MoveNext()` throws InvalidOperationException,
// "Collection was modified; enumeration operation may not execute."
//
// Sites 1-4 and 10-11 are one per ENUMERATED RECEIVER TYPE. metavariable-type
// is not subtype-aware, so each type in the rule's list is an independent claim
// and a type without a fixture could be deleted, or could never have worked,
// with no number moving. Same reasoning as loop-lte-count.
//
// SITE 8 IS THE ONE THAT MATTERS. It is the bug Java's fourth wave swallowed,
// ported here rather than rediscovered.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Guardian.Fixtures.Hits;

public sealed class ModifyDuringIteration
{
    private readonly List<int> _items = new List<int>();

    // 1.
    public void OverList(List<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); } }
    }

    // 2.
    public void OverHashSet(HashSet<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); } }
    }

    // 3.
    public void OverIList(IList<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); } }
    }

    // 4.
    public void OverICollection(ICollection<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); } }
    }

    // 5. `RemoveAt` rather than `Remove`. The rule binds the removal method to
    //    `$RM` and constrains it by regex, so the EXCLUSIONS unify the same
    //    method — measured, and it matters: with the exclusions naming
    //    `Remove` literally, a correct `RemoveAt(0); break;` became a false
    //    positive, because no exclusion could see it.
    public void RemoveAtDuringIteration(List<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.RemoveAt(0); } }
    }

    // 6. A plain field receiver.
    public void OverField()
    {
        foreach (var x in _items) { if (x > 1) { _items.Remove(x); } }
    }

    // 7. The `this.`-qualified twin, which needs the receiver to be bound
    //    through a metavariable-pattern before it is typed. Without that
    //    wrapper the qualified form is invisible while the plain one fires —
    //    the same defect the Java map rules carried.
    public void OverThisField()
    {
        foreach (var x in this._items) { if (x > 1) { this._items.Remove(x); } }
    }

    // 8. REMOVAL INSIDE A `switch` ARM, FOLLOWED BY `break`.
    //
    //    This is a real InvalidOperationException, and it is exactly the bug
    //    Java's wave 4 deleted. The `break` exclusion exists because
    //    `Remove(x); break;` normally leaves the LOOP, which makes the removal
    //    safe. Inside a `switch`, `break` leaves the SWITCH — the loop carries
    //    on to the invalidated enumerator.
    //
    //    Measured on this fixture: adding the exit exclusions alone closes the
    //    five false positives in misses/ AND swallows this site. The
    //    switch-inside-foreach re-inclusion is what keeps it. Note the
    //    nesting direction is load-bearing: the `switch` must be inside the
    //    `foreach`. A `foreach` inside a `switch` case is the opposite
    //    situation, where `break` really does leave the loop, and it is in
    //    misses/ as its own near-miss.
    //    THERE ARE TWO OF THESE, one per switch-label kind, and that is not
    //    duplication. The re-inclusion is two `pattern-inside` branches — one
    //    written with `case $C:`, one with `default:` — because a switch
    //    written with only `case` labels does not match the `default:` pattern
    //    and vice versa. With a single fixture carrying BOTH labels, either
    //    branch alone satisfied it and both read DEAD in the ablation while
    //    removing the pair was a regression. One switch of each kind is what
    //    makes each branch independently measurable.
    public void RemoveInSwitchCaseArm(List<int> xs, int mode)
    {
        foreach (var x in xs)
        {
            switch (mode)
            {
                case 0:
                    xs.Remove(x);
                    break;
            }
        }
    }

    // 9. The `default:`-only twin of site 8.
    public void RemoveInSwitchDefaultArm(List<int> xs, int mode)
    {
        foreach (var x in xs)
        {
            switch (mode)
            {
                default:
                    xs.Remove(x);
                    break;
            }
        }
    }

    // 10. `Collection<T>`, added 2026-08-21. Written from the SHAPE — a
    //     foreach over a collection that removes from itself — and not from
    //     the rule's type list: probed against the shipped rule, this exact
    //     method did not fire, because metavariable-type is not subtype-aware
    //     and `Collection<T>` was not enumerated. `Collection<T>` is the type
    //     the framework design guidelines tell you to expose from a public
    //     API, so it is not an exotic receiver.
    public void OverCollection(Collection<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); } }
    }

    // 11. `ObservableCollection<T>`, the same measurement and the likeliest
    //     real-world site of this defect: removing from the collection bound
    //     to a WPF/MAUI view while a `foreach` walks it. That C# does not
    //     exist in `dotnet/runtime`, which is why the corpus count for this
    //     rule stayed at zero either way.
    public void OverObservableCollection(ObservableCollection<int> xs)
    {
        foreach (var x in xs) { if (x > 1) { xs.Remove(x); } }
    }
}
