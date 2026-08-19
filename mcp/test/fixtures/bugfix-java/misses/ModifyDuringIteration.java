import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Correct Java: none of these can throw ConcurrentModificationException.
 *
 * The exit-terminated near-misses vary the SHAPE and not just the exit
 * keyword: an interposed assignment, an interposed log line, a labelled
 * break out of a nested loop, a value computed before the return, a
 * `Collection`-typed receiver. Writing each one as the exclusion pattern with
 * its metavariables filled in would make the ablation table one-to-one and
 * blind — the exclusions were adjacency-only precisely because that is how
 * they were tested.
 */
public class ModifyDuringIteration {
    void viaIterator(List<String> items) {
        Iterator<String> it = items.iterator();
        while (it.hasNext()) {
            if (it.next().isEmpty()) { it.remove(); }
        }
    }
    // viaRemoveIf is DOCUMENTARY, not discriminating: it has no `for` loop
    // at all, so no mutation of a rule anchored on a for-each over `$COLL`
    // could ever make it fire.
    void viaRemoveIf(List<String> items) {
        items.removeIf(String::isEmpty);
    }
    // removeFromOther is DISCRIMINATING: it genuinely exercises the `$COLL`
    // identity requirement. Mutate the shipped rule to let the removed-from
    // collection be a metavariable independent from the one bound by the
    // for-each — dropping the requirement that it be the SAME `$COLL` — and
    // this fires, because it removes from `b` while iterating `a`, which is
    // legal Java that the current rule correctly leaves alone.
    void removeFromOther(List<String> a, List<String> b) {
        for (String s : a) { b.remove(s); }
    }
    void readOnly(List<String> items) {
        for (String s : items) { System.out.println(s); }
    }

    // ---- procurar, remover, sair -----------------------------------------
    //
    // Eight functions, four exits times two shapes. `return` and `throw`
    // leave the METHOD from any depth; a LABELLED `break` leaves the loop
    // from any depth, a `switch` included; a plain `break` leaves the loop
    // only when the removal is not inside a `switch`, which is why that one
    // clause sits behind a re-inclusion and why the two `switch` cases live
    // in hits/, not here.
    //
    // The second shape in each pair puts ONE statement between the removal
    // and the exit. That is not decoration either: the adjacency-only
    // exclusions that shipped meant `list.remove(s); removed = 1; break;` —
    // correct Java, and the first thing anybody writes when the caller needs
    // to know whether anything was removed — fired at ERROR.

    // findRemoveReturn: the returned value is computed BEFORE the removal, so
    // the removal is not even the last interesting statement.
    String findRemoveReturn(List<String> items, String target) {
        for (String s : items) {
            if (s.equals(target)) {
                items.remove(s);
                return target;
            }
        }
        return null;
    }

    // findRemoveFlagReturn: an assignment between the removal and the return.
    boolean findRemoveFlagReturn(List<String> items, String target) {
        boolean hit = false;
        for (String s : items) {
            if (s.equals(target)) {
                items.remove(s);
                hit = true;
                return hit;
            }
        }
        return hit;
    }

    // findRemoveThrow: the loop cannot continue past a throw. A `HashSet`
    // receiver, so it also walks a different `pattern-either` branch.
    void findRemoveThrow(HashSet<String> items, String target) {
        for (String s : items) {
            if (s.equals(target)) {
                items.remove(s);
                throw new IllegalStateException("gone: " + target);
            }
        }
    }

    // findRemoveLogThrow: a log line between the removal and the throw.
    void findRemoveLogThrow(List<String> items, String target) {
        for (String s : items) {
            if (s.equals(target)) {
                items.remove(s);
                System.err.println("removed " + s);
                throw new IllegalStateException("gone");
            }
        }
    }

    // findRemoveLabelledBreak: the removal is in an INNER loop and the break
    // is labelled, so it leaves the loop that is being iterated. A plain
    // `break` here would leave only the inner loop and would be a real bug —
    // which is why the labelled form needs a clause of its own.
    void findRemoveLabelledBreak(List<String> items, List<String> others) {
        outer:
        for (String s : items) {
            for (String o : others) {
                if (s.equals(o)) {
                    items.remove(s);
                    break outer;
                }
            }
        }
    }

    // findRemoveFlagLabelledBreak: an assignment between the two.
    boolean findRemoveFlagLabelledBreak(List<String> items, List<String> others) {
        boolean hit = false;
        outer:
        for (String s : items) {
            for (String o : others) {
                if (s.equals(o)) {
                    items.remove(s);
                    hit = true;
                    break outer;
                }
            }
        }
        return hit;
    }

    // findRemoveBreak is DISCRIMINATING for the plain-`break` exclusion, and
    // for that one only: same argument as findRemoveReturn but the loop is
    // left by `break`, a different AST node needing its own clause. The
    // receiver is a `Collection`, the widest of the enumerated types.
    void findRemoveBreak(Collection<String> items, String target) {
        for (String s : items) {
            if (s.equals(target)) {
                items.remove(s);
                break;
            }
        }
    }

    // findRemoveLogBreak: a log line between the removal and the break.
    void findRemoveLogBreak(HashSet<String> items, String target) {
        for (String s : items) {
            if (s.equals(target)) {
                items.remove(s);
                System.out.println("removed " + s);
                break;
            }
        }
    }

    // cowRemove is DISCRIMINATING for the receiver-type restriction.
    // `CopyOnWriteArrayList` iterates over a snapshot taken when the iterator
    // was created, so mutating it mid-iteration is not merely tolerated, it
    // is the collection's designed usage and the textbook safe-removal idiom
    // for it. Widen `$COLL` back to any receiver — drop the
    // `metavariable-type` restriction — and this fires at ERROR on code that
    // cannot throw.
    void cowRemove(CopyOnWriteArrayList<String> cow) {
        for (String s : cow) {
            if (s.isEmpty()) { cow.remove(s); }
        }
    }

    // switchLabelledBreak and switchReturn are the near-misses that keep the
    // `switch` re-inclusion honest in the OTHER direction. A plain `break`
    // inside a `switch` leaves the switch and not the loop — that is a hit,
    // and it lives in hits/. A LABELLED break and a `return` do leave the
    // loop and the method respectively, from inside a `switch` just as from
    // anywhere else, so those two must stay silent. If the re-inclusion were
    // written as "anything inside a switch fires", these would break.
    void switchLabelledBreak(List<String> items) {
        outer:
        for (String s : items) {
            switch (s) {
                case "x":
                    items.remove(s);
                    break outer;
                default:
                    break;
            }
        }
    }

    String switchReturn(List<String> items) {
        for (String s : items) {
            switch (s) {
                case "x":
                    items.remove(s);
                    return s;
                default:
                    break;
            }
        }
        return null;
    }
}
