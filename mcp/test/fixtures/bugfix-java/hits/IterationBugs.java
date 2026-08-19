import java.util.List;

/**
 * REAL-BUGS CORPUS for `edge-case-modify-during-iteration` — written by the
 * REVIEWER, not by the rule author, and the third file of that corpus after
 * RealBugs.java and ElseArm.java.
 *
 * It exists because the corpus was measured and found to cover 4 of the 8
 * rules — `map-get-deref` 9, `optional-get` 6, `loop-lte-length` 4,
 * `static-dateformat` 1 — and to carry NOTHING for this rule. That was the
 * riskiest of the four gaps: `modify-during-iteration` carries 37 clauses and
 * the file's only nested re-inclusion, and it is the rule whose exclusion
 * swallowed a real `ConcurrentModificationException` in wave 4. Its real bugs
 * lived only in `hits/ModifyDuringIteration.java`, written by the rule's own
 * author — exactly the artefact the corpus exists to compensate for.
 *
 * Every method here throws `ConcurrentModificationException`. None of them is
 * a minimal instantiation: each puts the `remove()` at a nesting depth or
 * behind a statement shape that a future tightening of the `break` exclusions
 * plausibly swallows. The count is asserted per file, so any exclusion that
 * drops it has eaten a real bug and has to justify itself.
 */
public class IterationBugs {

    // I1: the `switch` is nested one level deeper than the for-each body,
    // inside an `if`. `break` leaves the SWITCH, the for-each calls `next()`
    // again: CME. The re-inclusion disjunct has to reach through the `if`.
    void i1(List<String> list, boolean enabled) {
        for (String s : list) {
            if (enabled) {
                switch (s) {
                    case "x":
                        list.remove(s);
                        break;
                    default:
                        break;
                }
            }
        }
    }

    // I2: the `switch` is inside an INNER loop inside the for-each over
    // `list`. `break` leaves the switch; both loops carry on, so the CME is on
    // `list`. This is the shape closest to the correct code the wave-6 fix had
    // to keep firing on — a loop written inside a `case` — with the nesting
    // order the other way round.
    void i2(List<String> list, List<String> others) {
        for (String s : list) {
            for (String o : others) {
                switch (o) {
                    case "x":
                        list.remove(s);
                        break;
                    default:
                        break;
                }
            }
        }
    }

    // I3: the `switch` is inside a `try` inside the for-each, with a `finally`
    // that runs after the `break`.
    void i3(List<String> list) {
        for (String s : list) {
            try {
                switch (s) {
                    case "x":
                        list.remove(s);
                        break;
                    default:
                        break;
                }
            } finally {
                System.out.println("done");
            }
        }
    }

    // I4: a BRACED `case` block. The braces make the case body a block
    // statement rather than a statement list, which is a different AST shape
    // from the one the `switch` hit fixtures pin.
    void i4(List<String> list) {
        for (String s : list) {
            switch (s) {
                case "x": {
                    list.remove(s);
                    break;
                }
                default:
                    break;
            }
        }
    }

    // I5: TWO statements between the removal and the `break`, inside the
    // switch. The bounded exclusions tolerate exactly one — accepted false
    // positive (5) — so what keeps this firing is the `switch` re-inclusion,
    // not the bound. Both have to hold.
    void i5(List<String> list) {
        for (String s : list) {
            switch (s) {
                case "x":
                    list.remove(s);
                    System.out.println("a");
                    System.out.println("b");
                    break;
                default:
                    break;
            }
        }
    }

    // I6: the removal is inside a nested `if` inside the `case`, so the
    // `remove(); break;` sequence the exclusion matches is not even adjacent —
    // and the `break` still leaves only the switch.
    void i6(List<String> list, boolean flag) {
        for (String s : list) {
            switch (s) {
                case "x":
                    if (flag) {
                        list.remove(s);
                    }
                    break;
                default:
                    break;
            }
        }
    }
}
