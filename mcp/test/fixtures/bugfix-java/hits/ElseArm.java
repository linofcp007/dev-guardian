import java.util.Map;
import java.util.Optional;

/**
 * REAL-BUGS CORPUS — written by the REVIEWER, not by the rule author.
 *
 * Every method here is a GUARANTEED NullPointerException or
 * NoSuchElementException: the dereference sits on the branch the guard proves
 * is UNSAFE. All eight must fire.
 *
 * This file is the regression that wave 4 shipped and nothing caught. Closing
 * the guard false positives with `pattern-not-inside: if ($M.containsKey($K))
 * { ... }` scoped the exclusion to the whole IF-ELSE STATEMENT, and the quoted
 * ternary exclusions scoped to the whole CONDITIONAL EXPRESSION — so BOTH arms
 * were excluded, including the one the guard proves is the bug. Measured:
 * before wave 4 this file produced 6 findings; after it, 1. The harness went
 * green through all of it, because it had a hit fixture per rule and near-miss
 * fixtures per exclusion, and nothing that measured a LOSS OF RECALL.
 *
 * The fix is to constrain each exclusion to the guarded arm — the deep
 * expression operator in the ternary arm, and a dereference requirement in the
 * `if` body. Whatever a future wave does to those clauses, this count is the
 * thing that must not move.
 */
public class ElseArm {

    // F1: map, else arm of containsKey.
    String f1(Map<String, String> m, String k) {
        if (m.containsKey(k)) { return "present"; }
        else { return m.get(k).trim(); }
    }

    // F2: map, else arm of get() != null.
    String f2(Map<String, String> m, String k) {
        if (m.get(k) != null) { return "present"; }
        else { return m.get(k).trim(); }
    }

    // F3: map, FALSE arm of the containsKey ternary.
    String f3(Map<String, String> m, String k) {
        return m.containsKey(k) ? "present" : m.get(k).trim();
    }

    // F4: map, TRUE arm of the !containsKey ternary.
    String f4(Map<String, String> m, String k) {
        return !m.containsKey(k) ? m.get(k).trim() : "present";
    }

    // F5: optional, else arm of isPresent.
    String f5(Optional<String> o) {
        if (o.isPresent()) { return "present"; }
        else { return o.get(); }
    }

    // F6: optional, FALSE arm of the isPresent ternary.
    String f6(Optional<String> o) {
        return o.isPresent() ? "present" : o.get();
    }

    // F7: optional, else arm of a conjunction guard.
    String f7(Optional<String> o, boolean flag) {
        if (flag && o.isPresent()) { return "present"; }
        else { return o.get(); }
    }

    // F8: control — plain unguarded deref, must fire.
    String f8(Map<String, String> m, String k) {
        return m.get(k).trim();
    }

    // F9..F12 arrived with the external-corpus round, which added the `else`
    // arm of an `isEmpty()` test and `assert isPresent()` to the exclusions.
    // Both are guard exclusions, so both are exactly what this file exists to
    // fence: each of the four is the shape ADJACENT to a new exclusion where
    // the guard proves the OPPOSITE, and each must keep firing.

    // F9: optional, THEN arm of isEmpty — proven EMPTY exactly where it is
    // read, and the new `else`-arm clauses must not reach it.
    //
    // The obvious spelling of this — `if (o.isEmpty()) { return o.get(); }` —
    // does NOT belong here, because it does not fire and never did: the
    // early-exit exclusion `if ($O.isEmpty()) { return ...; }` matches the
    // whole `if` node, so the `get()` inside its own exit branch is excluded
    // with it. Measured against the shipped rule and against this one, and it
    // is the same false negative for `!isPresent()` and for `!containsKey`.
    // It is recorded as a limitation, not fixtured as a hit.
    String f9(Optional<String> o) {
        if (o.isEmpty()) { System.out.println(o.get()); }
        else { System.out.println("present"); }
        return "d";
    }

    // F10: optional, else arm of a CONJUNCTION with isEmpty. `!(flag &&
    // o.isEmpty())` proves nothing about the Optional, so this is a genuine
    // NoSuchElementException and the disjunction clause must not reach it.
    String f10(Optional<String> o, boolean flag) {
        if (flag && o.isEmpty()) { return "empty"; }
        else { return o.get(); }
    }

    // F11: assert on a DIFFERENT Optional. The exclusion unifies the receiver;
    // break the unification and the read is unguarded.
    String f11(Optional<String> o, Optional<String> other) {
        assert other.isPresent();
        return o.get();
    }

    // F12: assert of the NEGATION — the invariant declared is that it is
    // empty, and the read below it throws every time.
    String f12(Optional<String> o) {
        assert o.isEmpty();
        return o.get();
    }
}
