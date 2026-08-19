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
}
