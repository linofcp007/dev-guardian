import java.text.SimpleDateFormat;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;

/**
 * REAL-BUGS CORPUS — written by the REVIEWER, not by the rule author.
 *
 * Every other fixture in hits/ is a minimal instantiation of one rule, written
 * by whoever wrote that rule; it proves the rule fires at all and nothing more.
 * This file and its sibling ElseArm.java exist to answer a different question,
 * the one five waves of false-positive work never asked: does an exclusion
 * added to silence correct code also eat a REAL bug?
 *
 * Nothing here is minimal and nothing here is safe. Each method is a defect a
 * tightening plausibly swallows — the short-form SimpleDateFormat that the
 * fully-qualified pattern has to resolve through the import, the four array
 * shapes the `"$T[]"` type restriction has to keep seeing, the disjunction that
 * proves NOTHING and must survive the disjunction exclusions, the guard on a
 * different key or a different Optional than the one dereferenced.
 *
 * The count is asserted per file in bugfixRulesJava.test.ts. Any future
 * exclusion that drops it has eaten a real bug and must justify itself.
 */
public class RealBugs {

    // B1: the short-form static SimpleDateFormat with a normal single-type
    // import. The rule's only pattern is the fully-qualified name; this pins
    // that Semgrep resolves the short form through the import.
    private static final SimpleDateFormat SHORT = new SimpleDateFormat("yyyy");

    // B2: off-by-one on an array parameter. Must still fire under the
    // `"$T[]"` type restriction.
    int b2(int[] a) {
        int sum = 0;
        for (int i = 0; i <= a.length; i++) {
            sum += a[i];
        }
        return sum;
    }

    // B3: off-by-one on a local array.
    int b3() {
        String[] names = new String[3];
        int n = 0;
        for (int i = 0; i <= names.length; i++) {
            n += names[i].length();
        }
        return n;
    }

    // B4: off-by-one on an array FIELD.
    private final int[] data = new int[4];
    int b4() {
        int sum = 0;
        for (int i = 0; i <= data.length; i++) {
            sum += data[i];
        }
        return sum;
    }

    // B5: off-by-one on a `var`-inferred local array.
    int b5() {
        var xs = new int[2];
        int sum = 0;
        for (int i = 0; i <= xs.length; i++) {
            sum += xs[i];
        }
        return sum;
    }

    // B6: unguarded map deref. Must fire.
    String b6(Map<String, String> m, String k) {
        return m.get(k).trim();
    }

    // B7: unguarded map deref on a `this.` field. Must fire.
    private final HashMap<String, String> cache = new HashMap<>();
    String b7(String k) {
        return this.cache.get(k).trim();
    }

    // B8: a DISJUNCTION that proves nothing — `force` true and the key absent
    // is an NPE. This is the near-miss for the negative-first `||` exclusions
    // added in wave 6: `!containsKey || deref` is guard-proving and excluded,
    // `force || containsKey` is not and must keep firing. The two are
    // structurally distinguishable, and this pins that they stay so.
    String b8(Map<String, String> m, String k, boolean force) {
        if (force || m.containsKey(k)) {
            return m.get(k).trim();
        }
        return "";
    }

    // B9: containsKey on a DIFFERENT key than the one dereferenced. Must fire.
    String b9(Map<String, String> m, String k1, String k2) {
        if (m.containsKey(k1)) {
            return m.get(k2).trim();
        }
        return "";
    }

    // B10: unguarded Optional.get. Must fire.
    String b10(Optional<String> o) {
        return o.get();
    }

    // B11: Optional.ofNullable can be empty — must still fire, and is the
    // near-miss for the `Optional.of` exclusion right next to it.
    String b11(String s) {
        Optional<String> o = Optional.ofNullable(s);
        return o.get();
    }

    // B12: guard on a DIFFERENT Optional than the one dereferenced.
    String b12(Optional<String> a, Optional<String> b) {
        if (a.isPresent()) {
            return b.get();
        }
        return "";
    }

    // B13: iterate ONE map's keys and dereference ANOTHER map with them. The
    // near-miss for the wave-7 `keySet()` exclusion on its map metavariable:
    // the loop proves nothing about `b`, so this is an NPE on the first key
    // `a` has and `b` does not. Drop the `$M` unification from that clause —
    // write it against a fresh metavariable — and this stops firing.
    void b13(Map<String, String> a, Map<String, String> b) {
        for (String k : a.keySet()) {
            System.out.println(b.get(k).trim());
        }
    }

    // B14: iterate the map's own keys and dereference a DIFFERENT key. The
    // near-miss for the same clause on its KEY metavariable: `other` is not
    // the loop variable and nothing proves it is in the map. Drop the `$K`
    // unification and this stops firing.
    void b14(Map<String, String> m, String other) {
        for (String k : m.keySet()) {
            System.out.println(k + "=" + m.get(other).trim());
        }
    }
}
