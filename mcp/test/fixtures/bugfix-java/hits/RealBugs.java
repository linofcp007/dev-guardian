import java.text.SimpleDateFormat;
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
 * shapes the `"$T[]"` type restriction has to keep seeing, the guard on a
 * different Optional than the one dereferenced, the positive-first disjunction
 * that proves NOTHING and must survive the disjunction exclusions.
 *
 * B6-B9, B13, B14, B16, B18 and B20 were the MAP half — nine defects fencing
 * the `keySet()` unifications, the disjunction that proves nothing, the guard
 * on a different key, and the chain clauses on their map side. They went with
 * `null-safety-map-get-deref` when the application-corpus round deleted it, and
 * the count went 20 -> 11 with nothing else moving. What they fenced is NOT
 * unfenced: every clause shape they measured has an Optional twin still in the
 * pack, and B15, B17 and B19 below are those twins.
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

    // ---- near-misses for the wave-8 CHAIN exclusions ----------------------
    //
    // The chain clauses each match `$X && GUARD && DEREF` (or the `||` dual),
    // and `$X` matches the whole left-nested subtree — which is deliberately
    // permissive. These three are the shapes that permissiveness must NOT
    // reach: three ways a chain can look like a guard without being one. Each
    // is a guaranteed throw.

    // B15: the chain guards a DIFFERENT Optional than the one dereferenced.
    // `a` present says nothing about `b`.
    boolean b15(Optional<String> a, Optional<String> b, boolean flag) {
        return flag && a.isPresent() && b.get().isEmpty();
    }

    // B17: a POSITIVE-first disjunction chain, which proves nothing. `||`
    // short-circuits, so the last operand runs only when everything left of it
    // was FALSE — and here that means `isPresent()` was false, so the `get()`
    // is a guaranteed NoSuchElementException. Only the NEGATIVE-first form is
    // a guard, and this is the structural twin that must stay distinguishable
    // from it.
    boolean b17(Optional<String> o, boolean flag) {
        return flag || o.isPresent() || o.get().isEmpty();
    }

    // B19: a conjunction chain whose guard is NEGATED. `&&` short-circuits, so
    // the dereference runs only when `!isPresent()` was TRUE — the Optional is
    // proven EMPTY at exactly the point the value is read. The clause requires
    // the last-but-one operand to be `$O.isPresent()` literally, not its
    // negation, and this measures that every run.
    boolean b19(Optional<String> o, boolean flag) {
        return flag && !o.isPresent() && o.get().isEmpty();
    }
}
