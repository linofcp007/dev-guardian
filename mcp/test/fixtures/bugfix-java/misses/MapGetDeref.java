import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Correct Java. Every method here is safe and none may be flagged.
 *
 * The functions below are deliberately NOT minimal instantiations of the
 * clause each one pins. A near-miss that is the exclusion pattern with its
 * metavariables filled in proves only that the pattern matches itself; it
 * says nothing about whether the clause survives contact with real code. So
 * each carries at least one shape the clause does not mention — an extra
 * statement, a loop, a chained call, a second dereference, a receiver of a
 * different declared type, an interposed log line.
 */
public class MapGetDeref {
    // checked is DISCRIMINATING: mutate the shipped rule to `$M.get($K)` —
    // dropping the `.$METHOD(...)` deref requirement — and this fires,
    // because the bare `m.get("k")` call is still there, just assigned to a
    // local and null-checked before use. Proven by mutation, not assumed.
    int checked(Map<String, Integer> m) {
        Integer v = m.get("k");
        if (v == null) { return 0; }
        return v.intValue();
    }

    // withDefault is DOCUMENTARY, not discriminating, and that is worth
    // saying out loud rather than leaving a reader to assume every near-miss
    // carries the same weight. `getOrDefault` is a different identifier from
    // `get` — Semgrep's Java matcher requires the literal method name, so no
    // mutation of this pattern (dropping the deref, widening `$K`, anything
    // short of matching a different method name) could ever make this fire.
    // It records that the safe idiom is safe; it proves nothing about the
    // rule.
    int withDefault(Map<String, Integer> m) {
        return m.getOrDefault("k", 0).intValue();
    }

    // justGet is a second DISCRIMINATING near-miss, and it catches a mutation
    // `checked` does not: dropping the deref requirement to `$M.get($K)`
    // makes this fire too, on the bare `return m.get("k");`. What keeps it
    // silent under the SHIPPED rule is the `.$METHOD(...)` requirement — a
    // possibly-null value simply returned to the caller, with no method
    // called on it here, is correct Java and is the caller's business, not
    // this rule's.
    Integer justGet(Map<String, Integer> m) {
        return m.get("k");
    }

    // listGet is DISCRIMINATING for the receiver-type restriction, and it is
    // the reason that restriction exists. `List.get(int)` is a
    // one-argument `get` chained with a method call, so it matched
    // `$M.get($K).$METHOD(...)` exactly. Before the fix this fired at ERROR
    // on entirely correct code and advised `getOrDefault` — a method `List`
    // does not have. Delete every `metavariable-type` branch from the map
    // rule and this fires again.
    String listGet(List<String> xs) {
        return xs.get(0).trim();
    }

    // ---- guarda inline ---------------------------------------------------
    //
    // Each of the six below pins exactly one inline-guard clause. The rule
    // shipped with NO guard exclusion at all, so `if (m.containsKey(k))` —
    // the textbook Java guard — fired at ERROR and advised `getOrDefault` on
    // already-guarded code.

    // inlineContainsKey: not a bare `return m.get(k).trim();` inside the if.
    // The guarded body is four statements long and the dereference happens
    // inside a builder call, which is where a clause written against the
    // one-liner would come apart.
    String inlineContainsKey(Map<String, String> m, String k) {
        if (m.containsKey(k)) {
            System.out.println("hit " + k);
            StringBuilder sb = new StringBuilder("v=");
            sb.append(m.get(k).trim());
            return sb.toString();
        }
        return "";
    }

    // compoundContainsKeyLeft: the guard is a CONJUNCTION whose second
    // operand dereferences the same key, and the body is a loop that
    // dereferences it again. Two derefs, both under one guard.
    int compoundContainsKeyLeft(Map<String, Integer> m, String k) {
        int total = 0;
        if (m.containsKey(k) && !m.get(k).equals(0)) {
            for (int i = 0; i < 3; i++) { total += m.get(k).intValue(); }
        }
        return total;
    }

    // compoundContainsKeyRight: the same conjunction with the operands the
    // other way round, on a TreeMap receiver rather than a Map, so it also
    // walks a different `pattern-either` branch than its twin above.
    int compoundContainsKeyRight(TreeMap<String, Integer> m, String k, boolean enabled) {
        if (enabled && m.containsKey(k)) {
            int v = m.get(k).intValue();
            return v * 2;
        }
        return -1;
    }

    // inlineNotNull: the `!= null` guard, on a LinkedHashMap, with the value
    // read twice — once into a local that is printed, once dereferenced.
    String inlineNotNull(LinkedHashMap<String, String> m, String k) {
        if (m.get(k) != null) {
            String raw = m.get(k);
            System.out.println(raw);
            return m.get(k).trim();
        }
        return "";
    }

    // compoundNotNullLeft: `!= null` first, and the second operand of the
    // conjunction is itself a dereference — the guard covers it too. The body
    // dereferences again from inside a LOOP, which is what makes this one
    // discriminating for the multi-statement half of the clause pair rather
    // than for the braceless half.
    int compoundNotNullLeft(Map<String, String> m, String k) {
        int total = 0;
        if (m.get(k) != null && !m.get(k).isEmpty()) {
            for (int i = 0; i < 2; i++) { total += m.get(k).length(); }
        }
        return total;
    }

    // compoundNotNullRight: `!= null` second, on a ConcurrentHashMap, with the
    // value read into a local and logged before the dereference.
    int compoundNotNullRight(ConcurrentHashMap<String, String> m, String k, boolean on) {
        if (on && m.get(k) != null) {
            String raw = m.get(k);
            System.out.println(raw);
            return m.get(k).length();
        }
        return 0;
    }

    // ---- ternário --------------------------------------------------------
    //
    // A ternary is a conditional EXPRESSION, a different AST node from an
    // `if`, so none of the statement clauses above reach it and it needs its
    // own. All four polarities are written the way they actually appear.

    // ternaryContainsKey: the true branch CHAINS a second call onto the
    // dereference, which a clause matched against `cond ? m.get(k).trim() :
    // d` would not survive.
    String ternaryContainsKey(HashMap<String, String> m, String k) {
        return m.containsKey(k) ? m.get(k).trim().toUpperCase() : "none";
    }

    // ternaryNotContainsKey: the negated form, where the dereference is in
    // the FALSE branch.
    String ternaryNotContainsKey(Map<String, String> m, String k) {
        return !m.containsKey(k) ? "none" : m.get(k).trim();
    }

    // ternaryNotNull: arithmetic on the dereferenced value rather than a bare
    // return of it.
    int ternaryNotNull(Map<String, Integer> m, String k) {
        return m.get(k) != null ? m.get(k).intValue() + 1 : 0;
    }

    // ternaryNull: the commonest of the four in real code, and the mirror of
    // ternaryNotNull — the dereference sits in the false branch.
    String ternaryNull(Map<String, String> m, String k) {
        return m.get(k) == null ? "" : m.get(k).trim();
    }

    // ---- guarda sem chavetas, ciclo, e as formas de EXPRESSÃO -------------
    //
    // Added in wave 6. The six inline clauses above all read `if (...) { ...
    // }`, and the documentation claimed the rule honoured a conjunction guard
    // full stop. It did not: a conjunction used as an EXPRESSION — returned,
    // assigned to a local — was never excluded, and every function in this
    // section fired on correct Java until the expression-form clauses went in.

    // bracelessContainsKey: the guard body has no braces. It is its own clause
    // because the arm-scoping added in wave 6 split the old `if (...) { ... }`
    // exclusion in two, and only the single-statement half reaches this shape.
    // Chains a call onto the dereference so it is not the clause with its
    // metavariables filled in.
    // Each of the six inline guards needs its OWN braceless twin: measured by
    // ablation, the braceless half of a clause pair is INERT whenever the only
    // near-miss for that guard shape is a braced one, because the
    // multi-statement half covers a braced single-statement body too. An inert
    // clause is one that could be deleted without a test moving, which is the
    // defect class this repo keeps finding by ablation and not by review.
    String bracelessContainsKey(Map<String, String> m, String k) {
        if (m.containsKey(k)) return m.get(k).trim().toLowerCase();
        return "";
    }

    int bracelessContainsKeyLeft(Map<String, Integer> m, String k) {
        if (m.containsKey(k) && k.length() > 0) return m.get(k).intValue();
        return 0;
    }

    int bracelessContainsKeyRight(TreeMap<String, Integer> m, String k, boolean on) {
        if (on && m.containsKey(k)) return m.get(k).intValue();
        return 0;
    }

    String bracelessNotNull(LinkedHashMap<String, String> m, String k) {
        if (m.get(k) != null) return m.get(k).trim();
        return "";
    }

    int bracelessNotNullLeft(Map<String, String> m, String k) {
        if (m.get(k) != null && k.length() > 0) return m.get(k).length();
        return 0;
    }

    int bracelessNotNullRight(ConcurrentHashMap<String, String> m, String k, boolean on) {
        if (on && m.get(k) != null) return m.get(k).length();
        return 0;
    }

    // whileContainsKey: the drain loop. The Optional rule had excluded
    // `while ($O.isPresent())` since wave 1 and the map rule had no
    // counterpart, so this exact loop — correct, because the body only runs
    // while the key is in — was flagged.
    void whileContainsKey(Map<String, String> m, String k) {
        while (m.containsKey(k)) {
            System.out.println(m.get(k).trim());
            m.remove(k);
        }
    }

    // conjunctionExpression: the conjunction is not the condition of anything
    // — it is the returned value. `&&` short-circuits, so the dereference on
    // the right only evaluates when the left proved the key present.
    boolean conjunctionExpression(Map<String, String> m, String k) {
        return m.containsKey(k) && m.get(k).isEmpty();
    }

    // conjunctionAssigned: the same short-circuit assigned to a local, on a
    // `this.`-qualified field receiver, so it also walks the qualified-receiver
    // branch rather than the bare-name one.
    private final HashMap<String, String> byKind = new HashMap<>();

    boolean conjunctionAssigned(String k) {
        boolean blank = this.byKind.containsKey(k) && this.byKind.get(k).isEmpty();
        return blank;
    }

    // conjunctionNotNull: the null-check spelling of the same idiom.
    boolean conjunctionNotNull(Map<String, String> m, String k) {
        return m.get(k) != null && m.get(k).isEmpty();
    }

    // disjunctionNullFirst: the De Morgan dual of conjunctionNotNull, and the
    // commonest null-guard idiom in Java — "absent or blank". `||`
    // short-circuits too, so the right operand only evaluates when the left
    // was FALSE, which is exactly when the key is present.
    boolean disjunctionNullFirst(Map<String, String> m, String k) {
        return m.get(k) == null || m.get(k).isEmpty();
    }

    // ---- as mesmas guardas em CADEIA -------------------------------------
    //
    // Added in wave 8. The expression clauses above bind the guard to exactly
    // ONE operand of a two-operand expression, so all four of these fired on
    // correct Java. They are the same guards with something else
    // short-circuiting in front — a feature flag, a cheap test — which is how
    // they usually read in real code.
    //
    // ONE extra clause per guard is enough because `$X` matches the whole
    // LEFT-NESTED SUBTREE rather than a single operand: `a && b && c` parses as
    // `(a && b) && c`, so `$X && GUARD && DEREF` matches a chain of ANY length
    // whose last-but-one operand is the guard. `chainContainsKeyLonger` is the
    // four-operand proof of that, and it is closed by the same clause as its
    // three-operand sibling — a second clause for longer chains would be inert.
    //
    // Their near-misses are `b15`-`b20` in hits/RealBugs.java: a chain guarding
    // a different key, a positive-first disjunction that proves nothing, and a
    // NEGATED guard whose dereference is a guaranteed NPE. All must keep firing.

    // chainContainsKey: three operands, one dereference.
    boolean chainContainsKey(Map<String, String> m, String k, boolean flag) {
        return flag && m.containsKey(k) && m.get(k).isEmpty();
    }

    // chainContainsKeyLonger: FOUR operands, on a TreeMap, with a chained call
    // on the dereference, so it is not the clause with its metavariables
    // filled in.
    boolean chainContainsKeyLonger(TreeMap<String, String> m, String k, boolean flag, boolean on) {
        return flag && on && m.containsKey(k) && m.get(k).trim().isEmpty();
    }

    // chainNotNull: the null-check spelling of the same chain.
    boolean chainNotNull(Map<String, String> m, String k, boolean flag) {
        return flag && m.get(k) != null && m.get(k).isEmpty();
    }

    // chainDisjunctionNotContainsKey: the negative-first disjunction as a
    // chain. `||` short-circuits identically, so the last operand runs only
    // when the whole left side was false — which requires the key to be there.
    boolean chainDisjunctionNotContainsKey(Map<String, String> m, String k, boolean flag) {
        return flag || !m.containsKey(k) || m.get(k).isEmpty();
    }

    // chainDisjunctionNull: the `get() == null` spelling of the same chain.
    boolean chainDisjunctionNull(Map<String, String> m, String k, boolean flag) {
        return flag || m.get(k) == null || m.get(k).isEmpty();
    }

    // disjunctionNotContainsKey: the same shape with `!containsKey`, used as
    // the condition of an `if`, with a chained call on the dereference.
    //
    // Its near-miss is `b8` in hits/RealBugs.java — `force || containsKey`,
    // where the disjunction proves NOTHING and the dereference is a real NPE.
    // The two are structurally distinguishable and both are measured.
    void disjunctionNotContainsKey(Map<String, String> m, String k) {
        if (!m.containsKey(k) || m.get(k).trim().isEmpty()) {
            System.out.println("absent or blank");
        }
    }

    // ---- saída antecipada sobre !containsKey -----------------------------
    //
    // Six clauses, three exits times two body shapes: the guard body is
    // either the exit alone or one interposed statement and then the exit.
    // The interposed-statement twins exist because the unbounded `{ ...
    // return ...; }` form would also swallow a guard whose exit is CONDITIONAL
    // — a guard that does not cover every path — and that is a real bug.

    // exitReturnContainsKey: the dereference is four statements after the
    // guard, not the next one, and it is nested inside an argument.
    String exitReturnContainsKey(Map<String, String> m, String k) {
        if (!m.containsKey(k)) { return ""; }
        StringBuilder sb = new StringBuilder();
        sb.append("v=");
        sb.append(m.get(k).trim());
        return sb.toString();
    }

    // exitReturnContainsKeyLogged: one statement before the return, and the
    // dereference is chained.
    String exitReturnContainsKeyLogged(Map<String, String> m, String k) {
        if (!m.containsKey(k)) {
            System.out.println("miss " + k);
            return "";
        }
        return m.get(k).trim().toLowerCase();
    }

    // exitThrowContainsKey: throws instead of returning, on a HashMap.
    String exitThrowContainsKey(HashMap<String, String> m, String k) {
        if (!m.containsKey(k)) { throw new IllegalArgumentException(k); }
        return m.get(k).trim();
    }

    // exitThrowContainsKeyLogged: a log line before the throw.
    String exitThrowContainsKeyLogged(Map<String, String> m, String k) {
        if (!m.containsKey(k)) {
            System.err.println("missing " + k);
            throw new IllegalArgumentException(k);
        }
        return m.get(k).trim();
    }

    // exitContinueContainsKey: the guard is inside a loop and the exit is a
    // `continue`, so the dereference below runs only for present keys.
    int exitContinueContainsKey(Map<String, Integer> m, List<String> keys) {
        int total = 0;
        for (String k : keys) {
            if (!m.containsKey(k)) { continue; }
            total += m.get(k).intValue();
        }
        return total;
    }

    // exitContinueContainsKeyLogged: same, with a log line before the
    // `continue` and a second dereference after it.
    int exitContinueContainsKeyLogged(Map<String, Integer> m, List<String> keys) {
        int total = 0;
        for (String k : keys) {
            if (!m.containsKey(k)) {
                System.out.println("skip " + k);
                continue;
            }
            total += m.get(k).intValue() * m.get(k).intValue();
        }
        return total;
    }

    // ---- saída antecipada sobre get() == null ----------------------------
    //
    // The same six, written against the null of the value rather than the
    // absence of the key. They are not interchangeable: `containsKey` is
    // false for an absent key, while `get() == null` is also true for a key
    // mapped to null, and the two conditions are different AST shapes.

    // exitReturnNull: the guard's exit returns a computed value, not a
    // literal, and the dereference below is chained.
    String exitReturnNull(Map<String, String> m, String k) {
        if (m.get(k) == null) { return k.trim(); }
        return m.get(k).trim().intern();
    }

    // exitReturnNullLogged: one statement before the return.
    String exitReturnNullLogged(TreeMap<String, String> m, String k) {
        if (m.get(k) == null) {
            System.out.println("absent " + k);
            return "";
        }
        return m.get(k).trim();
    }

    // exitThrowNull: throws, and the dereference is two statements later.
    int exitThrowNull(Map<String, Integer> m, String k) {
        if (m.get(k) == null) { throw new IllegalStateException(k); }
        int base = 10;
        return base + m.get(k).intValue();
    }

    // exitThrowNullLogged: a log line before the throw, on a
    // ConcurrentHashMap.
    int exitThrowNullLogged(ConcurrentHashMap<String, Integer> m, String k) {
        if (m.get(k) == null) {
            System.err.println("absent " + k);
            throw new IllegalStateException(k);
        }
        return m.get(k).intValue();
    }

    // exitContinueNull: `continue` inside a loop, with the dereference
    // feeding a collection.
    List<String> exitContinueNull(Map<String, String> m, List<String> keys) {
        List<String> out = new ArrayList<>();
        for (String k : keys) {
            if (m.get(k) == null) { continue; }
            out.add(m.get(k).trim());
        }
        return out;
    }

    // exitContinueNullLogged: a log line before the `continue`.
    List<String> exitContinueNullLogged(LinkedHashMap<String, String> m, List<String> keys) {
        List<String> out = new ArrayList<>();
        for (String k : keys) {
            if (m.get(k) == null) {
                System.out.println("absent " + k);
                continue;
            }
            out.add(m.get(k).trim());
        }
        return out;
    }

    // ---- população que garante a chave -----------------------------------

    // populatePutIfAbsent: the write and the read are not adjacent — a log
    // line sits between them — and the value is dereferenced twice.
    String populatePutIfAbsent(HashMap<String, String> m, String k) {
        m.putIfAbsent(k, "default");
        System.out.println("ensured " + k + " len " + m.get(k).length());
        return m.get(k).trim();
    }

    // populateComputeIfAbsent: the mapping function builds the value, and the
    // first dereference MUTATES it before the second reads it back.
    int populateComputeIfAbsent(Map<String, List<String>> m, String k) {
        m.computeIfAbsent(k, x -> new ArrayList<>());
        m.get(k).add("v");
        return m.get(k).size();
    }

    // populatePut: a plain `put` of the same key, three statements above the
    // read. This is the shape the docs used to list as an accepted false
    // positive — "a map populated immediately above the read is still
    // flagged" — and it is not immediately above the read here on purpose.
    String populatePut(Map<String, String> m, String k, String v) {
        m.put(k, v);
        System.out.println("stored " + k);
        int len = m.get(k).length();
        return m.get(k).trim() + len;
    }

    // populateOnMiss: populate-on-miss, which is NOT an early exit — the
    // guarded branch writes the key instead of leaving, so control falls
    // through to the dereference either way, and either way the key is
    // there. None of the exit clauses reach this shape.
    String populateOnMiss(TreeMap<String, String> m, String k) {
        if (!m.containsKey(k)) { m.put(k, "default"); }
        return m.get(k).trim();
    }

    // ---- receptor `this.`-qualificado -------------------------------------
    //
    // thisQualifiedGuarded is DISCRIMINATING for the interaction between the
    // new `this.$F` receiver form and the guard clauses, and it is the one
    // that could regress silently: making the rule SEE `this.cache.get(k)`
    // is only half the job, because a guard written `this.cache.containsKey(k)`
    // has to bind the same receiver. It does — `$M` binds the whole qualified
    // expression, so every exclusion above applies unchanged — and this
    // function is the proof.
    private final Map<String, String> cache = new HashMap<>();

    String thisQualifiedGuarded(String k) {
        if (this.cache.containsKey(k)) {
            return this.cache.get(k).trim();
        }
        return "";
    }
    // ---- iteração sobre o próprio keySet ---------------------------------
    //
    // Added in wave 7. The loop header binds the key FROM THE MAP ITSELF, so
    // presence is guaranteed on every syntactic path that reaches the
    // dereference — the same standard by which `containsKey` is accepted as a
    // guard. It is the commonest map-iteration idiom in Java and all three
    // shapes below fired on correct code until the `keySet()` clause went in.
    //
    // The clause unifies BOTH metavariables: the map iterated has to be the
    // map dereferenced, and the loop variable has to be the key passed to
    // `get`. Its near-misses are `b13` and `b14` in hits/RealBugs.java, which
    // break each unification in turn and must keep firing.

    // keySetIteration: the body is four statements long and the dereference
    // sits inside a builder call, so it is not the clause with its
    // metavariables filled in.
    String keySetIteration(Map<String, String> m) {
        StringBuilder sb = new StringBuilder();
        for (String k : m.keySet()) {
            sb.append(k);
            sb.append('=');
            sb.append(m.get(k).trim());
        }
        return sb.toString();
    }

    // keySetIterationBraceless: no braces on the loop body, on a TreeMap
    // receiver, with a chained call on the dereference. Measured: the braced
    // form of the clause — `for (...) { ... }` — does NOT reach this, which is
    // why the shipped clause writes the body as a bare statement ellipsis
    // instead. Delete this function and the clause could be narrowed back to
    // the braced form without a test moving.
    void keySetIterationBraceless(TreeMap<String, String> m) {
        for (String k : m.keySet()) System.out.println(m.get(k).trim().toLowerCase());
    }

    // keySetThisQualified: the receiver is `this.`-qualified on BOTH ends —
    // the loop header and the dereference — and the dereference is nested one
    // level deeper, inside an `if`. The qualified form is the one that could
    // regress silently: `$M` has to bind the whole qualified expression in the
    // exclusion exactly as it does in the positive pattern.
    //
    // THIS WHOLE SECTION SITS AT THE BOTTOM OF THE CLASS ON PURPOSE, AND
    // MOVING IT UP BREAKS IT SILENTLY. Measured in wave 7: `metavariable-type`
    // resolves a `this.`-qualified field only when the field's DECLARATION
    // PRECEDES the method in source order. Written above the `cache`
    // declaration, this function is silent under the rule as it stood BEFORE
    // the `keySet()` clause existed — so it would have been added, gone green,
    // and pinned nothing. A fixture that cannot fail is the same defect class
    // as a dead clause, moved from the rules into the fixtures, and only a RED
    // measurement taken per FUNCTION rather than per file catches it. Any
    // near-miss added here that reads a `this.`-qualified field belongs below
    // that field's declaration.
    void keySetThisQualified(boolean verbose) {
        for (String k : this.cache.keySet()) {
            if (verbose) {
                System.out.println(this.cache.get(k).trim());
            }
        }
    }
}
