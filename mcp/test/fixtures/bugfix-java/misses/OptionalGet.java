import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * Correct Java: every get() below is provably guarded, or is not an
 * Optional at all.
 *
 * As in the map fixture, the functions are deliberately NOT minimal
 * instantiations of the clause each one pins. The clause list is long enough
 * that a one-to-one ablation table is easy to fake by writing the pattern
 * back out with its metavariables filled in — that table would be perfectly
 * green and would prove nothing about code anybody writes. Each function
 * below carries at least one shape its clause does not mention.
 */
public class OptionalGet {
    // guarded is DISCRIMINATING for the plain `if ($O.isPresent()) { ... }`
    // clause. The body is three statements, not one, and the guarded value is
    // read twice — a clause written against `if (o.isPresent()) return
    // o.get();` alone would not cover this.
    String guarded(Optional<String> o) {
        if (o.isPresent()) {
            String v = o.get();
            System.out.println("present " + v);
            return o.get().trim();
        }
        return "";
    }
    String orElse(Optional<String> o) {
        return o.orElse("");
    }
    String orElseThrowExplicit(Optional<String> o) {
        return o.orElseThrow(() -> new IllegalStateException("missing"));
    }

    // ---- guardas compostas ----------------------------------------------
    //
    // The doc sentence used to claim the rule "recognises guards written
    // inline against the same Optional variable". Measured, it did not: two
    // Optionals checked in one condition fired twice, at the exact spot where
    // both were proven present. These two pin the conjunction clauses.
    //
    // The DISJUNCTION is deliberately not excluded and has no fixture here:
    // `a.isPresent() || b.isPresent()` proves nothing about `a` inside the
    // body, so excluding it would hide a real bug.

    // compoundLeft: the guarded variable is the LEFT operand, both Optionals
    // are dereferenced, and the body is more than a return.
    String compoundLeft(Optional<String> a, Optional<String> b) {
        if (a.isPresent() && b.isPresent()) {
            StringBuilder sb = new StringBuilder(a.get());
            sb.append(b.get());
            return sb.toString();
        }
        return "";
    }

    // compoundRight: the guarded variable is the RIGHT operand, and the other
    // operand is not an Optional test at all.
    String compoundRight(Optional<String> o, boolean enabled) {
        if (enabled && o.isPresent()) {
            return o.get().trim();
        }
        return "";
    }

    // whileGuard is DISCRIMINATING for the `while` clause. A `while` is not
    // an `if`, so none of the `if` clauses reach it; the loop re-tests the
    // condition on every pass, which is exactly what makes the `get()` safe.
    List<String> whileGuard(Optional<String> o, List<String> sink) {
        while (o.isPresent()) {
            sink.add(o.get().trim());
            o = Optional.empty();
        }
        return sink;
    }

    // ---- as formas de EXPRESSÃO ------------------------------------------
    //
    // Added in wave 6. compoundLeft / compoundRight above are both `if (...)
    // { ... }`, and the documentation claimed the rule honoured a conjunction
    // guard full stop. It did not: used as an expression, the same guard fired.
    //
    // The disjunction note above still holds for `a.isPresent() || b` — that
    // proves nothing. What it got WRONG is the negative-first form: `!isPresent
    // || X` is the De Morgan dual of the conjunction already excluded, is
    // exactly as guard-proving, and the two are structurally distinguishable,
    // so excluding one does not reintroduce the other.

    // The braceless twins. Each inline guard needs one: measured by ablation,
    // the braceless half of a clause pair is INERT whenever the only near-miss
    // for that guard shape is a braced one.
    String bracelessGuard(Optional<String> o) {
        if (o.isPresent()) return o.get();
        return "";
    }

    String bracelessCompoundLeft(Optional<String> o, boolean enabled) {
        if (o.isPresent() && enabled) return o.get();
        return "";
    }

    String bracelessCompoundRight(Optional<String> o, boolean enabled) {
        if (enabled && o.isPresent()) return o.get();
        return "";
    }

    // conjunctionExpression: the conjunction is the returned value, not the
    // condition of anything.
    boolean conjunctionExpression(Optional<String> o) {
        return o.isPresent() && o.get().isEmpty();
    }

    // conjunctionAssigned: the same short-circuit assigned to a local, with a
    // chained call on the dereference.
    boolean conjunctionAssigned(Optional<String> o) {
        boolean blank = o.isPresent() && o.get().trim().isEmpty();
        return blank;
    }

    // disjunctionNotPresent: "absent or blank", the commonest Optional guard
    // idiom after `orElse`. `||` short-circuits, so the right operand only
    // evaluates when the left was FALSE — i.e. when the value IS present.
    boolean disjunctionNotPresent(Optional<String> o) {
        return !o.isPresent() || o.get().isEmpty();
    }

    // disjunctionIsEmpty: the Java 11 spelling of the same thing, used as the
    // condition of an `if`.
    void disjunctionIsEmpty(Optional<String> o) {
        if (o.isEmpty() || o.get().trim().isEmpty()) {
            System.out.println("absent or blank");
        }
    }

    // ---- the same three guards as a CHAIN --------------------------------
    //
    // Added in wave 8. The three expression clauses above bind the guard to
    // exactly ONE operand of a two-operand expression, so every one of these
    // fired on correct Java. They are the same guards with something else
    // short-circuiting in front, which is the normal way these read in real
    // code — a feature flag, a null check, a cheap test first.
    //
    // What makes ONE extra clause per guard enough is that `$X` matches the
    // whole LEFT-NESTED SUBTREE, not a single operand: `a && b && c` parses as
    // `(a && b) && c`, so `$X && GUARD && DEREF` matches a chain of any length
    // whose last-but-one operand is the guard. Measured — the four-operand
    // twins below are closed by the same clause as the three-operand ones, and
    // adding a second clause for a longer chain would be inert.

    // chainIsPresent: three operands, one `get()`.
    boolean chainIsPresent(Optional<String> o, boolean flag) {
        return flag && o.isPresent() && o.get().isEmpty();
    }

    // chainIsPresentLonger: FOUR operands, and the dereference is chained, so
    // it is not the clause with its metavariables filled in.
    boolean chainIsPresentLonger(Optional<String> o, boolean flag, boolean other) {
        return flag && other && o.isPresent() && o.get().trim().isEmpty();
    }

    // chainNotPresent: the negative-first disjunction as a chain. `||`
    // short-circuits identically, so the last operand runs only when the whole
    // left side was false — which requires `isPresent()` to be true.
    boolean chainNotPresent(Optional<String> o, boolean flag) {
        return flag || !o.isPresent() || o.get().isEmpty();
    }

    // chainIsEmpty: the Java 11 spelling of the same chain.
    boolean chainIsEmpty(Optional<String> o, boolean flag) {
        return flag || o.isEmpty() || o.get().isEmpty();
    }

    // optionalOfAssigned is DISCRIMINATING for the `Optional.of` clause.
    // `Optional.of` throws on null, so a value that got past it is present
    // and `get()` cannot throw. `Optional.ofNullable` CAN be empty and is not
    // excluded — there is no fixture for it here because it is a HIT, not a
    // near-miss.
    String optionalOfAssigned(String s) {
        Optional<String> o = Optional.of(s.trim());
        System.out.println("built " + o.isPresent());
        return o.get();
    }

    // ---- the receiver is not an Optional at all -------------------------
    //
    // atomic is DISCRIMINATING, and it pins the single clause that makes this
    // rule about `Optional` rather than about the four-letter name `get`:
    // delete the `metavariable-type: {metavariable: $O, type: Optional}` and
    // this fires. Before the fix it DID fire — `$O.get()` matched any
    // zero-argument `get()` on any receiver, and this is what that cost.
    int atomic(AtomicInteger n) {
        return n.get();
    }

    // threadLocal and supplier are DOCUMENTARY, not discriminating, and that
    // is worth saying out loud rather than leaving a reader to assume every
    // near-miss carries the same weight. They are killed by exactly the same
    // mutation as `atomic` — dropping the `metavariable-type` clause — so
    // neither proves anything `atomic` does not already prove. They are here
    // because these three are the zero-argument `get()` receivers that
    // actually turn up in Java code, and the false positive was reported on
    // all three.
    String threadLocal(ThreadLocal<String> t) {
        return t.get();
    }
    String supplier(Supplier<String> s) {
        return s.get();
    }

    // ---- one function per guard shape the rule excludes ------------------
    //
    // Sixteen: four exits (`return`, `throw`, `continue`, `break`) times two
    // conditions (`!isPresent()` and `isEmpty()`) times two body shapes (the
    // exit alone, and one interposed statement before it). Each is
    // DISCRIMINATING for exactly one `pattern-not-inside` clause and for no
    // other: delete that one clause and that one function fires while the
    // other fifteen stay silent.
    //
    // The interposed-statement twins are not padding. The obvious way to
    // write these clauses once instead of twice is `{ ... return ...; }`,
    // and that was measured: the statement ellipsis matches DEEP, so it also
    // swallows `if (!o.isPresent()) { if (strict) { return ""; } }` — a guard
    // that does not cover every path, followed by a `get()` that really can
    // throw. `$S1` matches one statement, not a subtree, so that bug keeps
    // firing.
    String earlyReturnNotPresent(Optional<String> o) {
        if (!o.isPresent()) { return ""; }
        String v = o.get();
        return v.trim();
    }
    String earlyReturnNotPresentLogged(Optional<String> o) {
        if (!o.isPresent()) {
            System.out.println("absent");
            return "";
        }
        return o.get().trim();
    }
    String earlyThrowNotPresent(Optional<String> o) {
        if (!o.isPresent()) { throw new IllegalStateException("missing"); }
        return o.get().toUpperCase();
    }
    String earlyThrowNotPresentLogged(Optional<String> o) {
        if (!o.isPresent()) {
            System.err.println("missing");
            throw new IllegalStateException("missing");
        }
        return o.get();
    }
    void earlyContinueNotPresent(List<Optional<String>> os) {
        for (Optional<String> o : os) {
            if (!o.isPresent()) { continue; }
            System.out.println(o.get().trim());
        }
    }
    void earlyContinueNotPresentLogged(List<Optional<String>> os) {
        for (Optional<String> o : os) {
            if (!o.isPresent()) {
                System.out.println("skipping");
                continue;
            }
            System.out.println(o.get());
        }
    }
    void earlyBreakNotPresent(List<Optional<String>> os) {
        for (Optional<String> o : os) {
            if (!o.isPresent()) { break; }
            System.out.println(o.get());
        }
    }
    void earlyBreakNotPresentLogged(List<Optional<String>> os) {
        for (Optional<String> o : os) {
            if (!o.isPresent()) {
                System.out.println("stopping");
                break;
            }
            System.out.println(o.get().trim());
        }
    }
    String earlyReturnIsEmpty(Optional<String> o) {
        if (o.isEmpty()) { return ""; }
        return o.get().trim();
    }
    String earlyReturnIsEmptyLogged(Optional<String> o) {
        if (o.isEmpty()) {
            System.out.println("empty");
            return "";
        }
        String v = o.get();
        return v;
    }
    String earlyThrowIsEmpty(Optional<String> o) {
        if (o.isEmpty()) { throw new IllegalStateException("missing"); }
        return o.get();
    }
    String earlyThrowIsEmptyLogged(Optional<String> o) {
        if (o.isEmpty()) {
            System.err.println("empty");
            throw new IllegalStateException("missing");
        }
        return o.get().trim();
    }
    void earlyContinueIsEmpty(List<Optional<String>> os) {
        for (Optional<String> o : os) {
            if (o.isEmpty()) { continue; }
            System.out.println(o.get());
        }
    }
    void earlyContinueIsEmptyLogged(List<Optional<String>> os) {
        for (Optional<String> o : os) {
            if (o.isEmpty()) {
                System.out.println("skipping");
                continue;
            }
            System.out.println(o.get().trim());
        }
    }
    void earlyBreakIsEmpty(List<Optional<String>> os) {
        for (Optional<String> o : os) {
            if (o.isEmpty()) { break; }
            System.out.println(o.get());
        }
    }
    void earlyBreakIsEmptyLogged(List<Optional<String>> os) {
        for (Optional<String> o : os) {
            if (o.isEmpty()) {
                System.out.println("stopping");
                break;
            }
            System.out.println(o.get().trim());
        }
    }

    // ---- the same three guards, written as a ternary --------------------
    //
    // All three are DISCRIMINATING, and each for exactly one clause: delete
    // the matching `pattern-not-inside` and that one function fires while the
    // other two stay silent. Same one-to-one mapping as the statement guards
    // above.
    //
    // A ternary is a conditional EXPRESSION, not an `if` statement, so it is a
    // structurally different AST node — none of the clauses above reach it,
    // which is why it needed three of its own. Every one is correct Java: the
    // Optional is proven non-empty on the branch that calls `get()`, and
    // `o.isPresent() ? o.get() : d` is among the commonest ways to write that.
    String ternaryIsPresent(Optional<String> o) {
        return o.isPresent() ? o.get().trim() : "d";
    }
    String ternaryNotPresent(Optional<String> o) {
        return !o.isPresent() ? "d" : o.get();
    }
    String ternaryIsEmpty(Optional<String> o) {
        return o.isEmpty() ? "d" : o.get().toUpperCase();
    }

    // filterIsPresent is DISCRIMINATING for the `filter(...).isPresent()`
    // clause and no other: delete that clause and this fires alone.
    //
    // It is a genuine guard, not a lookalike. `Optional.filter` on an empty
    // Optional returns empty, so a present FILTER RESULT proves the original
    // is present too — `o.get()` cannot throw here. What made the rule miss
    // it is that the existing exclusion binds the receiver to exactly `$O`,
    // and here the receiver of `isPresent()` is `o.filter(p)`, not `o`.
    String filterIsPresent(Optional<String> o) {
        if (o.filter(s -> !s.isEmpty()).isPresent()) { return o.get(); }
        return "d";
    }

    // ---- the `else` arm of an isEmpty() test ----------------------------
    //
    // The four `else`-arm clauses came from the OpenJDK measurement: nine of
    // the rule's 26 findings there were this shape, the largest family it had.
    // Since Java 11 this is how the check is written, and the rule knew only
    // the `isPresent()` dual of it.
    //
    // WHAT THE THEN-ARM IS MATTERS, and the first version of this block got it
    // wrong in a way only ablation showed. Written with an early exit in the
    // then-arm — `if (o.isEmpty()) { return "d"; } else { … o.get() … }` —
    // all four functions were ALREADY silent, under the pre-existing
    // `if ($O.isEmpty()) { return ...; }` early-exit clause, and every one of
    // the four new clauses read DEAD. Those four fixtures are kept below as
    // DOCUMENTARY, because they record which clause actually covers the
    // commonest spelling; the four DISCRIMINATING ones are here, with a
    // then-arm that is not an exit, which is also what the nine OpenJDK
    // findings looked like (a nested `if`, an assignment, a log call).
    //
    // One clause each, measured by removing them one at a time:
    //   * discriminatingBlock   -> `{ ... $O.get(); ... }`
    //   * discriminatingBraceless -> `{ <... $O.get() ...>; }`
    //   * discriminatingDisjunctionBlock / …Braceless -> the `|| ...` pair
    // Remove one and exactly one of them fires. Without a multi-statement
    // `else` the first of each pair reads DEAD, because the second covers a
    // single-statement block on its own.
    //
    // The conjunction — `if (flag && o.isEmpty())` — is deliberately NOT here:
    // it proves nothing about the Optional in the `else`, it is pinned as a
    // real bug in hits/ElseArm.java, and if it ever stops firing that is the
    // file that says so.
    String discriminatingBlock(Optional<String> o) {
        String out = "d";
        if (o.isEmpty()) { System.out.println("absent"); }
        else { System.out.println("present"); out = o.get().trim(); }
        return out;
    }
    String discriminatingBraceless(Optional<String> o) {
        String out = "d";
        if (o.isEmpty()) { System.out.println("absent"); }
        else out = o.get().trim();
        return out;
    }
    String discriminatingDisjunctionBlock(Optional<String> o, boolean force) {
        String out = "d";
        if (o.isEmpty() || force) { System.out.println("absent"); }
        else { System.out.println("present"); out = o.get().trim(); }
        return out;
    }
    String discriminatingDisjunctionBraceless(Optional<String> o, boolean force) {
        String out = "d";
        if (o.isEmpty() || force) { System.out.println("absent"); }
        else out = o.get().trim();
        return out;
    }

    // DOCUMENTARY, and it is worth saying which clause each one really needs.
    // All four have an early exit in the then-arm, so the early-exit clause
    // matches the whole `if` and silences them before any `else`-arm clause is
    // consulted. They prove that the commonest spelling is covered; they prove
    // nothing about the clauses added for it.
    String elseArmIsEmpty(Optional<String> o) {
        if (o.isEmpty()) {
            System.out.println("absent");
            return "d";
        } else {
            System.out.println("present");
            return o.get().trim();
        }
    }
    String elseArmBraceless(Optional<String> o) {
        if (o.isEmpty()) { return "d"; } else return o.get();
    }
    String elseArmDisjunction(Optional<String> o, boolean force) {
        if (o.isEmpty() || force) { return "d"; } else { return o.get().trim(); }
    }
    String elseIfChain(Optional<String> o, boolean fast) {
        if (fast) { return "f"; }
        else if (o.isEmpty()) { return "d"; }
        else { return o.get().toUpperCase(); }
    }

    // ---- `assert isPresent()` ------------------------------------------
    //
    // ONE clause, not two, and that was measured rather than assumed. `assert
    // C;` and `assert C : msg;` are different AST nodes, so the obvious
    // reading is that each needs a pattern — but `: ...` matches the ABSENT
    // message, so the form WITH a message covers both. The pair was written,
    // ablated, and the message-less half came back INERT; it was deleted.
    // assertIsPresent is therefore DOCUMENTARY and assertIsPresentWithMessage
    // is DISCRIMINATING: remove the clause and both fire.
    //
    // This is the OpenJDK's own way of writing down an invariant it has
    // already established elsewhere — six of the 26 findings there were
    // exactly this — and unlike a comment it is in the tree for the rule to
    // read. It is an intention, not a runtime guard: assertions are off by
    // default. The counterparts that must still fire — an assert on a
    // DIFFERENT Optional, and `assert o.isEmpty()` — are pinned in
    // hits/ElseArm.java.
    String assertIsPresent(Optional<String> o) {
        assert o.isPresent();
        return o.get().trim();
    }
    String assertIsPresentWithMessage(Optional<String> o) {
        assert o.isPresent() : "resolved above";
        return o.get().trim();
    }
}
