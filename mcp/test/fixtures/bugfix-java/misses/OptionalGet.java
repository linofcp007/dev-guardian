import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

public class OptionalGet {
    String guarded(Optional<String> o) {
        if (o.isPresent()) { return o.get(); }
        return "";
    }
    String orElse(Optional<String> o) {
        return o.orElse("");
    }
    String orElseThrowExplicit(Optional<String> o) {
        return o.orElseThrow(() -> new IllegalStateException("missing"));
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
    // Each of the eight below is DISCRIMINATING for exactly one
    // `pattern-not-inside` clause, and for no other: delete that one clause
    // and that one function fires, while the other seven stay silent. That
    // one-to-one mapping is the point — it is what lets the ablation pass
    // report a per-clause verdict instead of a verdict on the set. Every one
    // of these is correct Java: the Optional is proven non-empty on the path
    // that reaches `get()`.
    String earlyReturnNotPresent(Optional<String> o) {
        if (!o.isPresent()) { return ""; }
        return o.get();
    }
    String earlyThrowNotPresent(Optional<String> o) {
        if (!o.isPresent()) { throw new IllegalStateException("missing"); }
        return o.get();
    }
    void earlyContinueNotPresent(List<Optional<String>> os) {
        for (Optional<String> o : os) {
            if (!o.isPresent()) { continue; }
            System.out.println(o.get());
        }
    }
    void earlyBreakNotPresent(List<Optional<String>> os) {
        for (Optional<String> o : os) {
            if (!o.isPresent()) { break; }
            System.out.println(o.get());
        }
    }
    String earlyReturnIsEmpty(Optional<String> o) {
        if (o.isEmpty()) { return ""; }
        return o.get();
    }
    String earlyThrowIsEmpty(Optional<String> o) {
        if (o.isEmpty()) { throw new IllegalStateException("missing"); }
        return o.get();
    }
    void earlyContinueIsEmpty(List<Optional<String>> os) {
        for (Optional<String> o : os) {
            if (o.isEmpty()) { continue; }
            System.out.println(o.get());
        }
    }
    void earlyBreakIsEmpty(List<Optional<String>> os) {
        for (Optional<String> o : os) {
            if (o.isEmpty()) { break; }
            System.out.println(o.get());
        }
    }

    // ---- the same three guards, written as a ternary --------------------
    //
    // All three are DISCRIMINATING, and each for exactly one clause: delete
    // the matching `pattern-not-inside` and that one function fires while the
    // other two stay silent. Same one-to-one mapping as the eight statement
    // guards above.
    //
    // A ternary is a conditional EXPRESSION, not an `if` statement, so it is a
    // structurally different AST node — none of the eight clauses above reach
    // it, which is why it needed three of its own. Every one is correct Java:
    // the Optional is proven non-empty on the branch that calls `get()`, and
    // `o.isPresent() ? o.get() : d` is among the commonest ways to write that.
    String ternaryIsPresent(Optional<String> o) {
        return o.isPresent() ? o.get() : "d";
    }
    String ternaryNotPresent(Optional<String> o) {
        return !o.isPresent() ? "d" : o.get();
    }
    String ternaryIsEmpty(Optional<String> o) {
        return o.isEmpty() ? "d" : o.get();
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
}
