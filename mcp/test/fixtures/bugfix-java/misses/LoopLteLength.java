public class LoopLteLength {
    // inBounds is the DISCRIMINATING near-miss: flip the shipped rule's `<=`
    // to `<` — the easiest typo to make in it — and this function fires.
    // Proven by mutation during review, not assumed.
    int inBounds(int[] xs) {
        int s = 0;
        for (int i = 0; i < xs.length; i++) { s += xs[i]; }
        return s;
    }

    // toLenMinusOne is a second DISCRIMINATING near-miss, and it catches a
    // mutation inBounds cannot:
    //
    //   - widen the bound to `$I <= $BOUND` (any expression, not just
    //     `$A.length`) -> this function fires, inBounds does not
    //   - flip the operator to `$I < $A.length` -> inBounds fires, this
    //     function does not
    //
    // So the two cover different halves of the pattern, and neither is
    // redundant. The loop itself is correct: `i <= xs.length - 1`
    // deliberately stops one short.
    int toLenMinusOne(int[] xs) {
        int s = 0;
        for (int i = 0; i <= xs.length - 1; i++) { s += xs[i]; }
        return s;
    }

    // enhanced is DOCUMENTARY, not discriminating, and that is worth saying
    // out loud rather than leaving a reader to assume every near-miss
    // carries the same weight. A for-each loop has no `int $I = 0; $I <=
    // $A.length; $I++` header at all — it is a structurally different AST
    // shape from the C-style for the rule matches, so no mutation of the
    // pattern — the operator, the index, or the length expression — could
    // ever make it fire. It records that rewriting the loop as a for-each is
    // the safe fix; it proves nothing about the rule.
    int enhanced(int[] xs) {
        int s = 0;
        for (int x : xs) { s += x; }
        return s;
    }

    // domainLength is DISCRIMINATING for the `metavariable-type: "$T[]"`
    // clause and for nothing else: delete that clause and this fires alone,
    // at ERROR, on a loop that has no array in it. `$A.length` matches any
    // field named `length`, and a domain object with an int field of that
    // name is ordinary Java — here the loop is inclusive ON PURPOSE, because
    // it is counting fence posts along a segment and not indexing anything.
    //
    // The type restriction costs no recall: measured, a parameter, a local, a
    // field, a `this.`-qualified field and a `var`-inferred local that are
    // arrays are all still matched.
    static class Segment { int length; }

    int domainLength(Segment seg) {
        int total = 0;
        for (int i = 0; i <= seg.length; i++) { total += i; }
        return total;
    }
}
