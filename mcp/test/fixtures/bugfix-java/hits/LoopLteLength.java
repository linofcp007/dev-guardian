public class LoopLteLength {
    int sumPastEnd(int[] xs) {
        int s = 0;
        for (int i = 0; i <= xs.length; i++) { s += xs[i]; }
        return s;
    }

    // The four below are the forms the rule was BLIND to until the
    // external-corpus round, and each is discriminating for one half of the
    // widening. The header used to spell the increment `$I++` and the body
    // `{ ... }`, and optional syntax written out in a pattern acts as a
    // FILTER: `++i`, `i += 1` and a braceless body all went unmatched. It is
    // the same defect the C# pack found (`i++` matched, `++i` did not), and
    // the same class as a `foreach` pattern there that found 0 of 5 real bugs.
    //
    //   * preIncrement and plusEquals need the increment to be `...`;
    //   * braceless needs the body to be a statement ellipsis rather than a
    //     block — measured, `{ ... }` does not reach it;
    //   * varIndex needs the second branch: `int` is literal in the pattern,
    //     so `for (var i = 0; ...)` had no branch at all.
    //
    // Every one is an ArrayIndexOutOfBoundsException on the last iteration.
    int preIncrement(int[] xs) {
        int s = 0;
        for (int i = 0; i <= xs.length; ++i) { s += xs[i]; }
        return s;
    }

    int plusEquals(int[] xs) {
        int s = 0;
        for (int i = 0; i <= xs.length; i += 1) { s += xs[i]; }
        return s;
    }

    int braceless(int[] xs) {
        int s = 0;
        for (int i = 0; i <= xs.length; i++) s += xs[i];
        return s;
    }

    int varIndex(int[] xs) {
        int s = 0;
        for (var i = 0; i <= xs.length; i++) { s += xs[i]; }
        return s;
    }
}
