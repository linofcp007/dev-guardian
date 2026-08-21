import java.text.SimpleDateFormat;
import java.util.Date;

public class StaticDateFormat {
    private final SimpleDateFormat perInstance = new SimpleDateFormat("yyyy");

    String localInstance() {
        SimpleDateFormat local = new SimpleDateFormat("yyyy");
        return local.format(new Date());
    }

    String useInstanceField() {
        return perInstance.format(new Date());
    }

    // THREAD_SAFE is DOCUMENTARY, not discriminating: it's a
    // `DateTimeFormatter`, a different class from `SimpleDateFormat`, so no
    // mutation of the shipped pattern — which matches on the literal
    // `SimpleDateFormat` identifier — could ever make it fire. It records
    // that the suggested fix is itself safe; it proves nothing about the
    // rule.
    static final java.time.format.DateTimeFormatter THREAD_SAFE =
        java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd");

    // The three below are the near-misses of the branch that matches a
    // declaration WITHOUT an initializer — the branch that has no `new` in it
    // and therefore the widest reach in the rule. Each removes exactly one
    // property of that branch:
    //
    //   * perInstanceSplit is not `static`, so it is not shared at all;
    //   * newPerCall is a static METHOD whose return type is
    //     `SimpleDateFormat`, not a field — every caller gets its own;
    //   * assignedLocally is a local, which cannot be `static` in Java, and
    //     is here so that "the branch never matches a local" is written down
    //     rather than inferred from the language spec.
    //
    // Widen the branch to any `SimpleDateFormat` declaration and all three
    // fire.
    private SimpleDateFormat perInstanceSplit;

    static SimpleDateFormat newPerCall() {
        return new SimpleDateFormat("yyyy");
    }

    String assignedLocally() {
        SimpleDateFormat scratch;
        scratch = new SimpleDateFormat("yyyy");
        return scratch.format(new Date());
    }
}
