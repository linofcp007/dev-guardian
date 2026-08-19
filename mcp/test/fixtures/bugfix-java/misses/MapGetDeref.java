import java.util.Map;

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
}
