import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

public class MapGetDeref {
    // One function per `pattern-either` branch of the rule, AND one per
    // receiver form inside each branch. They are not decoration: the rule
    // restricts the receiver by DECLARED type, and each branch binds the
    // receiver through a `metavariable-pattern` whose inner `pattern-either`
    // accepts a bare name (`cache`) or a `this.`-qualified one (`this.cache`).
    // A branch — or a receiver form — with no fixture behind it could be
    // deleted without a single test moving, which is exactly how a dead clause
    // ships. Every one of these is a real NullPointerException on the first
    // missing key.
    private final Map<String, Integer> mapField = new HashMap<>();
    private final HashMap<String, Integer> hashMapField = new HashMap<>();
    private final TreeMap<String, Integer> treeMapField = new TreeMap<>();
    private final LinkedHashMap<String, Integer> linkedField = new LinkedHashMap<>();
    private final ConcurrentHashMap<String, Integer> concurrentField =
        new ConcurrentHashMap<>();

    int deref(Map<String, Integer> m) {
        return m.get("k").intValue();
    }

    int derefHashMap(HashMap<String, Integer> m) {
        return m.get("k").intValue();
    }

    int derefTreeMap(TreeMap<String, Integer> m) {
        return m.get("k").intValue();
    }

    int derefLinkedHashMap(LinkedHashMap<String, Integer> m) {
        return m.get("k").intValue();
    }

    int derefConcurrentHashMap(ConcurrentHashMap<String, Integer> m) {
        // ConcurrentHashMap rejects null VALUES, but `get` on an absent key
        // still returns null — the deref is exactly as unsafe here.
        return m.get("k").intValue();
    }

    // The five `this.`-qualified twins. Before the `metavariable-pattern`
    // wrapper went in, `metavariable-type` could not resolve a qualified
    // field reference, so `cache.get(k).trim()` fired and
    // `this.cache.get(k).trim()` was invisible — same class, same field, same
    // bug. Delete `- pattern: this.$F` from one branch and exactly one of
    // these five fires.
    int derefThisMap() {
        return this.mapField.get("k").intValue();
    }

    int derefThisHashMap() {
        return this.hashMapField.get("k").intValue();
    }

    int derefThisTreeMap() {
        return this.treeMapField.get("k").intValue();
    }

    int derefThisLinkedHashMap() {
        return this.linkedField.get("k").intValue();
    }

    int derefThisConcurrentHashMap() {
        return this.concurrentField.get("k").intValue();
    }

    // The receiver's type is inferred, not written. Java 10's `var` is the
    // shape a type-restricted rule is most likely to miss, so it gets its own
    // hit rather than an assumption.
    int derefVar() {
        var m = new HashMap<String, Integer>();
        return m.get("k").intValue();
    }
}
