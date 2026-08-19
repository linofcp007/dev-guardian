import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

public class MapGetDeref {
    // One function per `pattern-either` branch of the rule. They are not
    // decoration: the rule restricts the receiver by DECLARED type, so a
    // branch with no fixture behind it is a branch that could be deleted
    // without a single test moving — which is exactly how a dead clause ships.
    // Every one of these is a real NullPointerException on the first missing
    // key.
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

    // The receiver's type is inferred, not written. Java 10's `var` is the
    // shape a type-restricted rule is most likely to miss, so it gets its own
    // hit rather than an assumption.
    int derefVar() {
        var m = new HashMap<String, Integer>();
        return m.get("k").intValue();
    }
}
