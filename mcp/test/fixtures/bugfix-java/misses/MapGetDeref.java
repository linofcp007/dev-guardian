import java.util.Map;

public class MapGetDeref {
    int checked(Map<String, Integer> m) {
        Integer v = m.get("k");
        if (v == null) { return 0; }
        return v.intValue();
    }
    int withDefault(Map<String, Integer> m) {
        return m.getOrDefault("k", 0).intValue();
    }
    Integer justGet(Map<String, Integer> m) {
        return m.get("k");
    }
}
