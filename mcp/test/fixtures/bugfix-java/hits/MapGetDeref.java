import java.util.Map;

public class MapGetDeref {
    int deref(Map<String, Integer> m) {
        return m.get("k").intValue();
    }
}
