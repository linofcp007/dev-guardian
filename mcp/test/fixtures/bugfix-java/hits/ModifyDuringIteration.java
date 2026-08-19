import java.util.List;

public class ModifyDuringIteration {
    void removeWhileIterating(List<String> items) {
        for (String s : items) {
            if (s.isEmpty()) { items.remove(s); }
        }
    }
}
