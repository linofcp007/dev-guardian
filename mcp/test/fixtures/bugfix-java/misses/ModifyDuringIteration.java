import java.util.Iterator;
import java.util.List;

public class ModifyDuringIteration {
    void viaIterator(List<String> items) {
        Iterator<String> it = items.iterator();
        while (it.hasNext()) {
            if (it.next().isEmpty()) { it.remove(); }
        }
    }
    void viaRemoveIf(List<String> items) {
        items.removeIf(String::isEmpty);
    }
    void removeFromOther(List<String> a, List<String> b) {
        for (String s : a) { b.remove(s); }
    }
    void readOnly(List<String> items) {
        for (String s : items) { System.out.println(s); }
    }
}
