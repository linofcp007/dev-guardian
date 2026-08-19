import java.util.Iterator;
import java.util.List;

public class ModifyDuringIteration {
    void viaIterator(List<String> items) {
        Iterator<String> it = items.iterator();
        while (it.hasNext()) {
            if (it.next().isEmpty()) { it.remove(); }
        }
    }
    // viaRemoveIf is DOCUMENTARY, not discriminating: it has no `for` loop
    // at all, so no mutation of a rule anchored on a for-each over `$COLL`
    // could ever make it fire.
    void viaRemoveIf(List<String> items) {
        items.removeIf(String::isEmpty);
    }
    // removeFromOther is DISCRIMINATING: it genuinely exercises the `$COLL`
    // identity requirement. Mutate the shipped rule to let the removed-from
    // collection be a metavariable independent from the one bound by the
    // for-each — dropping the requirement that it be the SAME `$COLL` — and
    // this fires, because it removes from `b` while iterating `a`, which is
    // legal Java that the current rule correctly leaves alone.
    void removeFromOther(List<String> a, List<String> b) {
        for (String s : a) { b.remove(s); }
    }
    void readOnly(List<String> items) {
        for (String s : items) { System.out.println(s); }
    }
}
