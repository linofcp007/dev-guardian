import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

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

    // findRemoveReturn is DISCRIMINATING for the `return`-terminated
    // exclusion, and it is the most common list-mutation idiom in Java:
    // find it, remove it, leave. No `ConcurrentModificationException` is
    // possible because the loop never calls `next()` again — the `return`
    // leaves the method on the same iteration that mutated. Delete the
    // `remove(); return ...;` exclusion and this fires, at ERROR, on correct
    // code.
    void findRemoveReturn(List<String> items, String target) {
        for (String s : items) {
            if (s.equals(target)) { items.remove(s); return; }
        }
    }

    // findRemoveBreak is DISCRIMINATING for the `break`-terminated exclusion,
    // and for that one only: it is the same argument as findRemoveReturn but
    // the loop is left by `break`, which is a different AST node and needs
    // its own clause. Delete the `remove(); break;` exclusion and this fires
    // while findRemoveReturn stays silent.
    void findRemoveBreak(List<String> items, String target) {
        for (String s : items) {
            if (s.equals(target)) { items.remove(s); break; }
        }
    }

    // cowRemove is DISCRIMINATING for the receiver-type restriction.
    // `CopyOnWriteArrayList` iterates over a snapshot taken when the iterator
    // was created, so mutating it mid-iteration is not merely tolerated, it
    // is the collection's designed usage and the textbook safe-removal idiom
    // for it. Widen `$COLL` back to any receiver — drop the
    // `metavariable-type` restriction — and this fires at ERROR on code that
    // cannot throw.
    void cowRemove(CopyOnWriteArrayList<String> cow) {
        for (String s : cow) {
            if (s.isEmpty()) { cow.remove(s); }
        }
    }
}
