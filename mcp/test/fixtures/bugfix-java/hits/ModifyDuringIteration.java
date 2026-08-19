import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class ModifyDuringIteration {
    // One function per `pattern-either` branch. The rule restricts the
    // receiver by DECLARED type — it enumerates the collections where
    // mutating mid-iteration is genuinely unsafe rather than negating the
    // concurrent ones — so a branch with no fixture behind it could be
    // deleted without a single test moving, which is how a dead clause ships.
    // Every one of these throws ConcurrentModificationException on the next
    // iteration.
    void removeWhileIteratingList(List<String> items) {
        for (String s : items) {
            if (s.isEmpty()) { items.remove(s); }
        }
    }

    void removeWhileIteratingArrayList(ArrayList<String> items) {
        for (String s : items) {
            if (s.isEmpty()) { items.remove(s); }
        }
    }

    void removeWhileIteratingLinkedList(LinkedList<String> items) {
        for (String s : items) {
            if (s.isEmpty()) { items.remove(s); }
        }
    }

    void removeWhileIteratingSet(Set<String> items) {
        for (String s : items) {
            if (s.isEmpty()) { items.remove(s); }
        }
    }

    void removeWhileIteratingHashSet(HashSet<String> items) {
        for (String s : items) {
            if (s.isEmpty()) { items.remove(s); }
        }
    }

    void removeWhileIteratingLinkedHashSet(LinkedHashSet<String> items) {
        for (String s : items) {
            if (s.isEmpty()) { items.remove(s); }
        }
    }

    void removeWhileIteratingCollection(Collection<String> items) {
        for (String s : items) {
            if (s.isEmpty()) { items.remove(s); }
        }
    }
}
