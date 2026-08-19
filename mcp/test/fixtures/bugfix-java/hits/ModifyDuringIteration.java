import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class ModifyDuringIteration {
    // One function per `pattern-either` branch, AND one per receiver form
    // inside each branch. The rule restricts the receiver by DECLARED type —
    // it enumerates the collections where mutating mid-iteration is genuinely
    // unsafe rather than negating the concurrent ones — and each branch binds
    // the receiver through a `metavariable-pattern` whose inner
    // `pattern-either` accepts a bare name or a `this.`-qualified one. A
    // branch, or a receiver form, with no fixture behind it could be deleted
    // without a single test moving, which is how a dead clause ships. Every
    // one of these throws ConcurrentModificationException on the next
    // iteration.
    private final List<String> listField = new ArrayList<>();
    private final ArrayList<String> arrayListField = new ArrayList<>();
    private final LinkedList<String> linkedListField = new LinkedList<>();
    private final Set<String> setField = new HashSet<>();
    private final HashSet<String> hashSetField = new HashSet<>();
    private final LinkedHashSet<String> linkedHashSetField = new LinkedHashSet<>();
    private final Collection<String> collectionField = new ArrayList<>();

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

    // The seven `this.`-qualified twins. Same story as the map rule: before
    // the `metavariable-pattern` wrapper, `metavariable-type` could not
    // resolve a qualified field reference, so a field mutated as
    // `this.items.remove(s)` inside `for (String s : this.items)` was
    // invisible. Delete `- pattern: this.$F` from one branch and exactly one
    // of these seven fires.
    void removeThisList() {
        for (String s : this.listField) {
            if (s.isEmpty()) { this.listField.remove(s); }
        }
    }

    void removeThisArrayList() {
        for (String s : this.arrayListField) {
            if (s.isEmpty()) { this.arrayListField.remove(s); }
        }
    }

    void removeThisLinkedList() {
        for (String s : this.linkedListField) {
            if (s.isEmpty()) { this.linkedListField.remove(s); }
        }
    }

    void removeThisSet() {
        for (String s : this.setField) {
            if (s.isEmpty()) { this.setField.remove(s); }
        }
    }

    void removeThisHashSet() {
        for (String s : this.hashSetField) {
            if (s.isEmpty()) { this.hashSetField.remove(s); }
        }
    }

    void removeThisLinkedHashSet() {
        for (String s : this.linkedHashSetField) {
            if (s.isEmpty()) { this.linkedHashSetField.remove(s); }
        }
    }

    void removeThisCollection() {
        for (String s : this.collectionField) {
            if (s.isEmpty()) { this.collectionField.remove(s); }
        }
    }

    // ---- the two `switch` re-inclusion disjuncts ------------------------
    //
    // These two are HITS, not near-misses, and they are the reason the
    // `break`-terminated exclusion is not applied unconditionally. Inside a
    // `switch`, `break` leaves the SWITCH and not the loop, so the for-each
    // calls `next()` again on a mutated collection: a real
    // ConcurrentModificationException that the paired exclusion swallowed
    // whole. Each kills exactly one disjunct — measured, a `switch` written
    // with only `case` labels does not match the `default:` pattern and vice
    // versa, which is why both are here and both are needed.
    void removeInSwitchCaseOnly(List<String> items) {
        for (String s : items) {
            switch (s) {
                case "x":
                    items.remove(s);
                    break;
            }
        }
    }

    void removeInSwitchDefaultOnly(List<String> items) {
        for (String s : items) {
            switch (s) {
                default:
                    items.remove(s);
                    break;
            }
        }
    }
}
