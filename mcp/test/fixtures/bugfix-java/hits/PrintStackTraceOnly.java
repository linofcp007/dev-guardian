import java.io.IOException;
import java.io.StringReader;

// The same six try shapes as hits/EmptyCatch.java, for the same reason: this
// rule was anchored on the identical `try { ... } catch ($E $V) { ... }` form,
// so a `finally` silenced it identically. Measured before the fix: 3 of 6.
//
// Kept as a separate file from EmptyCatch because the per-file expectation
// asserts the exact id set, and these two rules are mutually exclusive by body
// shape — an empty block is not a `printStackTrace()` call.
public class PrintStackTraceOnly {
    void onlyPrints(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { e.printStackTrace(); }
    }

    void onlyPrintsWithFinally(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { e.printStackTrace(); } finally { cleanup(); }
    }

    void onlyPrintsMultiCatch(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException | NullPointerException e) { e.printStackTrace(); }
    }

    void onlyPrintsMultiCatchWithFinally(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException | NullPointerException e) { e.printStackTrace(); } finally { cleanup(); }
    }

    void onlyPrintsInResource(String p) {
        try (StringReader r = new StringReader(p)) { r.read(); } catch (IOException e) { e.printStackTrace(); }
    }

    void onlyPrintsInResourceWithFinally(String p) {
        try (StringReader r = new StringReader(p)) { r.read(); } catch (IOException e) { e.printStackTrace(); } finally { cleanup(); }
    }

    void cleanup() { }
}
