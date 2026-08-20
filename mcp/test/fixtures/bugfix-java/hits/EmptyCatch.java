import java.io.IOException;
import java.io.StringReader;

// SIX empty catches, and the shape of the try around each one is the whole
// point of the file. A Java try statement WITH a finalizer is a different AST
// node from one without, so `try { ... } catch ($E $V) { }` never matched a
// try/catch/finally: attaching `finally { cleanup(); }` to a swallowing catch
// silenced the rule outright. Measured before the fix: 3 of 6 (the three
// without `finally`).
//
// The resource header and the multi-catch were measured in the same run and
// are NOT holes — `try { ... } catch ($E $V) { }` already matched a
// try-with-resources and already matched `catch (A | B e)`. They are pinned
// here anyway, because "already matched" is a measurement with a date on it
// and the counts are asserted.
//
// The resource is a StringReader and not a FileInputStream on purpose: the
// per-file expectation asserts the EXACT id set, and a FileInputStream here
// would drag `memory-leak-stream-not-closed` into it.
public class EmptyCatch {
    void swallow(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { }
    }

    void swallowWithFinally(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { } finally { cleanup(); }
    }

    void swallowMultiCatch(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException | NullPointerException e) { }
    }

    void swallowMultiCatchWithFinally(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException | NullPointerException e) { } finally { cleanup(); }
    }

    void swallowInResource(String p) {
        try (StringReader r = new StringReader(p)) { r.read(); } catch (IOException e) { }
    }

    void swallowInResourceWithFinally(String p) {
        try (StringReader r = new StringReader(p)) { r.read(); } catch (IOException e) { } finally { cleanup(); }
    }

    void cleanup() { }
}
