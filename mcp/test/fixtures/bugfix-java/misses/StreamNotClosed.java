import java.io.FileInputStream;
import java.io.IOException;

public class StreamNotClosed {
    void withResources(String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path)) { in.read(); }
    }

    // java9Resource is DISCRIMINATING for the second exclusion clause. Java 9
    // allows an already-declared, effectively-final resource to be named
    // directly in the try header — `try (in) { ... }` — and the stream IS
    // closed automatically, exactly as in `withResources` above. The
    // declaration sits OUTSIDE the try, so the original exclusion, which only
    // recognised `try ($T2 $V2 = new FileInputStream(...))`, never saw it and
    // the rule fired at WARNING on correct code. Delete the sequence-shaped
    // `pattern-not-inside` that covers this form and this fires.
    void java9Resource(String path) throws IOException {
        FileInputStream in = new FileInputStream(path);
        try (in) { in.read(); }
    }

    // The six below are the `finally` hole, in this rule the OPPOSITE
    // direction from the two error-handling rules: here the try shape sits in
    // an EXCLUSION, so a shape the exclusion cannot match does not silence the
    // rule, it makes the rule accuse correct code. A try WITH a finalizer is a
    // different AST node, so neither exclusion reached a try-with-resources
    // that also has a `finally` — and a stream in a try-with-resources is
    // closed by the resource header whatever else is attached to the
    // statement. Measured before the fix: all six fired at WARNING on code
    // that closes its stream.
    //
    // A `catch` alone was measured in the same run and is NOT a hole: both
    // exclusions already matched `try (r = ...) { ... } catch (...) { ... }`.
    // Semgrep's Java try matching is insensitive to extra catch clauses and
    // sensitive to the presence of a finalizer; the two are pinned separately
    // here so that the day that stops being true, this file fires.
    void withResourcesFinally(String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path)) { in.read(); } finally { cleanup(); }
    }
    void withResourcesCatch(String path) {
        try (FileInputStream in = new FileInputStream(path)) { in.read(); } catch (IOException e) { cleanup(); }
    }
    void withResourcesCatchFinally(String path) {
        try (FileInputStream in = new FileInputStream(path)) { in.read(); } catch (IOException e) { cleanup(); } finally { cleanup(); }
    }
    void java9ResourceFinally(String path) throws IOException {
        FileInputStream in = new FileInputStream(path);
        try (in) { in.read(); } finally { cleanup(); }
    }
    void java9ResourceCatch(String path) throws IOException {
        FileInputStream in = new FileInputStream(path);
        try (in) { in.read(); } catch (IOException e) { cleanup(); }
    }
    void java9ResourceCatchFinally(String path) throws IOException {
        FileInputStream in = new FileInputStream(path);
        try (in) { in.read(); } catch (IOException e) { cleanup(); } finally { cleanup(); }
    }

    void cleanup() { }
}
