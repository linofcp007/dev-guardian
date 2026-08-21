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

    // The four below are the MULTI-RESOURCE hole, and they are the reason the
    // rule stopped excluding try headers by naming them and started anchoring
    // on a statement sequence instead. A try-with-resources header with two
    // resources is a different AST node from one with a single resource, and
    // the exclusions that shipped here named exactly one — so
    // `try (FileInputStream fis = ...; BufferedInputStream bis = new
    // BufferedInputStream(fis))`, which is how a Java file gets read with a
    // buffer, was reported as a leak. MEASURED on 12 593 OpenJDK files: 8 of
    // the rule's 12 findings were this shape. Enumerating the lengths was
    // tried and abandoned — two clauses for two resources, three for three,
    // doubled again by the finalizer — and `try (...)`, `try ($...RES)` and
    // `try (...; $R; ...)` are all `Invalid pattern for Java`.
    //
    // All four are DISCRIMINATING for the `pattern-inside` anchor: delete it
    // and every one fires. A resource in a try header is not a statement in a
    // statement sequence, so no header of any length reaches the rule.
    void twoResources(String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path);
             java.io.BufferedInputStream bis = new java.io.BufferedInputStream(in)) { bis.read(); }
    }
    void threeResources(String path) throws IOException {
        try (java.io.Reader r = new java.io.StringReader("x");
             FileInputStream in = new FileInputStream(path);
             java.io.BufferedInputStream bis = new java.io.BufferedInputStream(in)) { bis.read(); r.read(); }
    }
    void twoResourcesFinally(String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path);
             java.io.BufferedInputStream bis = new java.io.BufferedInputStream(in)) { bis.read(); }
        finally { cleanup(); }
    }
    void twoResourcesCatch(String path) {
        try (FileInputStream in = new FileInputStream(path);
             java.io.BufferedInputStream bis = new java.io.BufferedInputStream(in)) { bis.read(); }
        catch (IOException e) { cleanup(); }
    }

    void cleanup() { }
}
