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
}
