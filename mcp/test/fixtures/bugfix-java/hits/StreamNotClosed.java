import java.io.FileInputStream;
import java.io.IOException;

public class StreamNotClosed {
    void leaks(String path) throws IOException {
        FileInputStream in = new FileInputStream(path);
        in.read();
    }

    // The two below measure the RECALL COST of the `pattern-inside` anchor
    // that replaced the try-header exclusions. The anchor requires the
    // declaration to sit in a statement sequence — `decl;` followed by `...`
    // — and the question nobody should have to re-derive is whether `...`
    // matches ZERO following statements. It does, in both positions where
    // that matters: the last statement of a method body, and the only
    // statement of a nested block. Both leak, both must fire.
    void leaksAsLastStatement(String path) throws IOException {
        FileInputStream last = new FileInputStream(path);
    }

    void leaksInNestedBlock(String path, boolean wanted) throws IOException {
        if (wanted) {
            FileInputStream only = new FileInputStream(path);
        }
    }
}
