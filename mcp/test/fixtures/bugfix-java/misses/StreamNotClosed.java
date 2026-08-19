import java.io.FileInputStream;
import java.io.IOException;

public class StreamNotClosed {
    void withResources(String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path)) { in.read(); }
    }
}
