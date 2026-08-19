import java.io.FileInputStream;
import java.io.IOException;

public class StreamNotClosed {
    void leaks(String path) throws IOException {
        FileInputStream in = new FileInputStream(path);
        in.read();
    }
}
