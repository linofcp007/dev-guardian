import java.util.Optional;

public class OptionalGet {
    String unchecked(Optional<String> o) {
        return o.get();
    }
}
