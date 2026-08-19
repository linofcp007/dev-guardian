import java.util.Optional;

public class OptionalGet {
    String guarded(Optional<String> o) {
        if (o.isPresent()) { return o.get(); }
        return "";
    }
    String orElse(Optional<String> o) {
        return o.orElse("");
    }
    String orElseThrowExplicit(Optional<String> o) {
        return o.orElseThrow(() -> new IllegalStateException("missing"));
    }
}
