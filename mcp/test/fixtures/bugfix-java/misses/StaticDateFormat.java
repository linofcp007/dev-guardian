import java.text.SimpleDateFormat;
import java.util.Date;

public class StaticDateFormat {
    private final SimpleDateFormat perInstance = new SimpleDateFormat("yyyy");

    String localInstance() {
        SimpleDateFormat local = new SimpleDateFormat("yyyy");
        return local.format(new Date());
    }

    String useInstanceField() {
        return perInstance.format(new Date());
    }

    // THREAD_SAFE is DOCUMENTARY, not discriminating: it's a
    // `DateTimeFormatter`, a different class from `SimpleDateFormat`, so no
    // mutation of the shipped pattern — which matches on the literal
    // `SimpleDateFormat` identifier — could ever make it fire. It records
    // that the suggested fix is itself safe; it proves nothing about the
    // rule.
    static final java.time.format.DateTimeFormatter THREAD_SAFE =
        java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd");
}
