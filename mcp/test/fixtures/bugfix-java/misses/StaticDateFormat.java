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

    static final java.time.format.DateTimeFormatter THREAD_SAFE =
        java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd");
}
