import java.text.SimpleDateFormat;

public class StaticDateFormat {
    static final SimpleDateFormat SHARED_FINAL = new SimpleDateFormat("yyyy-MM-dd");
    static SimpleDateFormat SHARED_PLAIN = new SimpleDateFormat("yyyy");
}
