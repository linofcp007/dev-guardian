import java.text.SimpleDateFormat;

public class StaticDateFormat {
    static final SimpleDateFormat SHARED_FINAL = new SimpleDateFormat("yyyy-MM-dd");
    static SimpleDateFormat SHARED_PLAIN = new SimpleDateFormat("yyyy");

    // SHARED_QUALIFIED is a REGRESSION GUARD, not a branch witness: the rule
    // ships a single pattern, written with the fully-qualified name, and the
    // short forms above match it only because the `import` at the top lets
    // Semgrep resolve them. This one carries the qualified name in the source
    // and was invisible for as long as the rule's only pattern was the short
    // one — which is the shape you get in any file that has no import.
    static final java.text.SimpleDateFormat SHARED_QUALIFIED =
        new java.text.SimpleDateFormat("yyyy");
}
