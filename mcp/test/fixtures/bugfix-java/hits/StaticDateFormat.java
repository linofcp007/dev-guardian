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

    // SPLIT_DECLARATION is DISCRIMINATING for the second branch and for
    // nothing else: delete it and this field alone goes quiet. The field is
    // declared with no initializer and assigned in a `static` block, which is
    // what people write when the next line has to call `setTimeZone(...)`.
    // It was invisible for as long as the rule's only pattern demanded the
    // `new` on the declaration itself.
    //
    // It is not a hypothetical shape. MEASURED: zero occurrences in 12 593
    // OpenJDK files, exactly ONE across 4 754 Spring Framework files — and
    // that one is a live race, a shared static formatter used with no lock at
    // all. The single candidate the corpora had, and the rule could not see
    // it.
    static final SimpleDateFormat SPLIT_DECLARATION;

    static {
        SPLIT_DECLARATION = new SimpleDateFormat("yyyy");
        SPLIT_DECLARATION.setLenient(false);
    }
}
