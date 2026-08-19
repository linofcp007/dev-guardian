public class EmptyCatch {
    void logs(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { log(e); }
    }
    void rethrows(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { throw new IllegalStateException(e); }
    }
    void log(Exception e) { }

    // The three below are DISCRIMINATING for the naming exclusion, and each
    // for one alternative of it: delete `ignored` from the
    // `metavariable-regex` on $V and only ignoredName fires, and so on.
    //
    // Semgrep matches the AST, and comments are not in it — a catch block
    // documented as a deliberate ignore is byte-identical to a silent
    // swallow, so the comment can never be the escape hatch. The variable
    // NAME can be, and it is already the convention two of the standard Java
    // linters use: Checkstyle's EmptyCatchBlock allows `ignore` and
    // `expected` by default, IntelliJ's inspection allows `ignored`. Naming
    // the exception one of those is the self-documenting way to say
    // "deliberate" without a suppression comment.
    //
    // Every other name still fires — the rule is not weakened, it is given a
    // vocabulary.
    void ignoredName(String p) {
        // IntelliJ's convention. Absence of a parsable value is expected here.
        try { Integer.parseInt(p); } catch (NumberFormatException ignored) { }
    }
    void ignoreName(String p) {
        // Checkstyle's first default.
        try { Integer.parseInt(p); } catch (NumberFormatException ignore) { }
    }
    void expectedName(String p) {
        // Checkstyle's second default: the throw IS the assertion.
        try { Integer.parseInt(p); } catch (NumberFormatException expected) { }
    }
}
