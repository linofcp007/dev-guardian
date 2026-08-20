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

    // The four below exist because the `finally` branch added to the positive
    // pattern could have been bolted on WITHOUT the naming escape hatch and
    // without the non-empty-body requirement, and nothing would have noticed:
    // before the fix every one of these was silent for the wrong reason — the
    // `finally` was doing the silencing, not the rule's own logic. They pin
    // that the two properties survive on the new branch as well as the old
    // one. Delete the `metavariable-regex` and the first two fire; write the
    // `finally` branch without requiring an EMPTY catch body and the last two
    // fire.
    void ignoredNameWithFinally(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException ignored) { } finally { cleanup(); }
    }
    void ignoredNameMultiCatch(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException | NullPointerException ignored) { }
    }
    void logsWithFinally(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { log(e); } finally { cleanup(); }
    }
    void rethrowsWithFinally(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { throw new IllegalStateException(e); } finally { cleanup(); }
    }

    void cleanup() { }
}
