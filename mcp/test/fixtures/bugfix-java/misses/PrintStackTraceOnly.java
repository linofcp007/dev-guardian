public class PrintStackTraceOnly {
    void printsThenRethrows(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { e.printStackTrace(); throw new IllegalStateException(e); }
    }
    void printsThenRecovers(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { e.printStackTrace(); fallback(); }
    }
    void fallback() { }

    // The three below pin that the `finally` branch did not widen the rule
    // beyond "the catch body is ONLY printStackTrace()". Before the fix all
    // three were silent because the `finally` silenced everything; now they
    // are silent because the catch body does more than print, which is the
    // property the rule was always supposed to test.
    void printsThenRethrowsWithFinally(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { e.printStackTrace(); throw new IllegalStateException(e); } finally { cleanup(); }
    }
    void printsThenRecoversWithFinally(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { e.printStackTrace(); fallback(); } finally { cleanup(); }
    }
    void printsThenRecoversMultiCatch(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException | NullPointerException e) { e.printStackTrace(); fallback(); }
    }

    void cleanup() { }
}
