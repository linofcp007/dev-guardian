public class PrintStackTraceOnly {
    void printsThenRethrows(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { e.printStackTrace(); throw new IllegalStateException(e); }
    }
    void printsThenRecovers(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { e.printStackTrace(); fallback(); }
    }
    void fallback() { }
}
