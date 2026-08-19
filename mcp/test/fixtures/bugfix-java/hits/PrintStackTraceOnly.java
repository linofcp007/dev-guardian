public class PrintStackTraceOnly {
    void onlyPrints(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { e.printStackTrace(); }
    }
}
