public class EmptyCatch {
    void logs(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { log(e); }
    }
    void rethrows(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { throw new IllegalStateException(e); }
    }
    void log(Exception e) { }
}
