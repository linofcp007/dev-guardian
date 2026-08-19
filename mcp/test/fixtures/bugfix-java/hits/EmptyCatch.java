public class EmptyCatch {
    void swallow(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { }
    }
}
