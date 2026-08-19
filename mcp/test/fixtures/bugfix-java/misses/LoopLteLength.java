public class LoopLteLength {
    int inBounds(int[] xs) {
        int s = 0;
        for (int i = 0; i < xs.length; i++) { s += xs[i]; }
        return s;
    }
    int toLenMinusOne(int[] xs) {
        int s = 0;
        for (int i = 0; i <= xs.length - 1; i++) { s += xs[i]; }
        return s;
    }
    int enhanced(int[] xs) {
        int s = 0;
        for (int x : xs) { s += x; }
        return s;
    }
}
