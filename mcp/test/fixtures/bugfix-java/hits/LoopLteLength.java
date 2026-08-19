public class LoopLteLength {
    int sumPastEnd(int[] xs) {
        int s = 0;
        for (int i = 0; i <= xs.length; i++) { s += xs[i]; }
        return s;
    }
}
