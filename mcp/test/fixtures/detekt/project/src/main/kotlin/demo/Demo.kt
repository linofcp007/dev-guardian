package demo

class Demo {
    fun empty() {
    }

    fun risky(): Int {
        try {
            return 42 * 1000
        } catch (e: Exception) {
            return -1
        }
    }
}
