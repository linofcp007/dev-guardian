public class Control {
    // Existe só para acionar a regra `eqeq` do próprio p/r2c-bug-scan,
    // provando que esse pack corre mesmo para Java. Nenhuma regra nossa
    // dispara aqui, e este diretório não faz parte dos pares hits/misses.
    boolean alwaysTrue(int x) {
        return x == x;
    }
}
