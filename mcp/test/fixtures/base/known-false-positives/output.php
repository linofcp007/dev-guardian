<?php
// CORRECT CODE THAT wp-unescaped-output FLAGS ANYWAY. Not a hit fixture and not
// a near-miss: a measured, pinned defect, kept visible instead of being written
// down in a comment nobody re-runs.
//
// Both lines escape their input properly and both are reported. The shape is
// narrow: a raw superglobal concatenated INSIDE an escaping call, where that
// call is itself an operand of a concatenation the echo emits. The rule matches
// the inner concatenation node, and `pattern-inside: echo $A . $B;` is satisfied
// by the OUTER one.
//
// It is not fixable with Semgrep OSS pattern syntax, and that was measured, not
// assumed: `echo` is a CALL node in Semgrep's PHP AST — `$F(...)` matches
// `echo $_GET['a'];` at columns 1-16 — so every exclusion that would name the
// escaping call also names the echo. `pattern-not-inside: $F($C . $D)` and
// `pattern-not-inside: $F(..., $C . $D, ...)` were both tried and both take the
// rule to zero findings on everything, true positives included.
//
// It is kept rather than traded away, and the trade is the honest one to state:
// the alternative is to anchor the concatenation branch to the echo statement at
// a bounded set of depths (`echo $X . $SUPER[...];`,
// `echo $X . $SUPER[...] . $Y;`, …), which removes these two and introduces a
// silent recall cliff at the first echo with one more term than somebody
// enumerated. In a SECURITY pack a missed XSS is the worse failure, and this
// whole branch of work exists because of rules that silently found nothing.
//
// If a future rewrite makes these two silent, the test that reads this
// directory goes red — which is the point. Delete the entry then.
function known_false_positives($a, $label) {
    echo esc_html($a . $_GET['b']) . "x";
    echo "y" . esc_html($label . $_POST['q']);
}

// The three shapes NEXT DOOR that are silent, pinned here so the boundary of
// the defect is a measurement rather than a description. Escaping applied to a
// concatenation is fine as long as the echo's own argument is that call, and an
// escaped operand inside a concatenation the echo emits is fine too.
function correctly_silent($a, $label) {
    echo esc_html($a . $_GET['b']);
    echo "<b>" . esc_html($_POST['t']) . "</b>";
    echo esc_html($label);
}
