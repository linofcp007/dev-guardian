<?php
// Near-misses for wp-unescaped-output — the correct WordPress code that most
// resembles the bug. Written BEFORE the hit fixture, deliberately: a fixture
// chosen by the rule's author tests the author's intent rather than the
// pattern, and the shapes below are the ones that decide whether the rule is
// usable in a real theme or plugin.

// 1-6: the escaping functions a WordPress developer actually reaches for,
// including a nested pair and a numeric cast. Silent BECAUSE the whole echoed
// expression is a CALL rather than a raw subscript — which is why the rule
// needs no list of escaping function names, and why `my_own_escaper()` below
// is silent too. A list-based rule flags every escaper nobody enumerated.
function render_escaped() {
    echo esc_html($_GET['name']);
    echo htmlspecialchars($_POST['x']);
    echo esc_attr($_GET['id']);
    echo intval($_GET['page']);
    echo wp_kses_post($_POST['content']);
    echo esc_html(sanitize_text_field($_GET['s']));
    echo my_own_escaper($_REQUEST['q']);
}

// 7-8: escaped values inside a concatenation. The concatenation branch of the
// rule requires a superglobal as a LITERAL operand of the `.` operator, so an
// escaped call in that position is silent BECAUSE the operand is a call node.
function render_concatenated() {
    echo "<a href='" . esc_url($_GET['u']) . "'>link</a>";
    echo "<b>" . esc_html($_POST['t']) . "</b>";
}

// 9: the case that decides between two designs. The raw superglobal is
// concatenated INSIDE an escaping call, so the escaping still covers it. Silent
// BECAUSE the concatenation branch is scoped by `pattern-inside: echo $A . $B;`
// — the echo's own argument has to be the concatenation. Drop that scope in
// favour of a plain `pattern-inside: echo ...;` and this fires: measured, that
// version produced 7 findings across this file.
function render_concatenated_then_escaped($a) {
    echo esc_html($a . $_GET['b']);
}

// 10-12: array subscripts that are not superglobals. These are the near-misses
// for the `metavariable-regex` on $SUPER, and they are the reason it is
// load-bearing: the patterns are written over `$SUPER[...]`, which matches ANY
// array access, so without the regex every `echo $row['title'];` in every
// WordPress template on earth becomes an ERROR-tier finding. Measured against
// the rule with only the `metavariable-regex` deleted: all three fire — the two
// direct echoes through the first branch, and the concatenation through the
// branch scoped by `pattern-inside`.
function render_row($row, $atts) {
    echo $row['title'];
    echo $atts['id'];
    echo "<td>" . $row['name'] . "</td>";
}

// 13-15: output that never touches request data, and request data that never
// reaches output. The assignment is the discriminating one — the superglobal is
// read raw, which is not itself a bug; the rule is about what reaches the
// browser.
function render_other($title) {
    echo "a literal string";
    echo $title;
    $value = $_GET['x'];
    return $value;
}
