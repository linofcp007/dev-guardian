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

// 16-26: EVERY PHP cast spelling, applied to a raw superglobal. `echo (int)
// $_GET['id'];` is the standard safe way to emit a numeric request parameter in
// WordPress: XSS-impossible, and flagged ERROR by this rule until the cast
// guard was added. Semgrep sees THROUGH a cast node — `$SUPER[...]` binds to
// the subscript inside it and `metavariable-regex` reads the text of the
// subscript, not of the cast — so nothing in the pattern language notices the
// cast is there. Measured before the guard: all eleven fire.
function render_cast() {
    echo (int) $_GET['a'];
    echo (integer) $_GET['b'];
    echo (float) $_GET['c'];
    echo (double) $_GET['d'];
    echo (real) $_GET['e'];
    echo (bool) $_GET['f'];
    echo (boolean) $_GET['g'];
    echo (string) $_GET['h'];
    echo (binary) $_GET['i'];
    echo (array) $_GET['j'];
    echo (object) $_GET['k'];
}

// 27-33: the same cast, in every OTHER branch the rule now has. The guard is a
// single `pattern-not-regex` over the matched text rather than one exclusion
// per branch, and these are what prove it reaches all of them.
function render_cast_everywhere($flag, $n) {
    print (int) $_POST['n'];
    echo "id=" . (int) $_GET['e'];
    echo (int) $_GET['f'] . "x";
    echo "n=", (int) $_GET['g'];
    echo $flag ? (int) $_GET['t'] : "safe";
    printf("<p>%d</p>", (int) $_GET['c']);
    echo (int) $_GET['u']['id'];
}

// 34-40: the near-misses for the branches added alongside the cast guard. Each
// is the escaped twin of a shape in `hits/output.php`, and each is silent for
// the same reason the older ones are: the operand the branch names is a CALL
// node, not a raw subscript.
function render_new_branches_escaped($flag, $row, $safe, $suffix) {
    echo $flag ? esc_html($_GET['t']) : "safe";
    printf("<p>%s</p>", esc_html($_GET['c']));
    echo "Hello ", esc_html($_GET['name']);
    echo $row['user']['name'];
    echo esc_url($_SERVER['PHP_SELF']);
    echo esc_html($_COOKIE['theme']);
    echo "<p>{$safe}</p>" . $suffix;
}

// 41-42: the two lines that were `known-false-positives/output.php` until this
// commit. A raw superglobal concatenated INSIDE an escaping call, where the
// call is itself an operand of a concatenation the echo emits. They were
// recorded as unfixable because `echo` lowers to a call node, so any exclusion
// naming the escaping call names the echo too. That is true of the AST and
// false of the FILTER: `metavariable-regex` matches the SOURCE TEXT of $F,
// which is `echo`, `print` or `<?=` for the language constructs and an
// identifier for a real call. Requiring identifier shape separates them at no
// cost — measured, 12/12 true positives kept, these two gone.
function formerly_false_positive($a, $label) {
    echo esc_html($a . $_GET['b']) . "x";
    echo "y" . esc_html($label . $_POST['q']);
}

// 43: a superglobal read from $_SERVER but never output — the same
// discriminating shape as line 62 above, for the two names just added to the
// regex.
function read_server() {
    $path = $_SERVER['REQUEST_URI'];
    return $path;
}
