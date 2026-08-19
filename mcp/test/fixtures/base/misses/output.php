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

// 44-54: the near-misses for the narrowed match. Once the rule points at the
// subscript instead of the statement, an escaped operand ELSEWHERE in the same
// statement stops being the thing that silences it — so each of these has to be
// silent on its own merits, and each was checked against the branch it belongs
// to rather than against the statement as a whole.
function render_narrow_match_near_misses($flag, $config, $suffix) {
    printf("%s %s", esc_attr($_POST['b']), esc_url($_REQUEST['c']));
    $s = sprintf("%s", $_GET['d']);
    echo "a", esc_html($_GET['e']), "b";
    echo "x", $title, "y";
    echo $flag ? esc_html($_GET['f']) : esc_html($_POST['g']);
    echo isset($_GET['h']) ? "set" : "unset";
    echo $_GET['i'] === 'yes' ? "y" : "n";
    echo esc_html($_GET['j']['k']);
    echo $config['db']['host'];
    echo (int) $_SERVER['CONTENT_LENGTH'];
    echo (bool) $_COOKIE['flag'];
    return $s . $suffix;
}

// 55: a superglobal in a CONDITION and nothing else. The ternary branches are
// scoped so the superglobal has to be an OPERAND; a `pattern-inside` on the
// whole ternary plus a bare `$SUPER[...]` flags this, measured.
function render_condition_only() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') { echo "posted"; }
}

// 56-64: the superglobal is an ARRAY KEY, not the output. What reaches the
// browser comes from a developer-controlled lookup table; the request only
// chooses which element. Ordinary i18n and menu code.
//
// These are near-misses for the ANCHOR of the rule, not for any one branch, and
// they are the FP the re-architecture introduced. Twelve of the fourteen scopes
// bind $SUPER themselves, so `metavariable-regex` rejects `$labels` and the
// comma, printf and ternary lookups below were never in danger. The two
// CONCATENATION scopes — `echo $A . $B;` and `print $A . $B;` — do not bind
// $SUPER, so the narrow `pattern: $SUPER[...]` was free to match a subscript in
// INDEX position. Measured before `pattern-not-inside: $ARR[$SUPER[...]]`: the
// four concat shapes fire, five findings, all ERROR.
function render_lookup($labels, $menu, $flag) {
    echo $labels[$_GET['lang']] . "</b>";
    echo "<b>" . $labels[$_POST['lang']];
    echo $menu[$_GET['section']][$_GET['item']] . "";
    echo "<b>", $labels[$_GET['lang']], "</b>";
    printf("<p>%s</p>", $labels[$_GET['lang']]);
    echo $flag ? $labels[$_GET['a']] : $labels[$_POST['b']];
    echo $_GET['mode'] === 'edit' ? $labels['edit'] : $labels['view'];
    echo esc_html($labels[$_GET['lang']]) . "x";
}

// 65-66: the superglobal is being TESTED, and what the echo emits is the
// literal on the other side. Both are silent, and for DIFFERENT reasons — an
// asymmetry that is measured, not assumed, and that decides how many clauses
// the rule carries:
//
//  - `isset()` is not a call node in Semgrep's PHP AST, so the `$G(...)` guard
//    never sees it. Ablating `pattern-not-inside: isset(...)` lights the first
//    line and nothing else. The clause is load-bearing.
//  - `empty()` IS modelled as a call, so `$G(...)` already covers it. Ablating
//    an `empty(...)` clause moved nothing at all; ablating `$G(...)` as well is
//    what lights the second line. Writing the clause anyway — for symmetry with
//    `isset`, which is exactly how it got proposed — would have added a rule
//    line that no measurement can ever move, in the branch of work that exists
//    to delete those. The near-miss stays; the clause does not.
function render_guarded() {
    echo (isset($_GET['x']) ? "set" : "unset") . "!";
    echo (empty($_GET['q']) ? "none" : "some") . "!";
}
