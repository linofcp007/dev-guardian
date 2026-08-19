<?php
// Hits for wp-unescaped-output, the rule this fixture directory exists for.
//
// It shipped as `pattern: echo $_GET[$X]`, which is not parsable PHP — `echo`
// is a statement and the pattern has no terminator — so the rule failed to
// compile and NEVER matched anything, in a plugin whose WordPress support is a
// headline feature. Measured against a file containing a real
// `echo $_GET['name'];`: results 0, errors 1, exit 2.
//
// Twelve shapes, chosen so that every branch of the replacement has a fixture
// behind it. Each one puts a raw superglobal on an output path with nothing
// between it and the browser.

// 1-4: the whole echoed/printed expression IS the superglobal.
echo $_GET['name'];
echo $_POST['x'];
echo $_REQUEST['y'];
print $_GET['q'];

// 5-8: the superglobal is a literal operand of a concatenation the echo emits.
// 5 is the left-nested three-term chain, 6 the two-term chain, 7 the
// superglobal on the LEFT of the operator, and 8 the case that matters most for
// the rule's honesty: a correctly escaped value and a raw one in the same
// statement. A rule that looked only at whether SOME escaping function appears
// would call 8 safe.
echo "<h1>" . $_GET['title'] . "</h1>";
echo "Hello " . $_POST['name'];
echo $_REQUEST['a'] . "!";
echo esc_html($safe) . $_GET['raw'];

// 9: interpolation. Distinct from concatenation in the AST and needs its own
// pattern; the concatenation branch does not see it.
echo "<p>{$_GET['msg']}</p>";

// 10-11: the two template forms. `<?=` is the short echo tag, and a `<?php echo`
// island inside HTML is how a WordPress theme file is written.
?>
<span><?= $_GET['v'] ?></span>
<span><?php echo $_REQUEST['w']; ?></span>
<?php

// 12: the bare interpolation form, without braces.
echo "<p>$_POST[status]</p>";

// 13: the `print $A . $B;` half of the concatenation branch. Until this line
// existed the clause was dead BY FIXTURE — deleting it left hits and misses
// unmoved, in the very branch of work that audits for clauses nobody measures.
print "<b>" . $_GET['x'];

// 14-15: nested subscript. `$SUPER[...]` alone binds $SUPER to `$_GET['user']`,
// which fails the metavariable-regex, so the doubly-subscripted form needs its
// own pattern in both the echo and the print shape.
echo $_GET['user']['name'];
print $_POST['u']['v'];

// 16-17: comma-separated echo. Valid PHP that emits every operand, and no
// branch covered it. Two shapes because the superglobal can be the first
// operand or a later one, and one `...` on each side has to absorb the rest.
echo "Hello ", $_GET['name'];
echo $_POST['x'], "</b>";

// 18-21: a ternary whose branch IS the raw value, in both operand positions and
// for both output statements. Scoping this by `pattern-inside` plus a bare
// `$SUPER[...]` instead would flag `echo $f ? esc_html($_GET['t']) : "safe";` —
// measured, it does; the operand-position patterns do not.
echo $flag ? $_GET['t'] : "safe";
echo $flag ? "safe" : $_GET['u'];
print $flag ? $_REQUEST['t'] : "safe";
print $flag ? "safe" : $_REQUEST['u'];

// 22: printf. A WordPress output helper the header used to list as NOT covered.
printf("<p>%s</p>", $_GET['c']);

// 23-24: an interpolated string as an OPERAND of a concatenation. It falls
// between the two old branches — the interpolation pattern wants the echo's
// whole argument to be the string, and `$X . $SUPER[...]` wants a bare
// subscript, not a string containing one.
echo "<p>{$_GET['m']}</p>" . $suffix;
echo $prefix . "<p>{$_GET['n']}</p>";

// 25-26: $_SERVER and $_COOKIE. `$_SERVER['PHP_SELF']` is the canonical
// reflected XSS in PHP and the regex covered only GET/POST/REQUEST.
echo '<form action="' . $_SERVER['PHP_SELF'] . '">';
echo $_COOKIE['theme'];
