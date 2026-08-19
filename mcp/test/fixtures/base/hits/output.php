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
