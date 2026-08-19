<?php
// Hits for php-eval and php-sql-injection-direct.
//
// The three-term concatenation is here because `.` is left-associative in PHP,
// so `"a" . $b . "c"` is `("a" . $b) . "c"` and the rule's `$X . $Y` binds $X to
// the whole left subtree. That it matches at all is a measurement, not a
// reading of the pattern.

function boot($code) {
    eval($code);
}

function fetch_two_terms($id) {
    return mysql_query("SELECT * FROM wp_posts WHERE ID=" . $id);
}

function fetch_three_terms($id) {
    return mysql_query("SELECT * FROM wp_posts WHERE ID=" . $id . " AND post_status='publish'");
}

function fetch_mysqli($conn, $id) {
    return mysqli_query($conn, "SELECT * FROM wp_posts WHERE ID=" . $id);
}
