<?php
// Near-misses for php-eval and php-sql-injection-direct.

// The WordPress-correct way to parameterise a query. Silent BECAUSE the rule
// requires a concatenation as the argument, and here the concatenation is
// inside $wpdb->prepare's format string, where the placeholder does the work.
function fetch_prepared($wpdb, $id) {
    return $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_posts WHERE ID=%d", $id));
}

// A query passed as a single variable. Silent BECAUSE the pattern is `$X . $Y`,
// a concatenation node — not because the code is safe. If $sql was built by
// concatenation somewhere else this is still injectable and the rule will not
// say so; that limitation is measured and recorded in the audit report rather
// than papered over. Widen the pattern to `mysql_query($X)` and both fire.
function fetch_prebuilt($conn, $sql) {
    mysql_query($sql);
    return mysqli_query($conn, $sql);
}

// A constant query with no interpolation at all.
function count_posts($conn) {
    return mysqli_query($conn, "SELECT COUNT(*) FROM wp_posts");
}

// A function whose NAME contains `eval`, and a call to it. Silent because
// php-eval matches a call to `eval`, not an identifier containing it.
function my_eval_helper($code) {
    return $code;
}
function use_helper($code) {
    return my_eval_helper($code);
}
