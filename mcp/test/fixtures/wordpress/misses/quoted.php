<?php
// configs/semgrep/wordpress.yml: the safe shapes — nothing here may fire.

function dg_quoted($wpdb, $s, $col, $op, $prefix) {
    $wpdb->query("SELECT * FROM t WHERE n = '" . esc_sql($_GET['n']) . "'");
    $wpdb->query("SELECT * FROM t WHERE n LIKE '%" . esc_sql($_GET['n']) . "%'");
    $wpdb->query('SELECT * FROM t WHERE n = "' . esc_sql($_GET['n']) . '"');
    // The quote opens in an earlier literal of the chain (WooCommerce's customer list).
    $w = " AND ( a LIKE '%" . esc_sql($s) . "%' OR b LIKE '%" . esc_sql($s) . "%' )";
    // STR_TO_DATE('...') and a value list in double quotes.
    $d = "BETWEEN STR_TO_DATE('" . esc_sql($_GET['after']) . "', '%Y') AND STR_TO_DATE('" . esc_sql($_GET['before']) . "', '%Y')";
    $r = '(' . (int) $_GET['i'] . ',"' . esc_sql($_GET['name']) . '")';
    // An identifier between backticks and an operator: not values (see the pack's comment).
    $q = 'x.`' . esc_sql($col) . '` ' . esc_sql($op) . ' %f';
    // Not SQL text.
    $key = $prefix . esc_sql($s);
    $meta = 'attribute_' . esc_sql($s);
    // Converted inside esc_sql.
    $wpdb->query("DELETE FROM t WHERE id = " . esc_sql((int) $_GET['id']));
    $wpdb->query("DELETE FROM t WHERE id = " . esc_sql(absint($_GET['id'])));
    $wpdb->query("DELETE FROM t WHERE id = " . esc_sql(intval($_GET['id'])));
    $wpdb->query("SELECT * FROM t WHERE price > " . esc_sql((float) $_GET['p']));
    $wpdb->query("SELECT * FROM t WHERE price < " . esc_sql(floatval($_GET['p'])));
}

function dg_converted_after($wpdb) {
    $a = (int) esc_sql($_GET['a']);
    $wpdb->query("DELETE FROM t WHERE id = " . $a);
    $b = (float) esc_sql($_GET['b']);
    $wpdb->query("DELETE FROM t WHERE price = " . $b);
    $c = absint(esc_sql($_GET['c']));
    $wpdb->query("DELETE FROM t WHERE id = " . $c);
    $d = intval(esc_sql($_GET['d']));
    $wpdb->query("DELETE FROM t WHERE id = " . $d);
    $e = floatval(esc_sql($_GET['e']));
    $wpdb->query("DELETE FROM t WHERE price = " . $e);
    $f = count(esc_sql($_POST['f']));
    $wpdb->query("SELECT * FROM t LIMIT " . $f);
    $g = sizeof(esc_sql($_POST['g']));
    $wpdb->query("SELECT * FROM t LIMIT " . $g);
    $h = strlen(esc_sql($_GET['h']));
    $wpdb->query("SELECT * FROM t WHERE len = " . $h);
}

function dg_quoted_in_the_value($wpdb) {
    // WooCommerce's order meta: the list already quoted.
    $ids = esc_sql($_POST['ids']);
    $in = "'" . implode("', '", $ids) . "'";
    $wpdb->get_results("SELECT * FROM t WHERE post_id IN ( $in )");
    $in2 = "('" . implode("','", $ids) . "')";
    $wpdb->get_results("SELECT * FROM t WHERE k IN " . $in2);
    $one = esc_sql($_GET['one']);
    $q = '"' . $one . '"';
    $wpdb->get_results("SELECT * FROM t WHERE k = " . $q);
}

function dg_interpolated_quoted($wpdb, $post_id) {
    $id = esc_sql($_GET['id']);
    $wpdb->query("DELETE FROM t WHERE n = '$id'");
    $wpdb->query("DELETE FROM t WHERE n = '{$id}' AND x = 1");
    // The unquoted one is not esc_sql's.
    $wpdb->query("DELETE FROM t WHERE id = $post_id AND n = '$id'");
    // Code, not a string.
    $copy = $id;
    if ($copy == $id) {
        return;
    }
}

function dg_sprintf_safe($wpdb) {
    $wpdb->query(sprintf("DELETE FROM t WHERE n = '%s'", esc_sql($_GET['n'])));
    // %d makes it an integer.
    $wpdb->query(sprintf("DELETE FROM t WHERE id = %d", esc_sql($_GET['n'])));
    // One %s quoted: which argument lands where is not guessed.
    $wpdb->query(sprintf("DELETE FROM t WHERE n = '%s' AND id = %s", esc_sql($_GET['n']), $_GET['i']));
}

function dg_prepared($wpdb) {
    $wpdb->query($wpdb->prepare("DELETE FROM t WHERE id = %d", $_GET['id']));
}
