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

function dg_prepared($wpdb) {
    $wpdb->query($wpdb->prepare("DELETE FROM t WHERE id = %d", $_GET['id']));
}
