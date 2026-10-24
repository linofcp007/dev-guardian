<?php
// configs/semgrep/wordpress.yml: every line marked BUG is one finding of wordpress-esc-sql-unquoted.

function dg_unquoted($wpdb, $base) {
    // The CVE-2021-24340 shape (wp-statistics 13.0.7).
    $wpdb->get_var("SELECT COUNT(*) FROM t WHERE `id` = " . esc_sql($_GET['ID']) . " AND `type` = 'x'"); // BUG
    $wpdb->query('DELETE FROM t WHERE id = ' . esc_sql($_GET['id'])); // BUG
    $wpdb->query("DELETE FROM t WHERE id IN (" . esc_sql($_POST['ids']) . ")"); // BUG
    $wpdb->query("SELECT * FROM t WHERE a = 'x' AND id = " . esc_sql($_GET['n'])); // BUG
    $wpdb->query($base . " AND id = " . esc_sql($_GET['n'])); // BUG
    $wpdb->get_results("SELECT * FROM t WHERE id>=" . esc_sql($_GET['n'])); // BUG
    $wpdb->get_results("SELECT * FROM t LIMIT " . esc_sql($_GET['n'])); // BUG
}

function dg_through_a_variable($wpdb) {
    $id = esc_sql($_GET['id']);
    $wpdb->query("DELETE FROM t WHERE id = " . $id); // BUG
    // WooCommerce's order items: the ids escaped, joined, put in an unquoted list.
    $ids = esc_sql($_POST['ids']);
    $list = implode(',', $ids);
    $wpdb->get_results("SELECT * FROM t WHERE order_id in ( $list )"); // BUG
    // The list brings its own parentheses.
    $parens = "(" . implode(',', $ids) . ")";
    $wpdb->get_results("SELECT * FROM t WHERE order_id IN " . $parens); // BUG
}

function dg_interpolated($wpdb) {
    $id = esc_sql($_GET['id']);
    $wpdb->query("DELETE FROM t WHERE id = $id"); // BUG
    $wpdb->query("DELETE FROM {$wpdb->prefix}t WHERE id = {$id} LIMIT 1"); // BUG
    $sql = "SELECT * FROM t
        WHERE id = $id"; // BUG
}

function dg_sprintf($wpdb) {
    $wpdb->query(sprintf("DELETE FROM t WHERE id = %s", esc_sql($_GET['id']))); // BUG
    $id = esc_sql($_GET['id']);
    $wpdb->query(sprintf('SELECT * FROM t WHERE id IN (%1$s) LIMIT %2$d', $id, 10)); // BUG
}
