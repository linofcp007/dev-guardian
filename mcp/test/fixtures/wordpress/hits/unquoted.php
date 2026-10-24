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
