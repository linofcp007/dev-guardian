<?php
/**
 * Plugin Name: DG Test
 * Description: Deliberately vulnerable: the Psalm e2e fixture (test/e2e/psalmSast.test.ts).
 */
add_action('init', 'dg_init');
function dg_init() {
    global $wpdb;
    $wpdb->query("DELETE FROM {$wpdb->prefix}t WHERE id = {$_GET['id']}");
    $wpdb->query($wpdb->prepare("DELETE FROM t WHERE id = %d", $_GET['id2']));
    $wpdb->get_results("SELECT * FROM t WHERE n = '" . esc_sql($_GET['n']) . "'");
    $wpdb->get_var("SELECT c FROM t WHERE n = '" . $_POST['raw'] . "'");
}
add_action('admin_notices', function () {
    echo $_GET['x'];
    echo esc_html($_GET['y']);
    echo esc_attr($_GET['z']);
    echo wp_unslash($_GET['u']);
    echo '<textarea>' . esc_textarea($_GET['t']) . '</textarea>';
    echo '<a href="' . esc_url($_GET['l']) . '">x</a>';
    echo absint($_GET['n']);
});
add_action('wp_ajax_dg', 'dg_ajax');
function dg_ajax() {
    $data = maybe_unserialize(wp_unslash($_POST['blob']));
    wp_remote_get($_GET['url']);
    system($_REQUEST['cmd']);
}
