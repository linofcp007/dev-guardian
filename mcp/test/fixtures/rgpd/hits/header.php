<?php
/**
 * A WordPress theme loading trackers unconditionally. Every `BUG` fires its
 * rule exactly once.
 */

function tema_scripts(): void
{
    // BUG rgpd-tracker-ga4-without-consent: enqueued on every page
    wp_enqueue_script('gtag', 'https://www.googletagmanager.com/gtag/js?id=' . get_option('tema_ga_id'), [], null, false);
}
add_action('wp_enqueue_scripts', 'tema_scripts');

function tema_video(string $id): string
{
    // BUG rgpd-youtube-embed-without-nocookie
    return '<iframe width="560" height="315" src="https://www.youtube.com/embed/' . esc_attr($id) . '"></iframe>';
}
?>
<!doctype html>
<html <?php language_attributes(); ?>>
<head>
  <!-- BUG rgpd-tracker-ga4-without-consent -->
  <script async src="https://www.googletagmanager.com/gtag/js?id=<?php echo esc_attr(get_option('tema_ga_id')); ?>"></script>
  <script>
    fbq('init', '<?php echo esc_js(get_option('tema_pixel_id')); ?>'); // BUG rgpd-tracker-meta-pixel-without-consent
  </script>
  <?php wp_head(); ?>
</head>
