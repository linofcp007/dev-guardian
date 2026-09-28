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
  <?php if ( is_front_page() ) : ?>
  <!-- BUG rgpd-youtube-embed-without-nocookie: a template condition, but not a consent one -->
  <iframe src="https://www.youtube.com/embed/apresentacao"></iframe>
  <?php endif; ?>
  <?php if ( ! wp_has_consent( 'marketing' ) ) : ?>
  <!-- BUG rgpd-youtube-embed-without-nocookie: a NEGATED consent condition -->
  <iframe src="https://www.youtube.com/embed/sem-consentimento"></iframe>
  <?php endif; ?>
  <?php if ( wp_has_consent( 'marketing' ) ) : ?>
  <!-- excluded: the THEN arm is guarded, beside the bug below -->
  <iframe src="https://www.youtube.com/embed/com-consentimento"></iframe>
  <?php else : ?>
  <!-- BUG rgpd-youtube-embed-without-nocookie: the ELSE arm of a consent condition -->
  <iframe src="https://www.youtube.com/embed/no-else"></iframe>
  <?php endif; ?>
  <?php wp_head(); ?>
</head>
