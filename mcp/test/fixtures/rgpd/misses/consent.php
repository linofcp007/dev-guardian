<?php
/**
 * A WordPress theme that asks the WP Consent API before it loads anything.
 * NOTHING here may fire (the consent-block guard).
 */

function tema_scripts(): void
{
    if (function_exists('wp_has_consent') && wp_has_consent('statistics')) {
        wp_enqueue_script('gtag', 'https://www.googletagmanager.com/gtag/js?id=' . get_option('tema_ga_id'), [], null, false);
    }
}
add_action('wp_enqueue_scripts', 'tema_scripts');

function tema_video(string $id): string
{
    // privacy-enhanced mode
    return '<iframe src="https://www.youtube-nocookie.com/embed/' . esc_attr($id) . '"></iframe>';
}
