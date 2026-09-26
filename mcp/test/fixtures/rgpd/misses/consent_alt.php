<?php
/**
 * A WordPress theme template in PHP's alternative syntax, asking the WP
 * Consent API before it prints any tracker. NOTHING here may fire (the
 * template-condition guard: `if ( ... consent ... ) : ... endif;`).
 */
?>
<?php if ( function_exists( 'wp_has_consent' ) && wp_has_consent( 'statistics' ) ) : ?>
  <script async src="https://www.googletagmanager.com/gtag/js?id=<?php echo esc_attr( get_option( 'tema_ga_id' ) ); ?>"></script>
  <script>
    (function(h,o,t,j,a,r){
      h.hj=h.hj||function(){(h.hj.q=h.hj.q||[]).push(arguments)};
      h._hjSettings={hjid:1234567,hjsv:6};
      a=o.getElementsByTagName('head')[0];
      r=o.createElement('script');r.async=1;
      r.src=t+h._hjSettings.hjid+j+h._hjSettings.hjsv;
      a.appendChild(r);
    })(window,document,'https://static.hotjar.com/c/hotjar-','.js?sv=');
  </script>
<?php endif; ?>
<?php if ( wp_has_consent( 'marketing' ) ) : ?>
  <script>
    fbq('init', '<?php echo esc_js( get_option( 'tema_pixel_id' ) ); ?>');
  </script>
  <iframe src="https://www.youtube.com/embed/<?php echo esc_attr( $video_id ); ?>"></iframe>
<?php endif; ?>
