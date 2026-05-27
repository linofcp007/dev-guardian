---
description: WordPress-focused audit (wp_audit + wp_vuln_check + scan_wordpress). Foco WordPress. Foco WordPress.
---

Run the **WordPress-focused** Guardian flow. Use when the project is a WP site, plugin, theme, or any codebase with `wp-config.php` / `composer.json` referencing WP.

The skill should invoke, in order:
1. `scan_wordpress` — source-side scan (Semgrep PHP + `p/wordpress` rule pack + Trivy on `composer.lock` + gitleaks + PHPCS-WPCS).
2. `wp_audit` — if a live WP install path is provided, checksum core/plugins/themes, list admins, check `WP_DEBUG` / `DISALLOW_FILE_EDIT` / `FORCE_SSL_ADMIN`.
3. `wp_vuln_check` — query WPScan's DB for known vulns in the installed plugins/themes/core.
4. `wp_plugin_check`, `wp_rest_audit`, `wp_cron_audit` for deeper surface coverage.
5. `wp_recommend_hardening` — concrete, copy-pasteable hardening tips.

If WP-CLI / WPScan / PHPCS are missing, run what is available and explicitly list the skipped tools with install instructions (offer `install_toolchain`).

Live-install path (optional, e.g. `/var/www/html`): $ARGUMENTS
