---
description: WordPress audit — source scan, vulnerabilities from source or a live URL, live-install checks and hardening. Foco WordPress. Foco WordPress.
argument-hint: "[WordPress install path or site URL]"
---

Run the WordPress-focused flow. Use it for a WP site, plugin or theme — `detect_stack { project_path: "<project>" }` reports WordPress even without a `composer.json` (by `wp-config.php`, `wp-content/` or a plugin/theme header).

The argument is a local install path (the directory holding `wp-config.php`), a live URL, or nothing (the source tree only).

Arguments: $ARGUMENTS

1. **Source**: `scan_wordpress { project_path: "<project>", standard: "WordPress" }` — Semgrep PHP with the WP rule pack, Trivy on `composer.lock`, gitleaks, and PHPCS with the WordPress standard (`WordPress-Extra`, `WordPress-VIP-Go` or `WordPress-Core` on request). A scanner that is missing is skipped with a reason.
2. **Vulnerabilities, no live site needed**: `wp_vuln_check_source { project_path: "<install root>" }` — core, plugin and theme versions read from disk and matched against the Wordfence Intelligence feed (needs `WORDFENCE_API_KEY`; without it, or offline, coverage is `partial` with the reason), plus wp.org's check for closed or abandoned plugins. `project_path` is the install root (`wp-includes/`, `wp-content/`), not a single plugin directory.
3. **Live install**, when a path is given (needs WP-CLI):
   - `wp_audit { wp_install_path: "<path>" }` — core/plugin/theme checksums, admin users, `WP_DEBUG` / `DISALLOW_FILE_EDIT` / `FORCE_SSL_ADMIN`;
   - `wp_cron_audit { wp_install_path: "<path>" }` — scheduled events, where persistent backdoors usually live;
   - `wp_plugin_check { slug: "<plugin slug>", wp_install_path: "<path>" }` for a plugin the user worries about — its installed version and state (WP-CLI) and the CVEs steps 2 and 4 already recorded. It queries nothing online itself, so run it after them; a WP-CLI probe that did not answer is a warning and coverage `partial`, not "not installed".
4. **Live site**, when a URL is given:
   - `wp_vuln_check { target_url: "<url>" }` — WPScan (a token in `WPSCAN_API_TOKEN` avoids the public rate limit);
   - `wp_rest_audit { target_url: "<url>" }` — read-only GETs against REST endpoints that commonly leak (user enumeration, drafts, comments, `xmlrpc.php`).
5. **Hardening**: `wp_recommend_hardening { project_path: "<install root>" }` turns that install's latest `wp_audit` into a prioritised, copy-pasteable checklist; `wp_describe_setup { project_path: "<install root>", target_url: "<url>" }` summarises everything gathered so far. The install root is the path given, else `<project>`; pass `target_url` only when a URL was given — the live-site results are filed under it. Both answer only for the project and site they are given.
6. Several installs at once: `bulk_audit_wordpress_sites { wp_install_paths: ["<path>"] }`.

When WP-CLI, WPScan or PHPCS are missing, run what is available, list what was skipped, and offer `install_toolchain { tools: ["wp-cli", "wpscan", "phpcs"], dry_run: true }` first.

Respond in the user's language (EN/PT/ES).
