/**
 * The `project_path` keys the WordPress tools file their scan rows under, and
 * how a reader finds a row under every spelling it may have been stored with.
 *
 * WordPress rows are keyed by what was looked at: an install root
 * (`wp_audit`, `wp_cron_audit`, `wp_vuln_check_source`, `scan_wordpress`, a
 * path-given `wp_vuln_check`) or a live site's URL (`wp_rest_audit`, a
 * URL-only `wp_vuln_check`). Since Task 24 a path is filed in its canonical
 * spelling and a URL without its trailing slash — but builds up to 2.0.x
 * filed `wp_vuln_check` under the RAW `wp_install_path ?? url` it was given
 * (`./wp`, `/var/www/html/`, `C:/sites/wp`, `https://site.example/`). Those
 * rows are left as they are (no migration); a reader looks them up under the
 * aliases below and keeps the newest row across every key (fix round 1, I3).
 *
 * **A relative path names one install only when it exists here** (fix round
 * 2, controller ruling). `canonicalPath` falls back to a lexical `resolve()`
 * against the SERVER's working directory when `realpath` fails, so two
 * remote installs both passed as `wp` or `./site` shared one key — and one's
 * CVEs were reported as the other's — and a nonexistent path could resolve
 * onto a real, unrelated project. So a `wp_install_path` must be absolute
 * (a remote install described by its server path is its own exact key) or
 * exist locally ({@link wpInstallPathProblem}), and a relative path that does
 * not exist contributes no alias. A legacy row filed under a relative raw key
 * is therefore reachable only while that path exists on this machine.
 */
import { existsSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { findLatestUsable } from '../history/openSet.js';
/** A site URL the way `wp_rest_audit` (and, since Task 24, `wp_vuln_check`) files it. */
export function wpSiteKey(url) {
    return url.replace(/\/$/, '');
}
/**
 * Whether `raw` can name one install: absolute, or existing on this machine.
 * Null when it can; otherwise the message a tool refuses it with.
 */
export function wpInstallPathProblem(raw) {
    if (namesOneInstall(raw))
        return null;
    return (`wp_install_path ${JSON.stringify(raw)} is relative and does not exist on this machine, so it names no ` +
        "single install (resolved against the server's working directory, every remote install passed the same " +
        'way would share one record). Pass the absolute path of the install, or target_url for a remote site.');
}
/**
 * Every key an install root may be filed under: its canonical spelling (what
 * this build writes), the raw path the caller gave, and that path resolved
 * lexically — what an earlier build may have stored, and how. The raw
 * spellings are aliases only when they name one install (absolute, or
 * existing here): a relative path that does not exist is resolved against no
 * one's directory in particular — see the module comment.
 */
export function wpInstallKeys(canonical, raw) {
    const keys = [canonical];
    if (raw !== undefined && raw.length > 0 && namesOneInstall(raw))
        keys.push(raw, resolve(raw));
    return unique(keys);
}
function namesOneInstall(raw) {
    return isAbsolute(raw) || existsSync(raw);
}
/** Every key a site URL may be filed under: without the trailing slash, with it, and as given. */
export function wpSiteKeys(url) {
    const key = wpSiteKey(url);
    return unique([key, `${key}/`, url]);
}
/**
 * The newest usable completed scan of `types` under any of `keys` — one
 * project-scoped query per key, the newest across them in the one order every
 * "latest" query uses (`started_at`, then `rowid`).
 */
export function latestUnderKeys(storage, keys, types, opts = {}) {
    let newest = null;
    for (const key of unique(keys)) {
        const found = findLatestUsable(storage, key, types, opts).scan;
        if (found === null)
            continue;
        if (newest === null || storage.scans.sortNewestFirst([newest.scan_id, found.scan_id])[0] === found.scan_id) {
            newest = found;
        }
    }
    return newest;
}
function unique(keys) {
    return [...new Set(keys)];
}
//# sourceMappingURL=siteKeys.js.map