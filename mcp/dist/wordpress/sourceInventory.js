/**
 * `wp_vuln_check_source`'s inventory pass — reads a local WordPress install
 * and reports what is actually on disk: no live URL, no WP-CLI, no shell.
 * Task 15's `runners/stackDetect.ts` already detects WordPress from these
 * same files (`wp-config.php`, `wp-content/`, a theme's `style.css` header,
 * a plugin's own header) but only ever asks "is this WordPress?" — never
 * "which version?". This module reuses its bounded, exception-safe file
 * reads ({@link readDirSafe}, {@link readTextSafe}, re-exported from there)
 * and adds the header-VALUE extraction stackDetect never needed.
 *
 * Three sources, in the order the design brief lists them:
 *   1. Core: `wp-includes/version.php`'s `$wp_version = '...'`.
 *   2. Plugins: `wp-content/plugins/<slug>/`'s main file header (`Plugin
 *      Name:`, `Version:`), falling back to the same directory's
 *      `readme.txt` `Stable tag:` when the main file has no `Version:` —
 *      some plugins only ever state it there. `Stable tag: trunk` is wp.org's
 *      own convention for "this plugin's stable release tracks its dev
 *      trunk", not a version number, so it is recorded but never used as one.
 *      A single-file plugin directly under `wp-content/plugins/*.php` is
 *      also read (WordPress supports both layouts).
 *   3. Themes: `wp-content/themes/<slug>/style.css`'s `Theme Name:` /
 *      `Version:` header — always at that exact path, parent and child
 *      themes alike.
 */
import { join } from 'node:path';
import { readDirSafe, readTextSafe } from '../runners/stackDetect.js';
/** A plugin's or theme's main file header is always near the top; bounding
 *  the read keeps a pathologically large file from being read in full. */
const MAX_HEADER_BYTES = 8192;
/** `readme.txt` files can run long (changelog, FAQ); `Stable tag:` is always
 *  in the header block near the top. */
const MAX_README_BYTES = 16384;
export function inventoryWordPressSource(wpPath) {
    const warnings = [];
    const coreVersion = readCoreVersion(wpPath);
    if (coreVersion === null) {
        warnings.push('wp-includes/version.php not found or unparsable under the given path — core version unknown.');
    }
    return {
        core: { version: coreVersion },
        plugins: inventoryPlugins(wpPath, warnings),
        themes: inventoryThemes(wpPath, warnings),
        mu_plugins: inventoryMuPlugins(wpPath, warnings),
        warnings,
    };
}
/** A component whose main file was found but carries no usable version —
 *  pushed once per component, at the point each inventory function already
 *  knows the file existed and was readable. */
function warnUnversioned(warnings, label, stableTag) {
    const stableTagNote = stableTag === undefined
        ? ''
        : stableTag === null
            ? ' (no readme.txt Stable tag either)'
            : ` (readme.txt's Stable tag is "${stableTag}", not a usable version)`;
    warnings.push(`${label}: version unknown — no Version: header${stableTagNote}. Cannot be matched against a vulnerability feed.`);
}
function readCoreVersion(wpPath) {
    const text = readTextSafe(join(wpPath, 'wp-includes', 'version.php'));
    if (text === null)
        return null;
    const m = /\$wp_version\s*=\s*'([^']+)'/.exec(text);
    return m?.[1] ?? null;
}
function inventoryPlugins(wpPath, warnings) {
    const pluginsDir = join(wpPath, 'wp-content', 'plugins');
    const out = [];
    for (const entry of readDirSafe(pluginsDir)) {
        if (entry.isDirectory()) {
            const dir = join(pluginsDir, entry.name);
            const main = findMainFile(dir, entry.name, 'Plugin Name');
            if (main === null) {
                warnings.push(`wp-content/plugins/${entry.name}: no file with a "Plugin Name:" header — skipped.`);
                continue;
            }
            const text = readTextSafe(main, MAX_HEADER_BYTES) ?? '';
            const stableTag = readStableTag(join(dir, 'readme.txt'));
            const headerVersion = extractHeader(text, 'Version');
            const version = headerVersion ?? usableVersion(stableTag);
            const component = {
                slug: entry.name,
                name: extractHeader(text, 'Plugin Name'),
                version,
                path: main,
            };
            if (stableTag !== null)
                component.stable_tag = stableTag;
            if (version === null)
                warnUnversioned(warnings, `wp-content/plugins/${entry.name}`, stableTag);
            out.push(component);
        }
        else if (entry.isFile() && entry.name.toLowerCase().endsWith('.php')) {
            const filePath = join(pluginsDir, entry.name);
            const text = readTextSafe(filePath, MAX_HEADER_BYTES);
            if (text === null || !hasHeader(text, 'Plugin Name'))
                continue;
            const version = extractHeader(text, 'Version');
            if (version === null)
                warnUnversioned(warnings, `wp-content/plugins/${entry.name}`, undefined);
            out.push({
                slug: entry.name.slice(0, -'.php'.length),
                name: extractHeader(text, 'Plugin Name'),
                version,
                path: filePath,
            });
        }
    }
    return out;
}
function inventoryThemes(wpPath, warnings) {
    const themesDir = join(wpPath, 'wp-content', 'themes');
    const out = [];
    for (const entry of readDirSafe(themesDir)) {
        if (!entry.isDirectory())
            continue;
        const styleCssPath = join(themesDir, entry.name, 'style.css');
        const text = readTextSafe(styleCssPath, MAX_HEADER_BYTES);
        if (text === null || !hasHeader(text, 'Theme Name')) {
            warnings.push(`wp-content/themes/${entry.name}: no readable style.css with a "Theme Name:" header — skipped.`);
            continue;
        }
        const version = extractHeader(text, 'Version');
        if (version === null)
            warnUnversioned(warnings, `wp-content/themes/${entry.name}`, undefined);
        out.push({
            slug: entry.name,
            name: extractHeader(text, 'Theme Name'),
            version,
            path: styleCssPath,
        });
    }
    return out;
}
/** `require __DIR__ . '/sub-dir/sub-dir.php';` (also `require_once`,
 *  `include`, `include_once`; `dirname(__FILE__)`, `WPMU_PLUGIN_DIR` or
 *  `WP_PLUGIN_DIR` in place of `__DIR__`) — the standard workaround for
 *  WordPress only auto-loading TOP-LEVEL `.php` files under
 *  `wp-content/mu-plugins/`: real plugin code lives one directory down, and
 *  a tiny top-level "loader" file requires it in. Captures the subfolder
 *  name and the required file's basename; permissive on purpose (matches
 *  several common phrasings) rather than parsing PHP. */
const MU_PLUGIN_LOADER_RE = /(?:require|include)(?:_once)?\s*\(?\s*(?:__DIR__|dirname\s*\(\s*__FILE__\s*\)|WPMU_PLUGIN_DIR|WP_PLUGIN_DIR)\s*\.\s*['"]\/?([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+\.php)['"]/gi;
/**
 * Must-use plugins: `wp-content/mu-plugins/`, always active, never listed
 * on wp.org. Two shapes, both real in the wild:
 *   1. A top-level `.php` file with its own `Plugin Name:` header — WP's
 *      mu-plugins listing reads these the same way as regular plugins.
 *   2. A top-level "loader" file with NO header of its own, whose body
 *      `require`s a file in a subfolder ({@link MU_PLUGIN_LOADER_RE}) — the
 *      subfolder holds the real plugin, keyed by ITS directory name.
 * A loader naming a file that does not exist, or that has no header itself,
 * contributes nothing (never throws) — the file may be a helper, or the
 * subfolder simply is not there yet.
 */
function inventoryMuPlugins(wpPath, warnings) {
    const muDir = join(wpPath, 'wp-content', 'mu-plugins');
    const out = [];
    for (const entry of readDirSafe(muDir)) {
        if (!entry.isFile() || !entry.name.toLowerCase().endsWith('.php'))
            continue;
        const filePath = join(muDir, entry.name);
        const text = readTextSafe(filePath, MAX_HEADER_BYTES);
        if (text === null)
            continue;
        if (hasHeader(text, 'Plugin Name')) {
            const slug = entry.name.slice(0, -'.php'.length);
            const version = extractHeader(text, 'Version');
            if (version === null)
                warnUnversioned(warnings, `wp-content/mu-plugins/${entry.name}`, undefined);
            out.push({
                slug,
                name: extractHeader(text, 'Plugin Name'),
                version,
                path: filePath,
            });
            continue;
        }
        for (const match of text.matchAll(MU_PLUGIN_LOADER_RE)) {
            const subDir = match[1];
            const subFile = match[2];
            if (subDir === undefined || subFile === undefined)
                continue;
            const targetPath = join(muDir, subDir, subFile);
            const targetText = readTextSafe(targetPath, MAX_HEADER_BYTES);
            if (targetText === null || !hasHeader(targetText, 'Plugin Name'))
                continue;
            const version = extractHeader(targetText, 'Version');
            if (version === null)
                warnUnversioned(warnings, `wp-content/mu-plugins/${subDir}`, undefined);
            out.push({
                slug: subDir,
                name: extractHeader(targetText, 'Plugin Name'),
                version,
                path: targetPath,
            });
        }
    }
    return out;
}
/**
 * The plugin's main file: the top-level `*.php` file whose docblock carries
 * `nameHeader`. `<dirName>.php` is tried first (the overwhelmingly common
 * convention) so a helper file that happens to sort earlier alphabetically
 * never wins by accident; every other top-level `*.php` file is tried next,
 * in directory order. Returns null when none carries the header.
 */
function findMainFile(dir, dirName, nameHeader) {
    const candidates = readDirSafe(dir).filter((e) => e.isFile() && e.name.toLowerCase().endsWith('.php'));
    const preferredName = `${dirName.toLowerCase()}.php`;
    const preferred = candidates.find((e) => e.name.toLowerCase() === preferredName);
    const ordered = preferred ? [preferred, ...candidates.filter((e) => e !== preferred)] : candidates;
    for (const entry of ordered) {
        const path = join(dir, entry.name);
        const text = readTextSafe(path, MAX_HEADER_BYTES);
        if (text !== null && hasHeader(text, nameHeader))
            return path;
    }
    return null;
}
function readStableTag(readmePath) {
    const text = readTextSafe(readmePath, MAX_README_BYTES);
    if (text === null)
        return null;
    const value = extractHeader(text, 'Stable tag');
    return value;
}
/** `Stable tag: trunk` names wp.org's dev branch, not a released version. */
function usableVersion(stableTag) {
    if (stableTag === null)
        return null;
    return /^trunk$/i.test(stableTag) ? null : stableTag;
}
/**
 * WordPress core's own file-header convention (`get_file_data()`): a line
 * starting with optional comment markers (`* `, `// `, `# `, `@`), then the
 * header name, a colon, and the value to end of line. Reused here for
 * `Plugin Name:` / `Theme Name:` / `Version:` (plugin & theme files) and, on
 * `readme.txt`, `Stable tag:` — the same "key: value" shape, no block
 * comment involved there, so the trailing-comment cleanup below is just a
 * no-op for it.
 */
function hasHeader(text, name) {
    return headerRegex(name).test(text);
}
function extractHeader(text, name) {
    const m = headerRegex(name).exec(text);
    if (!m)
        return null;
    const cleaned = (m[1] ?? '')
        .trim()
        .replace(/\*\/\s*$/, '')
        .replace(/\?>\s*$/, '')
        .trim();
    return cleaned.length > 0 ? cleaned : null;
}
function headerRegex(name) {
    // Header names used here are fixed string literals we control (never user
    // input), so no regex-escaping is needed.
    return new RegExp(`^[ \\t/*#@]*${name}:(.*)$`, 'im');
}
//# sourceMappingURL=sourceInventory.js.map