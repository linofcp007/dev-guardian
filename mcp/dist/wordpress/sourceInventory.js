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
 *
 * ## The install is hostile input (review of 3.0, W2E)
 *
 * Every read stays inside the install and goes through
 * `platform/projectFs.ts`: a `version.php` linked to `/dev/zero` OOM-killed
 * the MCP server. What was there and could not be inventoried is never a
 * clean result:
 *
 *   - a file that was not read (a link out of the install, a FIFO, a file
 *     past the inventory's read budget) is a warning naming it and why;
 *   - a directory under `wp-content/plugins`, `themes` or `mu-plugins`, or
 *     one of those three itself, that is a link out of the install, cannot
 *     be listed or is not a directory is in `not_inventoried`, and
 *     `wp_vuln_check_source` reports partial coverage for it. A link that
 *     STAYS inside the install is followed: a `wp-content/plugins` linked to
 *     a shared directory in the same tree used to read as "0 plugins", and
 *     the Wordfence match then read clean (Akismet was inventoried on
 *     e27a37ae; the conversion to `listProjectDir` dropped it).
 *
 * Reads are bounded per file (a header's first 8 KiB) and for the whole
 * inventory ({@link INVENTORY_BUDGET_BYTES} / {@link INVENTORY_BUDGET_FILES}).
 */
import { join, relative, sep } from 'node:path';
import { describeReadRefusal, listProjectDirOrNull, presentInProject, projectPathKind, ReadBudget, } from '../platform/projectFs.js';
/** A plugin's or theme's main file header is always near the top; bounding
 *  the read keeps a pathologically large file from being read in full. */
const MAX_HEADER_BYTES = 8192;
/** `readme.txt` files can run long (changelog, FAQ); `Stable tag:` is always
 *  in the header block near the top. */
const MAX_README_BYTES = 16384;
/** `wp-includes/version.php` is a few KB; `$wp_version` sits near its top. */
const MAX_VERSION_PHP_BYTES = 64 * 1024;
/** What one inventory may read in all: a large site has a few thousand plugin files, each read for 8 KiB. */
export const INVENTORY_BUDGET_BYTES = 64 * 1024 * 1024;
export const INVENTORY_BUDGET_FILES = 20_000;
function relOf(src, abs) {
    return relative(src.root, abs).split(sep).join('/');
}
function noteUnread(src, abs, why) {
    const rel = relOf(src, abs);
    if (!src.unread.has(rel))
        src.unread.set(rel, why);
}
/** The first `maxBytes` bytes of `path`, within the budget — or null, naming why when it was there. */
function read(src, path, maxBytes) {
    const r = src.budget.readHead(src.root, path, maxBytes);
    if (r.status === 'ok')
        return r.text;
    if (r.status === 'refused')
        noteUnread(src, path, describeReadRefusal(r.reason));
    return null;
}
function kindOf(src, abs, e) {
    if (e.kind === 'directory')
        return 'directory';
    if (e.kind === 'file')
        return 'file';
    if (e.kind === 'other')
        return 'unreachable';
    const k = projectPathKind(src.root, abs);
    if (k === 'directory' || k === 'file' || k === 'absent')
        return k;
    return 'unreachable';
}
/**
 * The entries of `dir` — or null, naming it, when something is there and it
 * could not be listed (a link out of the install, not a directory). Absent:
 * `[]`, nothing to name.
 */
function listDir(src, dir) {
    const entries = listProjectDirOrNull(src.root, dir);
    if (entries !== null)
        return entries;
    if (!presentInProject(src.root, dir))
        return [];
    const kind = projectPathKind(src.root, dir);
    noteUnread(src, dir, kind === 'outside'
        ? 'a link out of the install (or to a network or device path), not followed — not inventoried'
        : kind === 'file' || kind === 'other'
            ? 'not a directory — not inventoried'
            : 'this directory could not be listed — not inventoried');
    return null;
}
export function inventoryWordPressSource(wpPath) {
    const warnings = [];
    const src = { root: wpPath, budget: new ReadBudget(INVENTORY_BUDGET_BYTES, INVENTORY_BUDGET_FILES), unread: new Map() };
    const coreVersion = readCoreVersion(src);
    if (coreVersion === null) {
        warnings.push('wp-includes/version.php not found or unparsable under the given path — core version unknown.');
    }
    const plugins = inventoryPlugins(src, warnings);
    const themes = inventoryThemes(src, warnings);
    const muPlugins = inventoryMuPlugins(src, warnings);
    const notInventoried = [];
    for (const [rel, why] of src.unread) {
        warnings.push(`${rel}: not read — ${why}.`);
        // The core version file has its own warning, and matters to no component.
        if (rel !== 'wp-includes/version.php')
            notInventoried.push(rel);
    }
    return {
        core: { version: coreVersion },
        plugins,
        themes,
        mu_plugins: muPlugins,
        not_inventoried: notInventoried.sort(),
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
function readCoreVersion(src) {
    const text = read(src, join(src.root, 'wp-includes', 'version.php'), MAX_VERSION_PHP_BYTES);
    if (text === null)
        return null;
    const m = /\$wp_version\s*=\s*'([^']+)'/.exec(text);
    return m?.[1] ?? null;
}
function inventoryPlugins(src, warnings) {
    const pluginsDir = join(src.root, 'wp-content', 'plugins');
    const out = [];
    for (const entry of listDir(src, pluginsDir) ?? []) {
        const abs = join(pluginsDir, entry.name);
        const kind = kindOf(src, abs, entry);
        if (kind === 'directory') {
            const main = findMainFile(src, abs, entry.name, 'Plugin Name');
            if (main === null) {
                warnings.push(`wp-content/plugins/${entry.name}: no file with a "Plugin Name:" header — skipped.`);
                continue;
            }
            const text = read(src, main, MAX_HEADER_BYTES) ?? '';
            const stableTag = readStableTag(src, join(abs, 'readme.txt'));
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
        else if (kind === 'unreachable') {
            noteUnread(src, abs, 'a link out of the install, to a network or device path, or not a regular file or directory — not inventoried');
        }
        else if (kind === 'file' && entry.name.toLowerCase().endsWith('.php')) {
            const text = read(src, abs, MAX_HEADER_BYTES);
            if (text === null || !hasHeader(text, 'Plugin Name'))
                continue;
            const version = extractHeader(text, 'Version');
            if (version === null)
                warnUnversioned(warnings, `wp-content/plugins/${entry.name}`, undefined);
            out.push({
                slug: entry.name.slice(0, -'.php'.length),
                name: extractHeader(text, 'Plugin Name'),
                version,
                path: abs,
            });
        }
    }
    return out;
}
function inventoryThemes(src, warnings) {
    const themesDir = join(src.root, 'wp-content', 'themes');
    const out = [];
    for (const entry of listDir(src, themesDir) ?? []) {
        const abs = join(themesDir, entry.name);
        const kind = kindOf(src, abs, entry);
        if (kind === 'unreachable') {
            noteUnread(src, abs, 'a link out of the install, to a network or device path, or not a regular file or directory — not inventoried');
            continue;
        }
        if (kind !== 'directory')
            continue;
        const styleCssPath = join(abs, 'style.css');
        const text = read(src, styleCssPath, MAX_HEADER_BYTES);
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
function inventoryMuPlugins(src, warnings) {
    const muDir = join(src.root, 'wp-content', 'mu-plugins');
    const out = [];
    for (const entry of listDir(src, muDir) ?? []) {
        if (!entry.name.toLowerCase().endsWith('.php') || entry.kind === 'directory')
            continue;
        const filePath = join(muDir, entry.name);
        const text = read(src, filePath, MAX_HEADER_BYTES);
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
            const targetText = read(src, targetPath, MAX_HEADER_BYTES);
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
 * in directory order. A link or a FIFO under a `*.php` name is tried too —
 * read if it stays inside the install, else named. Returns null when none
 * carries the header.
 */
function findMainFile(src, dir, dirName, nameHeader) {
    const candidates = (listDir(src, dir) ?? []).filter((e) => e.kind !== 'directory' && e.name.toLowerCase().endsWith('.php'));
    const preferredName = `${dirName.toLowerCase()}.php`;
    const preferred = candidates.find((e) => e.name.toLowerCase() === preferredName);
    const ordered = preferred ? [preferred, ...candidates.filter((e) => e !== preferred)] : candidates;
    for (const entry of ordered) {
        const path = join(dir, entry.name);
        const text = read(src, path, MAX_HEADER_BYTES);
        if (text !== null && hasHeader(text, nameHeader))
            return path;
    }
    return null;
}
function readStableTag(src, readmePath) {
    const text = read(src, readmePath, MAX_README_BYTES);
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