/**
 * Claude Code's own settings can switch every dev-guardian hook off without
 * touching dev-guardian's configuration: `"disableAllHooks": true` in
 * `.claude/settings.json` / `.claude/settings.local.json` (project or user
 * level), an `env` block that sets the hook dispatcher's own switches —
 * `GUARDIAN_HOOKS=off`, `GUARDIAN_HOOKS_BASH_BLOCK=0|false`,
 * `GUARDIAN_PKG_VET=0` — or an `enabledPlugins` entry that turns the plugin
 * itself off (`"dev-guardian@<marketplace>": false`, follow-up Part Y). An
 * assistant writes those files routinely (to allow a
 * command, say), so the Write/Edit guard cannot refuse them wholesale. It
 * refuses exactly one thing: an edit whose RESULT sets one of those keys that
 * the file did not already set (final review M5). A key the user already set
 * stays set through any later edit; anything else — permissions, other env
 * vars, other hooks — is never refused.
 *
 * Pure functions, `node:` built-ins only: the hook dispatcher loads the
 * compiled copy from `mcp/dist/hooks/` in an install with no `node_modules`.
 */
/** `.claude/settings.json` or `.claude/settings.local.json`, anywhere. */
export function isClaudeSettingsPath(path) {
    return /(?:^|[\\/])\.claude[\\/]settings(?:\.local)?\.json$/i.test(path);
}
/** The env switches the dispatcher reads, and the values that turn a hook off. */
const ENV_SWITCHES = [
    { name: 'GUARDIAN_HOOKS', off: ['off'] },
    { name: 'GUARDIAN_HOOKS_BASH_BLOCK', off: ['0', 'false'] },
    { name: 'GUARDIAN_PKG_VET', off: ['0'] },
];
function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
/** A plugin id that names dev-guardian, under any marketplace (`dev-guardian@<marketplace>`). */
const OUR_PLUGIN = /dev-guardian/i;
/** From parsed settings. Env names match case-insensitively (Windows env is). */
function fromObject(settings) {
    const found = [];
    if (settings['disableAllHooks'] === true)
        found.push('disableAllHooks: true');
    const env = settings['env'];
    if (isPlainObject(env)) {
        for (const [key, value] of Object.entries(env)) {
            const sw = ENV_SWITCHES.find((s) => s.name === key.toUpperCase());
            if (sw !== undefined && sw.off.includes(String(value)))
                found.push(`env ${sw.name}=${String(value)}`);
        }
    }
    const plugins = settings['enabledPlugins'];
    if (isPlainObject(plugins)) {
        for (const [id, enabled] of Object.entries(plugins)) {
            if (enabled === false && OUR_PLUGIN.test(id))
                found.push(`enabledPlugins ${id}=false`);
        }
    }
    return found;
}
/**
 * The same settings, by pattern, for text that is not a JSON object (JSONC,
 * or a fragment of an edit that could not be applied). The labels match
 * {@link fromObject}'s, so the two can be compared.
 */
const TEXT_PATTERNS = [
    { label: 'disableAllHooks: true', re: /"disableAllHooks"\s*:\s*true\b/ },
    { label: 'env GUARDIAN_HOOKS=off', re: /"GUARDIAN_HOOKS"\s*:\s*"off"/i },
    { label: 'env GUARDIAN_HOOKS_BASH_BLOCK=0', re: /"GUARDIAN_HOOKS_BASH_BLOCK"\s*:\s*(?:"0"|0\b)/i },
    { label: 'env GUARDIAN_HOOKS_BASH_BLOCK=false', re: /"GUARDIAN_HOOKS_BASH_BLOCK"\s*:\s*(?:"false"|false\b)/i },
    { label: 'env GUARDIAN_PKG_VET=0', re: /"GUARDIAN_PKG_VET"\s*:\s*(?:"0"|0\b)/i },
];
/**
 * An `enabledPlugins` entry turning dev-guardian off, by pattern: a quoted key
 * naming dev-guardian set to `false`. In a Claude Code settings file only
 * `enabledPlugins` has such keys, and an edit fragment may not show the
 * `enabledPlugins` around it.
 */
const PLUGIN_OFF = /"([^"\n]*dev-guardian[^"\n]*)"\s*:\s*false\b/gi;
function fromText(text) {
    const found = TEXT_PATTERNS.filter((p) => p.re.test(text)).map((p) => p.label);
    for (const m of text.matchAll(PLUGIN_OFF))
        found.push(`enabledPlugins ${m[1] ?? ''}=false`);
    return found;
}
/**
 * The hook-loosening settings `content` sets, as labels (`disableAllHooks:
 * true`, `env GUARDIAN_PKG_VET=0`, …). Parsed as JSON when it is a JSON
 * object (a leading byte-order mark allowed), matched by pattern otherwise.
 */
export function hookLooseningSettings(content) {
    const text = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
    try {
        const parsed = JSON.parse(text);
        if (isPlainObject(parsed))
            return fromObject(parsed);
    }
    catch {
        /* not JSON: fall through to the patterns */
    }
    return fromText(text);
}
/** The loosening settings `after` sets that `before` did not. `before` undefined = a new file. */
export function newlyLoosened(before, after) {
    const had = new Set(before === undefined ? [] : hookLooseningSettings(before));
    return hookLooseningSettings(after).filter((label) => !had.has(label));
}
/**
 * Claude Code's Edit applied to `content`: `oldString` replaced by `newString`
 * (every occurrence with `replaceAll`). `undefined` when `oldString` is not
 * there, i.e. the edit cannot be reproduced.
 */
export function applyEdit(content, oldString, newString, replaceAll = false) {
    if (oldString === '')
        return undefined;
    if (replaceAll)
        return content.includes(oldString) ? content.split(oldString).join(newString) : undefined;
    const at = content.indexOf(oldString);
    return at < 0 ? undefined : content.slice(0, at) + newString + content.slice(at + oldString.length);
}
//# sourceMappingURL=settingsGuard.js.map