/**
 * Reading a small file that a project or a user controls — the hooks'
 * `.guardian/hooks.config.json`, `.guardian/hooks-allowlist.json` and
 * `~/.config/dev-guardian/hooks.json`, and the registry configuration the
 * install hook consults (`.npmrc`, `package.json`, `pip.conf`, …).
 *
 * Every one of those reads runs synchronously inside a hook that Claude Code
 * kills after 15 s, and a hook that dies lets the tool call through. The
 * reader this replaced did `existsSync` and then `readFileSync`, with no check
 * on WHAT the path was: `mkfifo .guardian/hooks.config.json` blocked the read
 * forever, `ln -s /dev/zero .guardian/hooks.config.json` read without end, and
 * a 300 MB file took 23 s on Windows — each one the whole guard switched off
 * by making it time out (Task 23 fix round 2, N1).
 *
 * So: `statSync` first — it follows a symlink, so it sees the TARGET — and read
 * only a regular file no larger than the cap. Anything else is `refused`, which
 * the hook treats as absent (the protective defaults) and names in its
 * SessionStart notice. A leading UTF-8 byte-order mark (PowerShell 5 writes
 * one) is stripped before parsing.
 *
 * Pure `node:` built-ins, no other import: the hook dispatcher loads the
 * compiled copy from `mcp/dist/hooks/` in an install with no `node_modules`.
 */
import { readFileSync, statSync } from 'node:fs';
/** The largest hook configuration file the hooks will read. */
export const MAX_HOOK_CONFIG_BYTES = 64 * 1024;
function readText(path, maxBytes) {
    let size;
    try {
        const st = statSync(path);
        if (!st.isFile())
            return { status: 'refused', reason: 'not-a-regular-file' };
        size = st.size;
    }
    catch (e) {
        const code = e.code;
        // A dangling symlink is ENOENT too: nothing there to read.
        if (code === 'ENOENT' || code === 'ENOTDIR')
            return { status: 'absent' };
        return { status: 'refused', reason: 'unreadable' };
    }
    if (size > maxBytes)
        return { status: 'refused', reason: 'too-large' };
    let buf;
    try {
        buf = readFileSync(path);
    }
    catch {
        return { status: 'refused', reason: 'unreadable' };
    }
    // The file grew between the stat and the read: still refused, never trusted.
    if (buf.length > maxBytes)
        return { status: 'refused', reason: 'too-large' };
    let text = buf.toString('utf8');
    if (text.charCodeAt(0) === 0xfeff)
        text = text.slice(1);
    return { status: 'ok', text };
}
/** A small JSON file, parsed — or why it was not. See the module doc. */
export function readSmallJsonFile(path, maxBytes = MAX_HOOK_CONFIG_BYTES) {
    const r = readText(path, maxBytes);
    if (r.status !== 'ok')
        return r;
    try {
        return { status: 'ok', value: JSON.parse(r.text) };
    }
    catch {
        return { status: 'invalid' };
    }
}
/** A small text file's content, or `undefined` for anything else. */
export function readSmallTextFile(path, maxBytes) {
    const r = readText(path, maxBytes);
    return r.status === 'ok' ? r.text : undefined;
}
//# sourceMappingURL=configFile.js.map