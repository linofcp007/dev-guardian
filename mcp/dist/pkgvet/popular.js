/**
 * Loads the committed popular-packages lists
 * (`configs/popular-packages/<ecosystem>.txt`) — one name per line, `#`
 * comments. How they are generated, from what source and when, is in that
 * directory's README.
 *
 * Two callers locate the directory two ways, deliberately:
 *
 *   - the MCP server resolves `configs/` through `resolveConfigsDir()`,
 *     which probes for the bundled (`dist/server.js`) and unbundled
 *     (`dist/pkgvet/*.js`, `src/pkgvet/*.ts`) layouts alike;
 *   - the hook passes the directory explicitly, computed from its own
 *     location (`<plugin>/hooks/..`), because it knows the plugin root
 *     without probing.
 *
 * A list that cannot be read returns `null`, and the caller reports the
 * typosquat check as `unknown` — never as a pass.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { resolveConfigsDir } from '../platform/configsDir.js';
import { buildPopularIndex } from './typosquat.js';
export function defaultPopularDir() {
    return join(resolveConfigsDir(), 'popular-packages');
}
export function parsePopularList(text) {
    return text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l !== '' && !l.startsWith('#'));
}
const cache = new Map();
export function loadPopularIndex(ecosystem, dir = defaultPopularDir()) {
    const path = join(dir, `${ecosystem}.txt`);
    const hit = cache.get(path);
    if (hit !== undefined)
        return hit;
    let index = null;
    try {
        const names = parsePopularList(readFileSync(path, 'utf8'));
        index = names.length > 0 ? buildPopularIndex(ecosystem, names) : null;
    }
    catch {
        index = null;
    }
    cache.set(path, index);
    return index;
}
//# sourceMappingURL=popular.js.map