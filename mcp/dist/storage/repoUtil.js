/**
 * Helpers shared across repository modules.
 *
 * - `nowIso()` is the single source of truth for timestamps written to the DB
 *   so tests can stub it in one place.
 * - `boolToInt` / `intToBool` translate SQLite's 0/1 ints to JS booleans.
 * - `parseJsonArray` / `parseJsonObject` defend against migration drift by
 *   tolerating malformed stored JSON instead of throwing.
 */
export function nowIso() {
    return new Date().toISOString();
}
export function boolToInt(value) {
    return value ? 1 : 0;
}
export function intToBool(value) {
    return value === 1;
}
export function parseJsonArray(raw, fallback = []) {
    if (raw === null || raw === undefined || raw === '')
        return fallback;
    try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : fallback;
    }
    catch {
        return fallback;
    }
}
export function parseJsonObject(raw, fallback) {
    if (raw === null || raw === undefined || raw === '')
        return fallback;
    try {
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
            ? parsed
            : fallback;
    }
    catch {
        return fallback;
    }
}
//# sourceMappingURL=repoUtil.js.map