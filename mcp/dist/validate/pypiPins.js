/**
 * Every exact pin of a PyPI distribution the project's own manifests hold —
 * the dependency provider's `PypiPinResolver`, and its only I/O.
 *
 * Why it exists (review of the 3.0 additions, N1): a Python environment is
 * not scoped to a directory. `deploy/requirements.txt` pinning pyyaml 5.3 is
 * installed into the environment `app/web.py` runs in, so the provider does
 * not scope PyPI importers to the manifest's directory the way npm's
 * `node_modules` are scoped. What it cannot know from one finding is whether
 * the project pins the package ONLY at the vulnerable version: two manifests
 * pinning different versions mean an import may load either. This reads them
 * all.
 *
 * Read, at any depth (skipping `PROJECT_WALK_EXCLUDE`: `node_modules`,
 * virtualenvs, build output, `vendor`, …):
 *   - requirement files — `requirements*.txt`, `*-requirements.txt`,
 *     `requirements/*.txt` — their `name==version` / `name===version` lines,
 *     extras and environment markers allowed, `\` continuations joined. A
 *     range (`>=`, `~=`) is not a pin; `-r`/`-c` includes are other files
 *     this walk reads on their own when they match these names;
 *   - `Pipfile.lock` (`default` and `develop`), `poetry.lock`, `uv.lock`.
 *
 * `null` — cannot tell — when a manifest it found could not be read (over
 * {@link MAX_MANIFEST_BYTES}, or a lockfile that does not parse): a pin it
 * did not see may be the different one.
 */
import { readProjectTextOrUndefined } from '../platform/projectFs.js';
import { join } from 'node:path';
import { listProjectFiles } from '../runners/projectFiles.js';
const MAX_MANIFEST_BYTES = 8 * 1024 * 1024;
/** Whether a project-relative POSIX path is a manifest this module reads. */
export function isPypiPinFile(path) {
    const lower = path.toLowerCase();
    const base = lower.split('/').pop() ?? '';
    if (/^requirements.*\.txt$/.test(base) || /-requirements\.txt$/.test(base))
        return true;
    if (/(^|\/)requirements\/[^/]+\.txt$/.test(lower))
        return true;
    return base === 'pipfile.lock' || base === 'poetry.lock' || base === 'uv.lock';
}
export function makePypiPinResolver(projectPath) {
    let index;
    return (name) => {
        if (index === undefined)
            index = readAllPins(projectPath);
        if (index === null)
            return null;
        return index.get(normalize(name)) ?? [];
    };
}
function readAllPins(projectPath) {
    const byName = new Map();
    for (const manifest of listProjectFiles(projectPath).filter(isPypiPinFile)) {
        const text = readText(projectPath, join(projectPath, ...manifest.split('/')));
        if (text === null)
            return null;
        const pins = pinsOf(manifest, text);
        if (pins === null)
            return null;
        for (const [name, version] of pins) {
            const list = byName.get(name) ?? [];
            if (!list.some((p) => p.manifest === manifest && p.version === version))
                list.push({ manifest, version });
            byName.set(name, list);
        }
    }
    for (const list of byName.values())
        list.sort((a, b) => (a.manifest < b.manifest ? -1 : a.manifest > b.manifest ? 1 : 0));
    return byName;
}
/** `[normalised name, version]` pairs, or null for a lockfile that does not parse. */
function pinsOf(manifest, text) {
    const base = (manifest.split('/').pop() ?? '').toLowerCase();
    if (base === 'pipfile.lock')
        return pipfileLockPins(text);
    if (base === 'poetry.lock' || base === 'uv.lock')
        return tomlPackagePins(text);
    return requirementPins(text);
}
function requirementPins(text) {
    const out = [];
    const joined = text.replace(/\\\r?\n/g, ' ');
    for (const raw of joined.split(/\r?\n/)) {
        const line = raw.replace(/(^|\s)#.*$/, '').trim();
        if (line === '' || line.startsWith('-'))
            continue;
        const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*===?\s*([^\s;,]+)/.exec(line);
        if (match?.[1] !== undefined && match[3] !== undefined)
            out.push([normalize(match[1]), match[3]]);
    }
    return out;
}
function pipfileLockPins(text) {
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        return null;
    }
    const out = [];
    for (const section of ['default', 'develop']) {
        const packages = record(record(parsed)?.[section]);
        for (const [name, value] of Object.entries(packages ?? {})) {
            const version = record(value)?.['version'];
            if (typeof version === 'string')
                out.push([normalize(name), version.replace(/^===?/, '')]);
        }
    }
    return out;
}
/** `[[package]]` tables of poetry.lock / uv.lock: their `name` and `version` keys. */
function tomlPackagePins(text) {
    const out = [];
    for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
        const name = /^name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
        const version = /^version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
        if (name !== undefined && version !== undefined)
            out.push([normalize(name), version]);
    }
    return out;
}
/** The repository's manifest: bounded, regular files only, contained in the project (`platform/projectFs.ts`). */
function readText(projectPath, path) {
    return readProjectTextOrUndefined(projectPath, path, MAX_MANIFEST_BYTES) ?? null;
}
function record(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? value
        : null;
}
/** PEP 503. */
function normalize(name) {
    return name.toLowerCase().replace(/[-_.]+/g, '-');
}
//# sourceMappingURL=pypiPins.js.map