/**
 * Public-registry lookups for package vetting: does the name exist, which
 * versions are published, when, and (npm) does a version run install
 * scripts.
 *
 *   npm        https://registry.npmjs.org/<name>  (abbreviated metadata first:
 *              `Accept: application/vnd.npm.install-v1+json` carries versions,
 *              dist-tags, `hasInstallScript` and `modified`, but no per-version
 *              publish time; the full document — which can run to megabytes —
 *              is fetched only when `modified` says a version is recent
 *              enough to matter)
 *   PyPI       https://pypi.org/pypi/<name>/json
 *   Packagist  https://repo.packagist.org/p2/<vendor>/<name>.json
 *   NuGet      https://api.nuget.org/v3-flatcontainer/<id>/index.json, and
 *              the registration leaf for a version's publish time
 *
 * A 404 is a definitive "no such package" — the only response that is. Any
 * other failure (timeout, abort, HTTP error, HTTP 429, malformed body) is
 * `{ ok: false, reason }` and the caller reports the check as `unknown`,
 * never as a pass.
 *
 * Global `fetch` only (injectable for tests). No dependencies.
 */
function describeError(e, signal) {
    if (signal.aborted)
        return 'network budget exhausted before the registry answered';
    if (e instanceof Error) {
        if (e.name === 'AbortError' || e.name === 'TimeoutError')
            return 'request timed out';
        const cause = e.cause;
        const detail = cause instanceof Error ? cause.message : '';
        return detail !== '' ? `${e.message} (${detail})` : e.message;
    }
    return String(e);
}
export async function fetchJson(url, http, headers = {}) {
    try {
        const res = await http.fetchImpl(url, { headers: { accept: 'application/json', ...headers }, signal: http.signal });
        if (res.status === 404 || res.status === 410)
            return { kind: 'not_found' };
        if (res.status === 429)
            return { kind: 'error', reason: `rate limited by ${new URL(url).host} (HTTP 429)` };
        if (!res.ok)
            return { kind: 'error', reason: `${new URL(url).host} answered HTTP ${res.status}` };
        return { kind: 'ok', json: await res.json() };
    }
    catch (e) {
        return { kind: 'error', reason: describeError(e, http.signal) };
    }
}
function isRecord(x) {
    return typeof x === 'object' && x !== null && !Array.isArray(x);
}
function stringRecord(x) {
    const out = {};
    if (!isRecord(x))
        return out;
    for (const [k, v] of Object.entries(x))
        if (typeof v === 'string')
            out[k] = v;
    return out;
}
export function npmDocUrl(name) {
    return `https://registry.npmjs.org/${name.replace('/', '%2F')}`;
}
async function lookupNpm(name, http) {
    const r = await fetchJson(npmDocUrl(name), http, { accept: 'application/vnd.npm.install-v1+json' });
    if (r.kind !== 'ok')
        return r;
    if (!isRecord(r.json) || !isRecord(r.json['versions']))
        return { kind: 'error', reason: 'npm registry returned an unexpected document' };
    const versions = Object.keys(r.json['versions']);
    const installScript = {};
    for (const [v, meta] of Object.entries(r.json['versions'])) {
        if (isRecord(meta) && meta['hasInstallScript'] === true)
            installScript[v] = true;
    }
    const tags = stringRecord(r.json['dist-tags']);
    const info = { versions, tags, times: {}, installScript };
    if (tags['latest'] !== undefined)
        info.latest = tags['latest'];
    if (typeof r.json['modified'] === 'string')
        info.modified = r.json['modified'];
    return { kind: 'found', info };
}
/** The full npm document: per-version publish `time` and `scripts`. */
export async function npmFullDocument(name, http) {
    const r = await fetchJson(npmDocUrl(name), http);
    if (r.kind === 'not_found')
        return { kind: 'error', reason: 'npm registry no longer has this package' };
    if (r.kind === 'error')
        return r;
    if (!isRecord(r.json))
        return { kind: 'error', reason: 'npm registry returned an unexpected document' };
    const scripts = {};
    const versions = r.json['versions'];
    if (isRecord(versions)) {
        for (const [v, meta] of Object.entries(versions)) {
            if (isRecord(meta))
                scripts[v] = stringRecord(meta['scripts']);
        }
    }
    return { kind: 'ok', times: stringRecord(r.json['time']), scripts };
}
/** One npm version manifest — small; used for the names of its install scripts. */
export async function npmVersionScripts(name, version, http) {
    const r = await fetchJson(`${npmDocUrl(name)}/${encodeURIComponent(version)}`, http);
    if (r.kind === 'not_found')
        return { kind: 'error', reason: 'version manifest not found' };
    if (r.kind === 'error')
        return r;
    return { kind: 'ok', scripts: isRecord(r.json) ? stringRecord(r.json['scripts']) : {} };
}
async function lookupPypi(name, http) {
    const r = await fetchJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, http);
    if (r.kind !== 'ok')
        return r;
    if (!isRecord(r.json) || !isRecord(r.json['info']))
        return { kind: 'error', reason: 'PyPI returned an unexpected document' };
    const releases = isRecord(r.json['releases']) ? r.json['releases'] : {};
    const times = {};
    const versions = [];
    for (const [v, files] of Object.entries(releases)) {
        if (!Array.isArray(files) || files.length === 0)
            continue; // a release with no files cannot be installed
        versions.push(v);
        let earliest;
        for (const f of files) {
            const t = isRecord(f) ? f['upload_time_iso_8601'] ?? f['upload_time'] : undefined;
            if (typeof t === 'string' && (earliest === undefined || t < earliest))
                earliest = t;
        }
        if (earliest !== undefined)
            times[v] = earliest;
    }
    const info = { versions, times, installScript: {} };
    const latest = r.json['info']['version'];
    if (typeof latest === 'string')
        info.latest = latest;
    return { kind: 'found', info };
}
async function lookupPackagist(name, http) {
    const lower = name.toLowerCase();
    const r = await fetchJson(`https://repo.packagist.org/p2/${lower}.json`, http);
    if (r.kind !== 'ok')
        return r;
    const pkgs = isRecord(r.json) ? r.json['packages'] : undefined;
    const list = isRecord(pkgs) ? pkgs[lower] : undefined;
    if (!Array.isArray(list))
        return { kind: 'error', reason: 'Packagist returned an unexpected document' };
    // composer/2.0 "minified" format: each entry repeats only what changed
    // from the one before it, so fields are carried forward.
    let carried = {};
    const versions = [];
    const times = {};
    for (const entry of list) {
        if (!isRecord(entry))
            continue;
        const next = { ...carried };
        for (const [k, v] of Object.entries(entry)) {
            if (v === '__unset')
                delete next[k];
            else
                next[k] = v;
        }
        carried = next;
        const version = next['version'];
        if (typeof version !== 'string')
            continue;
        versions.push(version);
        const time = next['time'];
        if (typeof time === 'string')
            times[version] = time;
    }
    return { kind: 'found', info: { versions, times, installScript: {} } };
}
async function lookupNuget(name, http) {
    const lower = name.toLowerCase();
    const r = await fetchJson(`https://api.nuget.org/v3-flatcontainer/${encodeURIComponent(lower)}/index.json`, http);
    if (r.kind !== 'ok')
        return r;
    const versions = isRecord(r.json) && Array.isArray(r.json['versions']) ? r.json['versions'].filter((v) => typeof v === 'string') : null;
    if (versions === null)
        return { kind: 'error', reason: 'NuGet returned an unexpected document' };
    return { kind: 'found', info: { versions, times: {}, installScript: {} } };
}
/** NuGet registration leaf: the `published` time of one version. */
export async function nugetPublished(name, version, http) {
    const url = `https://api.nuget.org/v3/registration5-gz-semver2/${encodeURIComponent(name.toLowerCase())}/${encodeURIComponent(version.toLowerCase())}.json`;
    const r = await fetchJson(url, http);
    if (r.kind === 'not_found')
        return { kind: 'error', reason: 'NuGet registration leaf not found' };
    if (r.kind === 'error')
        return r;
    const published = isRecord(r.json) ? r.json['published'] : undefined;
    return typeof published === 'string' ? { kind: 'ok', published } : { kind: 'ok' };
}
export function lookupRegistry(ecosystem, name, http) {
    switch (ecosystem) {
        case 'npm':
            return lookupNpm(name, http);
        case 'pypi':
            return lookupPypi(name, http);
        case 'packagist':
            return lookupPackagist(name, http);
        case 'nuget':
            return lookupNuget(name, http);
        default:
            return Promise.resolve({ kind: 'error', reason: 'unsupported ecosystem' });
    }
}
//# sourceMappingURL=registry.js.map