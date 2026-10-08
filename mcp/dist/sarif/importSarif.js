/**
 * SARIF 2.1.0 log → canonical findings and counts (feature `sarif-import`).
 *
 * Contract the tests hold it to:
 *   - pure: text in, result out — no file, URL or process is opened for
 *     anything the log names (US-1.AC-15); paths are resolved textually
 *     against `ctx.projectPath`;
 *   - a log that is not JSON, does not declare `version: "2.1.0"`, or has no
 *     `runs` array (an empty file included) is refused by THROWING an Error
 *     whose `code` is `'invalid_sarif'` and whose message names the field or
 *     index at fault — never content of the log (US-1.AC-10, US-1.AC-18);
 *   - one `SarifImportRun` per `runs[]` entry, in order.
 */
import { createHash } from 'node:crypto';
import { isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isCredentialFinding } from '../fingerprint/findingIdentity.js';
import { parseJsonBounded } from '../platform/boundedJson.js';
import { asArray, clampSnippet, getNumber, getProp, getString, makeFinding, normalizeSeverity, } from '../runners/scannerParsers/index.js';
import { CATEGORIES, SEVERITY_ORDER } from '../types.js';
/** A log the reader refuses; `message` names a field or an index, never content of the log (US-1.AC-18). */
export class SarifImportError extends Error {
    code = 'invalid_sarif';
    constructor(message) {
        super(message);
        this.name = 'SarifImportError';
    }
}
const DEFAULT_MAX_RESULTS = 50_000;
const MAX_RESULTS_CEILING = 200_000;
const MESSAGE_MAX_BYTES = 4096;
const TITLE_MAX_CHARS = 140;
const TOOL_NAME_MAX = 100;
/** Semgrep without a login writes this as `matchBasedId/v1` on every result: not an identity. */
const PLACEHOLDER_FINGERPRINT = /^requires login$/i;
/** CWEs of a rule that is about credentials (US-1.AC-16). */
const SECRET_CWES = new Set(['CWE-798', 'CWE-259', 'CWE-321']);
const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
export function importSarif(text, ctx) {
    const runs = parseLog(text);
    const maxResults = Math.min(ctx.maxResults ?? DEFAULT_MAX_RESULTS, MAX_RESULTS_CEILING);
    return { runs: runs.map((run) => readRun(run, ctx.projectPath, maxResults)) };
}
/** Text → the log's runs, or a refusal that names the problem. */
function parseLog(text) {
    if (text.trim() === '' || text === '﻿')
        throw new SarifImportError('the file is empty');
    const parsed = parseJsonBounded(text);
    if (!parsed.ok) {
        throw new SarifImportError(parsed.reason === 'invalid' ? 'the file is not valid JSON' : `the log is not read: it is ${parsed.reason}`);
    }
    const root = parsed.value;
    if (!isObject(root))
        throw new SarifImportError('the top level of the log is not an object (expected version and runs)');
    if (root['version'] !== '2.1.0')
        throw new SarifImportError('"version" is missing or is not "2.1.0"');
    const runs = root['runs'];
    if (!Array.isArray(runs))
        throw new SarifImportError('"runs" is missing or is not an array');
    const out = [];
    runs.forEach((r, i) => {
        if (!isObject(r))
            throw new SarifImportError(`runs[${String(i)}] is not an object`);
        out.push(r);
    });
    return out;
}
function readRun(run, projectPath, maxResults) {
    const toolObj = getProp(run, 'tool');
    const driver = getProp(toolObj, 'driver');
    const tool = (getString(driver, 'name') ?? '').trim().slice(0, TOOL_NAME_MAX) || 'unknown';
    const version = getString(driver, 'version') ?? getString(driver, 'semanticVersion');
    const driverRules = asArray(getProp(driver, 'rules'));
    const extensions = asArray(getProp(toolObj, 'extensions'));
    const rulesById = new Map();
    for (const rule of [...driverRules, ...extensions.flatMap((e) => asArray(getProp(e, 'rules')))]) {
        const id = getString(rule, 'id');
        if (id !== undefined && isObject(rule) && !rulesById.has(id))
            rulesById.set(id, rule);
    }
    const bases = getProp(run, 'originalUriBaseIds');
    const rc = { projectPath, tool, driverRules, extensions, rulesById, bases: isObject(bases) ? bases : {} };
    const counts = {
        results: 0,
        imported: 0,
        without_location: 0,
        skipped: [],
        suppressed_at_source: 0,
        not_findings: 0,
        duplicates: 0,
        identity_computed: 0,
        truncated: 0,
    };
    const findings = [];
    const seen = new Set();
    const keys = [];
    const results = asArray(getProp(run, 'results'));
    const limit = Math.min(results.length, maxResults);
    counts.truncated = results.length - limit;
    for (let index = 0; index < limit; index += 1) {
        counts.results += 1;
        const result = results[index];
        if (!isObject(result)) {
            counts.skipped.push({ index, reason: 'the result is not an object' });
            continue;
        }
        const kind = getString(result, 'kind');
        if ((kind !== undefined && kind !== 'fail') || (kind === undefined && getString(result, 'level') === 'none')) {
            counts.not_findings += 1;
            continue;
        }
        if (asArray(result['suppressions']).some((s) => getString(s, 'status') === 'accepted')) {
            counts.suppressed_at_source += 1;
            continue;
        }
        const built = buildFinding(result, rc);
        if ('skip' in built) {
            counts.skipped.push({ index, reason: built.skip });
            continue;
        }
        const { finding, dedupeKey } = built;
        if (seen.has(dedupeKey)) {
            counts.duplicates += 1;
            continue;
        }
        seen.add(dedupeKey);
        if (finding.file_path === undefined)
            counts.without_location += 1;
        if (finding.identity === undefined)
            counts.identity_computed += 1;
        findings.push(finding);
        keys.push(dedupeKey);
        counts.imported += 1;
    }
    separateSharedFingerprints(findings, keys);
    return { source_tool: tool, ...(version !== undefined ? { source_version: version } : {}), findings, counts };
}
/**
 * A finding's fingerprint is rule, file and line, and a scan stores one row
 * per fingerprint: two results on the same line (another message, another
 * log fingerprint) would collapse into one. Every member of such a group takes
 * a fingerprint of its own, derived from what told it apart — the same for
 * the same result on every import, whichever of its neighbours came first.
 */
function separateSharedFingerprints(findings, keys) {
    const uses = new Map();
    for (const f of findings)
        uses.set(f.fingerprint, (uses.get(f.fingerprint) ?? 0) + 1);
    findings.forEach((f, i) => {
        if ((uses.get(f.fingerprint) ?? 0) < 2)
            return;
        f.fingerprint = createHash('sha256').update(JSON.stringify(['sarif-fp-v1', f.fingerprint, keys[i] ?? ''])).digest('hex');
    });
}
/** The rule a result points at: by its reference (index, extension), else by its id. */
function resolveRule(result, rc) {
    const ref = getProp(result, 'rule');
    // -1 is SARIF's "absent" sentinel, not an index.
    const rawIndex = getNumber(result, 'ruleIndex') ?? getNumber(ref, 'index');
    const index = rawIndex !== undefined && rawIndex >= 0 ? rawIndex : undefined;
    const component = getProp(ref, 'toolComponent');
    let pool = rc.driverRules;
    const componentIndex = getNumber(component, 'index');
    const componentName = getString(component, 'name');
    if (componentIndex !== undefined) {
        pool = asArray(getProp(rc.extensions[componentIndex], 'rules'));
    }
    else if (componentName !== undefined) {
        const ext = rc.extensions.find((e) => getString(e, 'name') === componentName);
        if (ext !== undefined)
            pool = asArray(getProp(ext, 'rules'));
    }
    const byIndex = index === undefined ? undefined : pool[index];
    const referenced = isObject(byIndex) ? byIndex : undefined;
    const id = getString(result, 'ruleId') ?? getString(ref, 'id') ?? (referenced ? getString(referenced, 'id') : undefined);
    const rule = referenced ?? (id !== undefined ? rc.rulesById.get(id) : undefined);
    return {
        ...(rule !== undefined ? { rule } : {}),
        ...(id !== undefined ? { id } : {}),
        danglingRef: index !== undefined && referenced === undefined,
    };
}
function buildFinding(result, rc) {
    const { rule, id: ruleId, danglingRef } = resolveRule(result, rc);
    const messageText = textOf(getProp(result, 'message'));
    if (ruleId === undefined && danglingRef)
        return { skip: 'ruleIndex does not resolve to a rule' };
    if (ruleId === undefined && messageText === undefined) {
        return { skip: 'no ruleId, no resolvable ruleIndex and no message' };
    }
    const props = [getProp(result, 'properties'), getProp(rule, 'properties')];
    const cwe = cweOf(result, rule, props);
    // Whatever the tool calls itself: a credential rule never keeps its snippet.
    const secret = isSecretRule(cwe, props) ||
        // Every gitleaks result is a secret, though its ids (`aws-access-token`) may name none.
        rc.tool.toLowerCase() === 'gitleaks' ||
        isCredentialFinding({
            ...(ruleId !== undefined ? { rule_id: ruleId } : {}),
            subcategory: props.map((p) => getString(p, 'subcategory')).find((v) => v !== undefined) ?? '',
        });
    const where = locate(result, rc);
    const message = messageText !== undefined ? truncateBytes(messageText) : undefined;
    // The rule's own short description names the finding; the result's message is the detail, so the
    // title repeats it only when the rule has no description.
    const title = (getString(getProp(rule, 'shortDescription'), 'text') ?? message ?? ruleId ?? 'finding').slice(0, TITLE_MAX_CHARS);
    const input = {
        tool: rc.tool,
        severity: severityOf(result, rule, props),
        category: categoryOf(props),
        title,
        fix_available: false,
    };
    if (ruleId !== undefined)
        input.rule_id = ruleId;
    if (message !== undefined)
        input.message = message;
    if (where.file !== undefined) {
        input.file_path = where.file;
        if (where.startLine !== undefined)
            input.line_start = where.startLine;
        if (where.endLine !== undefined)
            input.line_end = where.endLine;
    }
    // Credentials: rule, file and line only — the snippet is never kept (US-1.AC-16).
    if (!secret && where.snippet !== undefined)
        input.snippet = where.snippet;
    if (cwe.length > 0)
        input.taxonomy = { cwe };
    const finding = makeFinding(input);
    const identity = identityOf(result, rc.tool, ruleId);
    if (identity !== undefined)
        finding.identity = identity;
    const dedupeKey = identity !== undefined
        ? `i:${identity}`
        : `l:${JSON.stringify([ruleId ?? null, where.file ?? null, where.startLine ?? null, where.endLine ?? null, where.columns ?? null, message ?? null])}`;
    return { finding, dedupeKey };
}
function textOf(message) {
    const t = getString(message, 'text') ?? getString(message, 'markdown');
    return t === undefined || t.trim() === '' ? undefined : t;
}
/** `s` cut to {@link MESSAGE_MAX_BYTES} UTF-8 bytes, at a character boundary. */
function truncateBytes(s) {
    if (Buffer.byteLength(s, 'utf8') <= MESSAGE_MAX_BYTES)
        return s;
    const buf = Buffer.from(s, 'utf8');
    let cut = MESSAGE_MAX_BYTES;
    while (cut > 0 && ((buf[cut] ?? 0) & 0xc0) === 0x80)
        cut -= 1;
    return buf.subarray(0, cut).toString('utf8');
}
// --- severity ---------------------------------------------------------------
function severityOf(result, rule, props) {
    // A dev-guardian export carries the exact severity (level cannot tell low from info).
    for (const p of props) {
        const s = getString(p, 'severity')?.toLowerCase();
        if (s !== undefined && hasOwn(SEVERITY_ORDER, s))
            return s;
    }
    for (const p of props) {
        const raw = getProp(p, 'security-severity');
        const score = typeof raw === 'number' ? raw : typeof raw === 'string' && /^\d+(\.\d+)?$/.test(raw.trim()) ? Number(raw) : NaN;
        if (Number.isFinite(score) && score >= 0 && score <= 10) {
            if (score >= 9)
                return 'critical';
            if (score >= 7)
                return 'high';
            if (score >= 4)
                return 'medium';
            return score > 0 ? 'low' : 'info';
        }
    }
    const level = getString(result, 'level') ?? getString(getProp(rule, 'defaultConfiguration'), 'level');
    // normalizeSeverity('none') is medium; a level of none is the lowest, not a guess.
    return level?.toLowerCase() === 'none' ? 'info' : normalizeSeverity(level);
}
function categoryOf(props) {
    for (const p of props) {
        const c = getString(p, 'category');
        if (c !== undefined && CATEGORIES.includes(c))
            return c;
    }
    return 'security';
}
// --- CWE --------------------------------------------------------------------
/** `external/cwe/cwe-089`, `CWE-798: Use of hard-coded credentials` (Semgrep), `cwe-79`. */
const CWE_TEXT = /^(?:external\/cwe\/)?cwe[-_ ]?0*(\d+)(?!\d)/i;
function cweOf(result, rule, props) {
    const found = new Set();
    const add = (raw, bare) => {
        if (typeof raw !== 'string')
            return;
        const t = raw.trim();
        const m = CWE_TEXT.exec(t) ?? (bare ? /^0*(\d+)$/.exec(t) : null);
        if (m?.[1] !== undefined)
            found.add(`CWE-${m[1]}`);
    };
    for (const p of props) {
        for (const tag of asArray(getProp(p, 'tags')))
            add(tag, false);
        const cwe = getProp(p, 'cwe');
        for (const c of Array.isArray(cwe) ? cwe : [cwe])
            add(typeof c === 'number' ? String(c) : c, true);
    }
    const addTaxon = (taxon) => {
        const name = getString(getProp(taxon, 'toolComponent'), 'name') ?? '';
        add(getString(taxon, 'id'), /cwe/i.test(name));
    };
    asArray(getProp(result, 'taxa')).forEach(addTaxon);
    asArray(getProp(rule, 'taxa')).forEach(addTaxon);
    for (const rel of asArray(getProp(rule, 'relationships')))
        addTaxon(getProp(rel, 'target'));
    return [...found];
}
function isSecretRule(cwe, props) {
    if (cwe.some((c) => SECRET_CWES.has(c)))
        return true;
    return props.some((p) => asArray(getProp(p, 'tags')).some((t) => typeof t === 'string' && /^secrets?$/i.test(t.trim())));
}
// --- identity ---------------------------------------------------------------
/** Name-sorted, usable fingerprints of `bag`: non-empty strings that are not a tool's placeholder. */
function usableFingerprints(bag) {
    if (!isObject(bag))
        return [];
    return Object.keys(bag)
        .sort()
        .flatMap((k) => {
        const v = bag[k];
        // A devGuardianIdentity that was not accepted as one is not a fingerprint either.
        if (k === 'devGuardianIdentity')
            return [];
        return typeof v === 'string' && v !== '' && !PLACEHOLDER_FINGERPRINT.test(v.trim()) ? [[k, v]] : [];
    });
}
function identityOf(result, tool, ruleId) {
    const partial = getProp(result, 'partialFingerprints');
    const own = getString(partial, 'devGuardianIdentity');
    // Only the shape of a native identity: a log cannot choose any other string.
    if (own !== undefined && /^[0-9a-f]{64}$/.test(own))
        return own;
    let key = usableFingerprints(partial);
    if (key.length === 0)
        key = usableFingerprints(getProp(result, 'fingerprints'));
    if (key.length === 0)
        return undefined;
    return createHash('sha256')
        .update(JSON.stringify(['sarif-v1', tool, ruleId ?? '', key]))
        .digest('hex');
}
const DRIVE_PATH = /^[a-zA-Z]:[\\/]/;
const URI_SCHEME = /^([a-zA-Z][a-zA-Z0-9+.-]*):/;
/** Where the result's primary location is, resolved textually against the project root (US-1.AC-15). */
function locate(result, rc) {
    const physical = getProp(asArray(getProp(result, 'locations'))[0], 'physicalLocation');
    const artifact = getProp(physical, 'artifactLocation');
    const uri = getString(artifact, 'uri');
    if (uri === undefined)
        return {};
    const file = relativeInProject(uri, getString(artifact, 'uriBaseId'), rc);
    if (file === undefined)
        return {};
    const region = getProp(physical, 'region');
    const startLine = positiveInt(getNumber(region, 'startLine'));
    const endLine = positiveInt(getNumber(region, 'endLine')) ?? startLine;
    const snippet = clampSnippet(getString(getProp(region, 'snippet'), 'text'));
    return {
        file,
        ...(startLine !== undefined ? { startLine } : {}),
        ...(endLine !== undefined ? { endLine } : {}),
        ...(snippet !== undefined ? { snippet } : {}),
        columns: [getNumber(region, 'startColumn') ?? null, getNumber(region, 'endColumn') ?? null],
    };
}
const positiveInt = (n) => n !== undefined && Number.isInteger(n) && n >= 1 ? n : undefined;
/** A `file:` URL or a drive-letter path as a native path; undefined for any other scheme. */
function nativePath(uri) {
    if (DRIVE_PATH.test(uri))
        return uri;
    if (URI_SCHEME.exec(uri)?.[1]?.toLowerCase() !== 'file')
        return undefined;
    try {
        return fileURLToPath(uri);
    }
    catch {
        return undefined;
    }
}
function decode(s) {
    try {
        return decodeURIComponent(s);
    }
    catch {
        return s;
    }
}
/** `p` relative to the project root, with `/` separators, when it lies strictly inside it. */
function insideRoot(p, root) {
    const rel = relative(root, p);
    if (rel === '' || rel === '..' || rel.startsWith('..\\') || rel.startsWith('../') || isAbsolute(rel))
        return undefined;
    return rel.replace(/\\/g, '/');
}
function relativeInProject(uri, baseId, rc) {
    const root = resolve(rc.projectPath);
    if (DRIVE_PATH.test(uri) || URI_SCHEME.test(uri)) {
        const native = nativePath(uri);
        return native === undefined ? undefined : insideRoot(resolve(native), root);
    }
    const decoded = decode(uri);
    // A NUL or other control character is never part of a path the project holds.
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f\u007f]/.test(decoded))
        return undefined;
    const rel = decoded.replace(/\\/g, '/');
    if (rel.startsWith('/'))
        return insideRoot(resolve(rel), root);
    return insideRoot(resolve(baseDirectory(baseId, rc, root), rel), root);
}
/** The directory a `uriBaseId` stands for when the log puts it inside the project; the project root otherwise (EC-1). */
function baseDirectory(baseId, rc, root) {
    if (baseId === undefined || !hasOwn(rc.bases, baseId))
        return root;
    const baseUri = getString(rc.bases[baseId], 'uri');
    const native = baseUri === undefined ? undefined : nativePath(baseUri);
    if (native === undefined)
        return root;
    const dir = resolve(native);
    return dir === root || insideRoot(dir, root) !== undefined ? dir : root;
}
//# sourceMappingURL=importSarif.js.map