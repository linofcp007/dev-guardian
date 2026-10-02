/**
 * Validation of what a model submits — pure, plus the injected contained
 * reader. Everything here is untrusted input.
 *
 *   - size first: a payload over {@link MAX_SUBMISSION_BYTES} serialized is
 *     refused before anything else is looked at (US-1.AC-15);
 *   - then the schema: closed enums, word and character limits, no key the
 *     schema does not name (US-1.AC-3, US-2.AC-3, US-2.AC-7);
 *   - then the disk: every `file:line` the schema's citation fields name must
 *     be a file inside the project root with that line (US-1.AC-14). A path
 *     outside the root is rejected WITHOUT being handed to the reader; a path
 *     inside is read only through it (`platform/projectFs.ts#readProjectText`
 *     in production), which refuses a link out of the project.
 *
 * Nothing a submission says is executed, opened or followed beyond those
 * reads (US-1.AC-16). No error message reproduces file content.
 *
 * Also here: the one place an `llm` verdict is turned into a
 * `finding_validations` row and back, so the tool that writes it and the open
 * set that reads it cannot disagree on the encoding.
 */
import { posix } from 'node:path';
import { HUNT_CLASSES } from './classes.js';
/** US-1.AC-15 */
export const MAX_SUBMISSION_BYTES = 64 * 1024;
/** US-2.AC-7 */
export const MAX_HUNT_FINDINGS = 50;
/** US-1.AC-3 */
export const MAX_REASONING_WORDS = 120;
export const MAX_EVIDENCE_WORDS = 60;
export const MAX_TITLE_CHARS = 200;
const VERDICTS = ['real', 'not_real', 'undetermined'];
const VERIFY_KEYS = ['verdict', 'attacker_input', 'operation', 'decisive_line', 'reasoning'];
const HUNT_KEYS = ['entry_points_reviewed', 'findings'];
const FINDING_KEYS = ['file', 'line', 'class', 'title', 'attacker', 'evidence'];
/** Bounds on what a hunt may list as reviewed, and on the references read per finding. */
const MAX_ENTRY_POINTS = 200;
const MAX_ENTRY_POINT_CHARS = 300;
const MAX_EVIDENCE_REFS = 10;
/** A cited file larger than this reads as "could not be read": a citation never needs more. */
export const MAX_CITED_FILE_BYTES = 1024 * 1024;
/** Distinct files one submission may make the server read; further citations are rejected unread. */
export const MAX_CITED_FILES = 100;
/** A key echoed in an error must look like a plain identifier of at most this many characters. */
const MAX_ECHOED_KEY_CHARS = 32;
const CLASS_SET = new Set(HUNT_CLASSES);
const isRecord = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const wordCount = (s) => s.split(/\s+/).filter((w) => w !== '').length;
/** The serialized size, or null when the payload cannot be serialized at all. */
function serializedBytes(payload) {
    try {
        const text = JSON.stringify(payload);
        return text === undefined ? null : Buffer.byteLength(text, 'utf8');
    }
    catch {
        return null;
    }
}
/** Size gate shared by both submissions: the failure to return, or null to go on. */
function sizeGate(payload) {
    const bytes = serializedBytes(payload);
    if (bytes === null)
        return { ok: false, code: 'invalid', errors: [{ path: '$', problem: 'payload is not serializable JSON' }] };
    if (bytes > MAX_SUBMISSION_BYTES) {
        return { ok: false, code: 'too_large', errors: [{ path: '$', problem: `payload is over ${MAX_SUBMISSION_BYTES} bytes serialized` }] };
    }
    return null;
}
function unknownKeys(obj, allowed, prefix, errors) {
    let index = 0;
    for (const key of Object.keys(obj)) {
        if (allowed.includes(key))
            continue;
        // The path is fixed; only a short identifier-shaped key is named in the
        // problem, anything else is never reproduced.
        const named = key.length <= MAX_ECHOED_KEY_CHARS && /^[A-Za-z_][A-Za-z0-9_]*$/.test(key);
        errors.push({ path: `${prefix}[unknown field #${index}]`, problem: named ? `unknown field ${key}` : 'unknown field' });
        index += 1;
    }
}
function textField(obj, key, prefix, errors) {
    const v = obj[key];
    if (v === undefined) {
        errors.push({ path: `${prefix}${key}`, problem: 'missing field' });
        return null;
    }
    if (typeof v !== 'string' || v.trim() === '') {
        errors.push({ path: `${prefix}${key}`, problem: 'must be a non-empty string' });
        return null;
    }
    return v;
}
/**
 * A project-relative POSIX path, or null when it is not lexically inside the
 * root (absolute in any platform's spelling, a drive, a UNC share, climbing
 * out after normalisation). Judged BEFORE any read: an outside path is never
 * handed to the reader (US-1.AC-14).
 */
const WINDOWS_DEVICE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;
function containedPath(raw) {
    if (raw === '' || raw.includes('\0'))
        return null;
    const slashed = raw.replace(/\\/g, '/');
    if (slashed.startsWith('/') || /^[A-Za-z]:/.test(slashed))
        return null;
    // A colon past the drive check is a Windows alternate data stream.
    if (slashed.includes(':'))
        return null;
    const normal = posix.normalize(slashed);
    if (normal === '..' || normal.startsWith('../') || normal === '.')
        return null;
    // Reserved device names open a device, not a file, in any segment and any case.
    if (normal.split('/').some((seg) => WINDOWS_DEVICE.test(seg)))
        return null;
    return normal;
}
/** Looks one `file:line` up on disk through the contained reader, once per file. */
class CitationChecker {
    ctx;
    looked = new Map();
    constructor(ctx) {
        this.ctx = ctx;
    }
    /** The reason a citation does not hold, or null when it does. */
    check(file, line) {
        const path = containedPath(file);
        if (path === null)
            return 'not inside the project';
        if (!Number.isSafeInteger(line) || line < 1)
            return 'line outside the file';
        let seen = this.looked.get(path);
        if (seen === undefined) {
            if (this.looked.size >= MAX_CITED_FILES)
                return 'too many distinct files cited';
            seen = this.look(path);
            this.looked.set(path, seen);
        }
        if (seen.status === 'absent')
            return 'file not found';
        if (seen.status === 'refused')
            return 'file could not be read';
        return line > seen.lines ? 'line outside the file' : null;
    }
    look(path) {
        const read = this.ctx.reader(this.ctx.root, path, MAX_CITED_FILE_BYTES);
        if (read.status !== 'ok')
            return { status: read.status };
        // Lines, not counting the empty "line" after a final newline.
        return { status: 'ok', lines: read.text === '' ? 0 : read.text.replace(/\r?\n$/, '').split(/\r?\n/).length };
    }
}
const CITATION = /^(.+):(\d+)$/;
const DECISIVE = /^(.+?):(\d+) — \S/;
function checkCitation(checker, field, text, form, errors) {
    const m = form.exec(text);
    const file = m?.[1];
    const line = m?.[2];
    if (file === undefined || line === undefined) {
        errors.push({ path: field, problem: field === 'decisive_line' ? 'must have the form file:line — reason' : 'must have the form file:line' });
        return;
    }
    const problem = checker.check(file, Number(line));
    if (problem !== null)
        errors.push({ path: field, problem: `citation: ${problem}` });
}
export function validateVerifySubmission(payload, ctx) {
    const gate = sizeGate(payload);
    if (gate !== null)
        return gate;
    if (!isRecord(payload))
        return { ok: false, code: 'invalid', errors: [{ path: '$', problem: 'must be a JSON object' }] };
    const errors = [];
    unknownKeys(payload, VERIFY_KEYS, '', errors);
    const verdict = payload['verdict'];
    if (verdict === undefined)
        errors.push({ path: 'verdict', problem: 'missing field' });
    else if (typeof verdict !== 'string' || !VERDICTS.includes(verdict)) {
        errors.push({ path: 'verdict', problem: `must be one of ${VERDICTS.join(', ')}` });
    }
    const attacker = textField(payload, 'attacker_input', '', errors);
    const operation = textField(payload, 'operation', '', errors);
    const decisive = textField(payload, 'decisive_line', '', errors);
    const reasoning = textField(payload, 'reasoning', '', errors);
    if (reasoning !== null && wordCount(reasoning) > MAX_REASONING_WORDS) {
        errors.push({ path: 'reasoning', problem: `must be at most ${MAX_REASONING_WORDS} words` });
    }
    // The disk is consulted only for a submission whose shape is already right.
    if (errors.length === 0 && attacker !== null && operation !== null && decisive !== null) {
        const checker = new CitationChecker(ctx);
        if (attacker !== 'none')
            checkCitation(checker, 'attacker_input', attacker, CITATION, errors);
        checkCitation(checker, 'operation', operation, CITATION, errors);
        checkCitation(checker, 'decisive_line', decisive, DECISIVE, errors);
    }
    if (errors.length > 0 || attacker === null || operation === null || decisive === null || reasoning === null) {
        return { ok: false, code: 'invalid', errors };
    }
    const value = {
        verdict: verdict,
        attacker_input: attacker,
        operation,
        decisive_line: decisive,
        reasoning,
    };
    return { ok: true, value, rejected: [] };
}
/** Every `file:line` in a piece of free text, URLs aside, at most {@link MAX_EVIDENCE_REFS}. */
function evidenceRefs(evidence) {
    const refs = [];
    for (const token of evidence.split(/[\s;,()'"`]+/)) {
        if (token.includes('://'))
            continue;
        const m = CITATION.exec(token.replace(/[.:]+$/, ''));
        const file = m?.[1];
        const line = m?.[2];
        if (file === undefined || line === undefined)
            continue;
        refs.push({ file, line: Number(line) });
        if (refs.length >= MAX_EVIDENCE_REFS)
            break;
    }
    return refs;
}
function validateFinding(raw, index, checker) {
    const prefix = `findings[${index}].`;
    const errors = [];
    if (!isRecord(raw))
        return { value: null, errors: [{ path: `findings[${index}]`, problem: 'must be an object' }] };
    unknownKeys(raw, FINDING_KEYS, prefix, errors);
    const file = textField(raw, 'file', prefix, errors);
    const line = raw['line'];
    if (line === undefined)
        errors.push({ path: `${prefix}line`, problem: 'missing field' });
    else if (typeof line !== 'number' || !Number.isSafeInteger(line) || line < 1) {
        errors.push({ path: `${prefix}line`, problem: 'must be a positive integer' });
    }
    const cls = raw['class'];
    if (cls === undefined)
        errors.push({ path: `${prefix}class`, problem: 'missing field' });
    else if (typeof cls !== 'string' || !CLASS_SET.has(cls))
        errors.push({ path: `${prefix}class`, problem: 'not one of the known classes' });
    const title = textField(raw, 'title', prefix, errors);
    if (title !== null && title.length > MAX_TITLE_CHARS) {
        errors.push({ path: `${prefix}title`, problem: `must be at most ${MAX_TITLE_CHARS} characters` });
    }
    const attacker = textField(raw, 'attacker', prefix, errors);
    if (attacker !== null && attacker.length > MAX_TITLE_CHARS) {
        errors.push({ path: `${prefix}attacker`, problem: `must be at most ${MAX_TITLE_CHARS} characters` });
    }
    const evidence = textField(raw, 'evidence', prefix, errors);
    if (evidence !== null && wordCount(evidence) > MAX_EVIDENCE_WORDS) {
        errors.push({ path: `${prefix}evidence`, problem: `must be at most ${MAX_EVIDENCE_WORDS} words` });
    }
    if (errors.length > 0 || file === null || typeof line !== 'number' || title === null || attacker === null || evidence === null) {
        return { value: null, errors };
    }
    const problem = checker.check(file, line);
    if (problem !== null)
        errors.push({ path: `${prefix}file`, problem: `citation: ${problem}` });
    // At least one reference in the evidence must hold; the rest is free text.
    if (!evidenceRefs(evidence).some((r) => checker.check(r.file, r.line) === null)) {
        errors.push({ path: `${prefix}evidence`, problem: 'needs at least one file:line reference that exists in the project' });
    }
    if (errors.length > 0)
        return { value: null, errors };
    return { value: { file, line, class: cls, title, attacker, evidence }, errors };
}
export function validateHuntSubmission(payload, ctx) {
    const gate = sizeGate(payload);
    if (gate !== null)
        return gate;
    if (!isRecord(payload))
        return { ok: false, code: 'invalid', errors: [{ path: '$', problem: 'must be a JSON object' }] };
    const errors = [];
    unknownKeys(payload, HUNT_KEYS, '', errors);
    const reviewed = payload['entry_points_reviewed'];
    if (reviewed === undefined)
        errors.push({ path: 'entry_points_reviewed', problem: 'missing field' });
    else if (!Array.isArray(reviewed) ||
        reviewed.length > MAX_ENTRY_POINTS ||
        reviewed.some((e) => typeof e !== 'string' || e.length > MAX_ENTRY_POINT_CHARS)) {
        errors.push({ path: 'entry_points_reviewed', problem: `must be at most ${MAX_ENTRY_POINTS} strings of at most ${MAX_ENTRY_POINT_CHARS} characters` });
    }
    const findings = payload['findings'];
    if (findings === undefined)
        errors.push({ path: 'findings', problem: 'missing field' });
    else if (!Array.isArray(findings))
        errors.push({ path: 'findings', problem: 'must be an array' });
    else if (findings.length > MAX_HUNT_FINDINGS)
        errors.push({ path: 'findings', problem: `at most ${MAX_HUNT_FINDINGS} findings` });
    if (errors.length > 0 || !Array.isArray(findings) || !Array.isArray(reviewed))
        return { ok: false, code: 'invalid', errors };
    const checker = new CitationChecker(ctx);
    const kept = [];
    const rejected = [];
    findings.forEach((raw, i) => {
        const r = validateFinding(raw, i, checker);
        if (r.value !== null)
            kept.push(r.value);
        else
            rejected.push(...r.errors);
    });
    return { ok: true, value: { entry_points_reviewed: reviewed, findings: kept }, rejected };
}
/** Evidence rows are `key: value`; the marker is read back by these keys. */
const EV = { independence: 'independence: ', decisive: 'decisive_line: ', reasoning: 'reasoning: ', prompt: 'prompt_version: ' };
const INDEPENDENCE = ['subagent', 'sampling', 'same_context'];
const STORED_VERDICTS = ['exploitable', 'not_exploitable', 'undetermined'];
/** The `finding_validations` row (provider `llm`) for a verdict. */
export function toFindingValidation(record) {
    const independent = record.independence !== 'same_context';
    return {
        fingerprint: record.fingerprint,
        verdict: record.verdict,
        confidence: independent ? 'high' : 'low',
        provider: 'llm',
        evidence: [
            { detail: EV.independence + record.independence },
            { detail: EV.decisive + record.decisive_line },
            { detail: EV.reasoning + record.reasoning },
            { detail: EV.prompt + record.prompt_version },
        ],
        coverage_gaps: independent ? [] : ['same_context: the judge shared the scan\'s context, so the verdict is advisory'],
        // The verdict is about a tree, not a surface snapshot.
        snapshot_id: 0,
        tree_hash: record.tree_hash,
        computed_at: record.computed_at,
    };
}
/** The marker the open set attaches for a row; null for a row of any other provider. */
export function llmMarkerOf(validation) {
    if (validation.provider !== 'llm' || !STORED_VERDICTS.includes(validation.verdict))
        return null;
    const field = (prefix) => validation.evidence.find((e) => e.detail.startsWith(prefix))?.detail.slice(prefix.length);
    const independence = field(EV.independence);
    const decisive = field(EV.decisive);
    const reasoning = field(EV.reasoning);
    const prompt = field(EV.prompt);
    if (independence === undefined || !INDEPENDENCE.includes(independence))
        return null;
    if (decisive === undefined || reasoning === undefined || prompt === undefined)
        return null;
    return {
        verdict: validation.verdict,
        independent: independence !== 'same_context',
        independence: independence,
        decisive_line: decisive,
        reasoning,
        prompt_version: prompt,
    };
}
//# sourceMappingURL=submission.js.map