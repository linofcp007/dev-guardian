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
import type { ProjectTextRead } from '../platform/projectFs.js';
import type { FindingValidation } from '../validate/types.js';
import { HUNT_CLASSES, type HuntClass } from './classes.js';
import type { HuntFinding, HuntResult, Independence, LlmMarker, LlmVerdict, VerifyVerdict } from './types.js';

/** US-1.AC-15 */
export const MAX_SUBMISSION_BYTES = 64 * 1024;
/** US-2.AC-7 */
export const MAX_HUNT_FINDINGS = 50;
/** US-1.AC-3 */
export const MAX_REASONING_WORDS = 120;
export const MAX_EVIDENCE_WORDS = 60;
export const MAX_TITLE_CHARS = 200;

/** The contained reader's signature (`readProjectText`). */
export type ProjectReader = (root: string, path: string, maxBytes?: number) => ProjectTextRead;

export interface SubmissionContext {
  /** Canonical project root. */
  root: string;
  reader: ProjectReader;
}

export interface SubmissionError {
  /** The offending field (`verdict`, `findings[3].file`, …), `$` for the whole payload. */
  path: string;
  problem: string;
}

/**
 * A whole submission is refused (`ok: false`) when it is too large, not the
 * schema's shape, or — a hunt — holds more than {@link MAX_HUNT_FINDINGS}
 * findings. Otherwise each hunt finding is judged on its own (US-2.AC-3:
 * "validar cada um … e guardar os válidos"): `value` keeps the valid ones and
 * `rejected` names the others. A verify submission is one verdict, so it is
 * either accepted whole (`rejected: []`) or refused.
 */
export type SubmissionCheck<T> =
  | { ok: true; value: T; rejected: SubmissionError[] }
  | { ok: false; code: 'too_large' | 'invalid'; errors: SubmissionError[] };

const VERDICTS = ['real', 'not_real', 'undetermined'] as const;
const VERIFY_KEYS = ['verdict', 'attacker_input', 'operation', 'decisive_line', 'reasoning'] as const;
const HUNT_KEYS = ['entry_points_reviewed', 'findings'] as const;
const FINDING_KEYS = ['file', 'line', 'class', 'title', 'attacker', 'evidence'] as const;
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

const CLASS_SET: ReadonlySet<string> = new Set(HUNT_CLASSES);

type Errors = SubmissionError[];

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const wordCount = (s: string): number => s.split(/\s+/).filter((w) => w !== '').length;

/** The serialized size, or null when the payload cannot be serialized at all. */
function serializedBytes(payload: unknown): number | null {
  try {
    const text = JSON.stringify(payload);
    return text === undefined ? null : Buffer.byteLength(text, 'utf8');
  } catch {
    return null;
  }
}

/** Size gate shared by both submissions: the failure to return, or null to go on. */
function sizeGate(payload: unknown): SubmissionCheck<never> | null {
  const bytes = serializedBytes(payload);
  if (bytes === null) return { ok: false, code: 'invalid', errors: [{ path: '$', problem: 'payload is not serializable JSON' }] };
  if (bytes > MAX_SUBMISSION_BYTES) {
    return { ok: false, code: 'too_large', errors: [{ path: '$', problem: `payload is over ${MAX_SUBMISSION_BYTES} bytes serialized` }] };
  }
  return null;
}

function unknownKeys(obj: Record<string, unknown>, allowed: readonly string[], prefix: string, errors: Errors): void {
  let index = 0;
  for (const key of Object.keys(obj)) {
    if (allowed.includes(key)) continue;
    // The path is fixed; only a short identifier-shaped key is named in the
    // problem, anything else is never reproduced.
    const named = key.length <= MAX_ECHOED_KEY_CHARS && /^[A-Za-z_][A-Za-z0-9_]*$/.test(key);
    errors.push({ path: `${prefix}[unknown field #${index}]`, problem: named ? `unknown field ${key}` : 'unknown field' });
    index += 1;
  }
}

function textField(obj: Record<string, unknown>, key: string, prefix: string, errors: Errors): string | null {
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

function containedPath(raw: string): string | null {
  if (raw === '' || raw.includes('\0')) return null;
  const slashed = raw.replace(/\\/g, '/');
  if (slashed.startsWith('/') || /^[A-Za-z]:/.test(slashed)) return null;
  // A colon past the drive check is a Windows alternate data stream.
  if (slashed.includes(':')) return null;
  const normal = posix.normalize(slashed);
  if (normal === '..' || normal.startsWith('../') || normal === '.') return null;
  // Reserved device names open a device, not a file, in any segment and any case.
  if (normal.split('/').some((seg) => WINDOWS_DEVICE.test(seg))) return null;
  return normal;
}

type LineProblem =
  | 'not inside the project'
  | 'file not found'
  | 'file could not be read'
  | 'line outside the file'
  | 'too many distinct files cited';

/** What is kept of a read: never its text. */
type Looked = { status: 'ok'; lines: number } | { status: 'absent' } | { status: 'refused' };

/** Looks one `file:line` up on disk through the contained reader, once per file. */
class CitationChecker {
  private readonly looked = new Map<string, Looked>();
  constructor(private readonly ctx: SubmissionContext) {}

  /** The reason a citation does not hold, or null when it does. */
  check(file: string, line: number): LineProblem | null {
    const path = containedPath(file);
    if (path === null) return 'not inside the project';
    if (!Number.isSafeInteger(line) || line < 1) return 'line outside the file';
    let seen = this.looked.get(path);
    if (seen === undefined) {
      if (this.looked.size >= MAX_CITED_FILES) return 'too many distinct files cited';
      seen = this.look(path);
      this.looked.set(path, seen);
    }
    if (seen.status === 'absent') return 'file not found';
    if (seen.status === 'refused') return 'file could not be read';
    return line > seen.lines ? 'line outside the file' : null;
  }

  private look(path: string): Looked {
    const read = this.ctx.reader(this.ctx.root, path, MAX_CITED_FILE_BYTES);
    if (read.status !== 'ok') return { status: read.status };
    // Lines, not counting the empty "line" after a final newline.
    return { status: 'ok', lines: read.text === '' ? 0 : read.text.replace(/\r?\n$/, '').split(/\r?\n/).length };
  }
}

const CITATION = /^(.+):(\d+)$/;
const DECISIVE = /^(.+?):(\d+) — \S/;

function checkCitation(checker: CitationChecker, field: string, text: string, form: RegExp, errors: Errors): void {
  const m = form.exec(text);
  const file = m?.[1];
  const line = m?.[2];
  if (file === undefined || line === undefined) {
    errors.push({ path: field, problem: field === 'decisive_line' ? 'must have the form file:line — reason' : 'must have the form file:line' });
    return;
  }
  const problem = checker.check(file, Number(line));
  if (problem !== null) errors.push({ path: field, problem: `citation: ${problem}` });
}

export function validateVerifySubmission(payload: unknown, ctx: SubmissionContext): SubmissionCheck<VerifyVerdict> {
  const gate = sizeGate(payload);
  if (gate !== null) return gate;
  if (!isRecord(payload)) return { ok: false, code: 'invalid', errors: [{ path: '$', problem: 'must be a JSON object' }] };

  const errors: Errors = [];
  unknownKeys(payload, VERIFY_KEYS, '', errors);
  const verdict = payload['verdict'];
  if (verdict === undefined) errors.push({ path: 'verdict', problem: 'missing field' });
  else if (typeof verdict !== 'string' || !(VERDICTS as readonly string[]).includes(verdict)) {
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
    if (attacker !== 'none') checkCitation(checker, 'attacker_input', attacker, CITATION, errors);
    checkCitation(checker, 'operation', operation, CITATION, errors);
    checkCitation(checker, 'decisive_line', decisive, DECISIVE, errors);
  }
  if (errors.length > 0 || attacker === null || operation === null || decisive === null || reasoning === null) {
    return { ok: false, code: 'invalid', errors };
  }
  const value: VerifyVerdict = {
    verdict: verdict as VerifyVerdict['verdict'],
    attacker_input: attacker,
    operation,
    decisive_line: decisive,
    reasoning,
  };
  return { ok: true, value, rejected: [] };
}

/** `file:line`, or a span `file:12-14` / `file:12–14` (both ends must exist). */
const EVIDENCE_REF = /^(.+?):(\d+)(?:[-–](\d+))?$/;

/**
 * Every `file:line` (or `file:a-b` span) in a piece of free text, URLs aside,
 * at most {@link MAX_EVIDENCE_REFS}. A model cites a span as often as a line,
 * and often in brackets: refusing those threw real findings away (measured,
 * v2 eval run).
 */
function evidenceRefs(evidence: string): Array<{ file: string; line: number; end?: number }> {
  const refs: Array<{ file: string; line: number; end?: number }> = [];
  for (const token of evidence.split(/[\s;,()[\]'"`]+/)) {
    if (token.includes('://')) continue;
    const m = EVIDENCE_REF.exec(token.replace(/[.:]+$/, ''));
    const file = m?.[1];
    const line = m?.[2];
    if (file === undefined || line === undefined) continue;
    const end = m?.[3];
    refs.push({ file, line: Number(line), ...(end !== undefined ? { end: Number(end) } : {}) });
    if (refs.length >= MAX_EVIDENCE_REFS) break;
  }
  return refs;
}

function validateFinding(raw: unknown, index: number, checker: CitationChecker): { value: HuntFinding | null; errors: Errors } {
  const prefix = `findings[${index}].`;
  const errors: Errors = [];
  if (!isRecord(raw)) return { value: null, errors: [{ path: `findings[${index}]`, problem: 'must be an object' }] };
  unknownKeys(raw, FINDING_KEYS, prefix, errors);
  const file = textField(raw, 'file', prefix, errors);
  const line = raw['line'];
  if (line === undefined) errors.push({ path: `${prefix}line`, problem: 'missing field' });
  else if (typeof line !== 'number' || !Number.isSafeInteger(line) || line < 1) {
    errors.push({ path: `${prefix}line`, problem: 'must be a positive integer' });
  }
  const cls = raw['class'];
  if (cls === undefined) errors.push({ path: `${prefix}class`, problem: 'missing field' });
  else if (typeof cls !== 'string' || !CLASS_SET.has(cls)) errors.push({ path: `${prefix}class`, problem: 'not one of the known classes' });
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
  if (problem !== null) errors.push({ path: `${prefix}file`, problem: `citation: ${problem}` });
  // At least one reference in the evidence must hold; the rest is free text.
  const holds = (r: { file: string; line: number; end?: number }): boolean =>
    checker.check(r.file, r.line) === null && (r.end === undefined || checker.check(r.file, r.end) === null);
  if (!evidenceRefs(evidence).some(holds)) {
    errors.push({ path: `${prefix}evidence`, problem: 'needs at least one file:line reference that exists in the project' });
  }
  if (errors.length > 0) return { value: null, errors };
  return { value: { file, line, class: cls as HuntClass, title, attacker, evidence }, errors };
}

export function validateHuntSubmission(payload: unknown, ctx: SubmissionContext): SubmissionCheck<HuntResult> {
  const gate = sizeGate(payload);
  if (gate !== null) return gate;
  if (!isRecord(payload)) return { ok: false, code: 'invalid', errors: [{ path: '$', problem: 'must be a JSON object' }] };

  const errors: Errors = [];
  unknownKeys(payload, HUNT_KEYS, '', errors);
  const reviewed = payload['entry_points_reviewed'];
  if (reviewed === undefined) errors.push({ path: 'entry_points_reviewed', problem: 'missing field' });
  else if (
    !Array.isArray(reviewed) ||
    reviewed.length > MAX_ENTRY_POINTS ||
    reviewed.some((e) => typeof e !== 'string' || e.length > MAX_ENTRY_POINT_CHARS)
  ) {
    errors.push({ path: 'entry_points_reviewed', problem: `must be at most ${MAX_ENTRY_POINTS} strings of at most ${MAX_ENTRY_POINT_CHARS} characters` });
  }
  const findings = payload['findings'];
  if (findings === undefined) errors.push({ path: 'findings', problem: 'missing field' });
  else if (!Array.isArray(findings)) errors.push({ path: 'findings', problem: 'must be an array' });
  else if (findings.length > MAX_HUNT_FINDINGS) errors.push({ path: 'findings', problem: `at most ${MAX_HUNT_FINDINGS} findings` });
  if (errors.length > 0 || !Array.isArray(findings) || !Array.isArray(reviewed)) return { ok: false, code: 'invalid', errors };

  const checker = new CitationChecker(ctx);
  const kept: HuntFinding[] = [];
  const rejected: Errors = [];
  findings.forEach((raw: unknown, i) => {
    const r = validateFinding(raw, i, checker);
    if (r.value !== null) kept.push(r.value);
    else rejected.push(...r.errors);
  });
  return { ok: true, value: { entry_points_reviewed: reviewed as string[], findings: kept }, rejected };
}

/** One `llm` verdict, as stored for a finding. */
export interface LlmVerdictRecord {
  fingerprint: string;
  verdict: LlmVerdict;
  independence: Independence;
  decisive_line: string;
  reasoning: string;
  prompt_version: string;
  /** The tree the verdict was given against. */
  tree_hash: string;
  computed_at: string;
}

/** Evidence rows are `key: value`; the marker is read back by these keys. */
const EV = { independence: 'independence: ', decisive: 'decisive_line: ', reasoning: 'reasoning: ', prompt: 'prompt_version: ' } as const;
const INDEPENDENCE: readonly string[] = ['subagent', 'sampling', 'same_context'];
const STORED_VERDICTS: readonly string[] = ['exploitable', 'not_exploitable', 'undetermined'];

/** The `finding_validations` row (provider `llm`) for a verdict. */
export function toFindingValidation(record: LlmVerdictRecord): FindingValidation {
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
export function llmMarkerOf(validation: FindingValidation): LlmMarker | null {
  if (validation.provider !== 'llm' || !STORED_VERDICTS.includes(validation.verdict)) return null;
  const field = (prefix: string): string | undefined =>
    validation.evidence.find((e) => e.detail.startsWith(prefix))?.detail.slice(prefix.length);
  const independence = field(EV.independence);
  const decisive = field(EV.decisive);
  const reasoning = field(EV.reasoning);
  const prompt = field(EV.prompt);
  if (independence === undefined || !INDEPENDENCE.includes(independence)) return null;
  if (decisive === undefined || reasoning === undefined || prompt === undefined) return null;
  return {
    verdict: validation.verdict as LlmVerdict,
    independent: independence !== 'same_context',
    independence: independence as Independence,
    decisive_line: decisive,
    reasoning,
    prompt_version: prompt,
  };
}
