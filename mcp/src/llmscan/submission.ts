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

import type { ProjectTextRead } from '../platform/projectFs.js';
import type { FindingValidation } from '../validate/types.js';
import type { HuntResult, Independence, LlmMarker, LlmVerdict, VerifyVerdict } from './types.js';

/** US-1.AC-15 */
export const MAX_SUBMISSION_BYTES = 64 * 1024;
/** US-2.AC-7 */
export const MAX_HUNT_FINDINGS = 50;
/** US-1.AC-3 */
export const MAX_REASONING_WORDS = 120;
export const MAX_EVIDENCE_WORDS = 60;
export const MAX_TITLE_CHARS = 200;

/** The contained reader's signature (`readProjectText`). */
export type ProjectReader = (root: string, path: string) => ProjectTextRead;

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

export function validateVerifySubmission(_payload: unknown, _ctx: SubmissionContext): SubmissionCheck<VerifyVerdict> {
  throw new Error('NotImplemented: validateVerifySubmission');
}

export function validateHuntSubmission(_payload: unknown, _ctx: SubmissionContext): SubmissionCheck<HuntResult> {
  throw new Error('NotImplemented: validateHuntSubmission');
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

/** The `finding_validations` row (provider `llm`) for a verdict. */
export function toFindingValidation(_record: LlmVerdictRecord): FindingValidation {
  throw new Error('NotImplemented: toFindingValidation');
}

/** The marker the open set attaches for a row; null for a row of any other provider. */
export function llmMarkerOf(_validation: FindingValidation): LlmMarker | null {
  throw new Error('NotImplemented: llmMarkerOf');
}
