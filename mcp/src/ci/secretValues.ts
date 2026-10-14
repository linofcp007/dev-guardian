/**
 * What a gitleaks finding's secret IS, for one gate run — as an HMAC under a
 * key this process draws once and never writes anywhere (review 10, finding
 * 5).
 *
 * The CI gate's tolerant key (`fingerprint/findingIdentity.ts#gateMatchKeys`)
 * keys a secret by (rule, path, occurrence), and counts the findings of two
 * commits on one line of history once, so a whitespace commit touching a
 * baselined secret does not make it new. That made a secret REPLACED in
 * place pass the gate: the base's `AKIA…QWERTY` on `config.js:2` and the
 * pull request's `AKIA…ZXCV` on the same line were one occurrence, and the
 * baseline's key matched the new one (3.2.1 exited 1, 3.3.0 exited 0). The
 * gate now compares the values of a slot's findings, and a slot holding two
 * is keyed by nothing (`mixedSlot`).
 *
 * The scans run gitleaks with `--redact`, and the database never holds a
 * secret or its hash. So the value is read back here, in memory, from where
 * the finding says it is: the line at that commit (`git cat-file blob
 * <commit>:<path>`) for a history finding, the working-tree file for the
 * files pass. Every whitespace is removed — a whitespace commit is the case
 * the collapse exists for — and the line is HMAC'd under {@link RUN_KEY}:
 * comparable within this process, useless outside it. Nothing is stored; the
 * values live in a `WeakMap` beside the finding objects the gate is handed.
 *
 * The line, not the secret alone: a redacted report carries no column the
 * secret could be cut out by. A commit that changes something else on a
 * secret's line therefore reads as a second value — that finding is judged
 * by its exact identity, and shows as new — the safe direction.
 *
 * A value that cannot be read (a commit or file gone, over {@link MAX_BLOB_BYTES},
 * past {@link MAX_BLOBS}) is undefined, and a slot holding one is mixed: never
 * a silent match.
 */

import { createHmac, randomBytes } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { readProjectText } from '../platform/projectFs.js';
import { git } from '../runners/git.js';
import type { Finding } from '../types.js';

/** Drawn once per process; never written, logged or returned. */
const RUN_KEY = randomBytes(32);

/** The largest file whose line is read (a blob, or a working-tree file). */
const MAX_BLOB_BYTES = 16 * 1024 * 1024;

/** At most this many distinct (commit, path) blobs read per run; the rest are unknown. */
const MAX_BLOBS = 2_000;

const values = new WeakMap<object, string>();
/** The findings {@link rememberSecretValues} tried to read, read or not. */
const attempted = new WeakSet<object>();

/** The finding's secret as this run's HMAC, or undefined when it was not read. */
export function secretValueOf(finding: object): string | undefined {
  return values.get(finding);
}

/**
 * Whether {@link rememberSecretValues} went over any finding of `findings` —
 * the gate's set. Without it (a caller that never read the values) the gate
 * compares none, as before 3.4.
 */
export function secretValuesRead(findings: readonly object[]): boolean {
  return findings.some((f) => attempted.has(f));
}

/** `rule=<id>;commit=<sha>` → the sha; null for a files-pass locator. */
function commitOf(snippet: string | undefined): string | null {
  const m = /;commit=([0-9a-f]{7,64})$/i.exec(snippet ?? '');
  return m?.[1] ?? null;
}

/** Lines `from`..`to` (1-based) of `text`, every whitespace removed; null when out of range. */
function linesOf(text: string, from: number, to: number): string | null {
  const lines = text.split(/\r?\n/);
  if (from < 1 || from > lines.length) return null;
  return lines.slice(from - 1, Math.max(from, Math.min(to, lines.length))).join('\n').replace(/\s+/g, '');
}

function hmac(text: string): string {
  return createHmac('sha256', RUN_KEY).update(text).digest('hex');
}

/**
 * Read and remember the value of every gitleaks finding of `findings` (the
 * gate's set, `projectPath` the scanned project). Never throws: a value it
 * cannot read is left unknown.
 */
export async function rememberSecretValues(projectPath: string, findings: readonly Finding[]): Promise<void> {
  const blobs = new Map<string, Promise<string | null>>();
  const blob = (commit: string, path: string): Promise<string | null> => {
    const key = `${commit}\n${path}`;
    let text = blobs.get(key);
    if (text === undefined) {
      if (blobs.size >= MAX_BLOBS) return Promise.resolve(null);
      text = git(projectPath, ['cat-file', 'blob', `${commit}:./${path}`]).then((r) =>
        r.exitCode === 0 && r.stdout.length <= MAX_BLOB_BYTES ? r.stdout : null,
      );
      blobs.set(key, text);
    }
    return text;
  };
  const tree = new Map<string, string | null>();
  const working = (path: string): string | null => {
    if (!tree.has(path)) {
      const r = readProjectText(projectPath, path, MAX_BLOB_BYTES);
      tree.set(path, r.status === 'ok' ? r.text : null);
    }
    return tree.get(path) ?? null;
  };

  for (const f of findings) {
    if (f.tool.toLowerCase() !== 'gitleaks') continue;
    attempted.add(f);
    if (f.line_start === undefined) continue;
    const path = (f.file_path ?? '').split('\\').join('/');
    if (path === '' || isAbsolute(path) || path === '..' || path.startsWith('../')) continue;
    try {
      const commit = commitOf(f.snippet);
      const text = commit !== null ? await blob(commit, path) : working(path);
      const line = text === null ? null : linesOf(text, f.line_start, f.line_end ?? f.line_start);
      if (line !== null) values.set(f, hmac(line));
    } catch {
      /* unknown — a slot holding it is mixed */
    }
  }
}
