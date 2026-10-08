/**
 * A private key in the quoted code is removed, and nothing else with it
 * (US-1.AC-13, US-1.AC-2).
 *
 * The redaction removed a key's body "up to the END line". OWASP Juice Shop
 * keeps its RSA key on ONE line, as a JS string with `\r\n` escapes: the END
 * marker was on the BEGIN line, no later line held one, and every line after
 * the key — 179 of them in the Claude Code smoke test, 2026-10-08 — became
 * "‹private key body removed›". A finding further down that file was verified
 * against no code at all. A key's body is now only what follows the header and
 * looks like a key: base64 lines, quoted or not, up to the END line.
 */

import { posix } from 'node:path';
import { describe, expect, it } from 'vitest';
import { renderBrief } from '../../../src/llmscan/briefs.js';
import type { ProjectReader } from '../../../src/llmscan/submission.js';
import type { LlmScanTask, TaskTarget } from '../../../src/llmscan/types.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';

// Assembled at run time: no key-shaped literal sits in this file.
const BEGIN = ['-----BEGIN', 'RSA PRIVATE KEY-----'].join(' ');
const END = ['-----END', 'RSA PRIVATE KEY-----'].join(' ');
const BODY = ['MIICXAIBAAKBgQDNwqLEe9wgTXCbC7', 'Q5Fh0kL8rYv2W1aTqZPp3XbN7cKmH4', 'R2sJdVf9LgUeYhWiXoPqNz=='];

function task(target: TaskTarget): LlmScanTask {
  return {
    plan_id: 'p',
    task_id: 't-0001',
    kind: 'verify',
    target,
    status: 'leased',
    lease_token: 'l',
    lease_expires_at: null,
    attempts: 0,
    file_hashes: {},
    brief_chars: null,
    response_chars: null,
    independence: null,
    result: null,
    closed_reason: null,
    delivered_at: null,
    closed_at: null,
  };
}

function brief(file: string, text: string, line: number): string {
  const f = makeFinding({
    tool: 'semgrep',
    rule_id: 'insecure-random',
    severity: 'medium',
    category: 'security',
    title: 'Insecure randomness',
    message: 'Math.random() used for a security value.',
    file_path: file,
    line_start: line,
  });
  const reader: ProjectReader = (_root, path) =>
    posix.normalize(path.replace(/\\/g, '/')) === file ? { status: 'ok', text } : { status: 'absent' };
  let n = 0;
  return renderBrief(task({ fingerprint: f.fingerprint, files: [file] }), {
    root: 'r',
    reader,
    boundary: () => `BOUNDARY_PK_${String((n += 1))}_ZQX`,
    finding: f,
  }).text;
}

// Module-level code right after the key: no function holds the flagged line,
// so the excerpt is a window over the file, key included (as in the smoke test).
const AFTER = ['', 'export const resetSeed = Math.random().toString(36);', 'export const resetLength = 12;'];

describe('a private key is removed, and only the key', () => {
  it('a key on ONE line (a string with \\r\\n escapes) takes only its own line', () => {
    const text = ["import jwt from 'jsonwebtoken';", '', `const privateKey = '${BEGIN}\\r\\n${BODY.join('\\r\\n')}\\r\\n${END}';`, ...AFTER].join('\n');
    const out = brief('lib/insecurity.ts', text, 5);
    expect(out).not.toContain('private key body removed');
    expect(out).toContain('export const resetSeed = Math.random().toString(36);');
    expect(out).toContain('export const resetLength = 12;');
    for (const b of BODY) expect(out).not.toContain(b);
    expect(out).toMatch(/‹[^›\n]*private-key[^›\n]*line 3›/);
  });

  it('a key over several lines takes its body up to the END line, and the code after stays', () => {
    const text = ['const pem = `' + BEGIN, ...BODY, END + '`;', ...AFTER].join('\n');
    const out = brief('lib/keys.ts', text, 7);
    for (const b of BODY) expect(out).not.toContain(b);
    expect(out.split('private key body removed').length - 1).toBe(BODY.length + 1);
    expect(out).toContain('export const resetSeed = Math.random().toString(36);');
  });

  it('a key with no END line takes its base64 lines only, never the code below', () => {
    const text = ['const pem = [', `  '${BEGIN}',`, ...BODY.map((b) => `  '${b}',`), '];', ...AFTER].join('\n');
    const out = brief('lib/partial.ts', text, 8);
    for (const b of BODY) expect(out).not.toContain(b);
    expect(out).toContain('export const resetSeed = Math.random().toString(36);');
    expect(out).toContain('];');
  });
});
