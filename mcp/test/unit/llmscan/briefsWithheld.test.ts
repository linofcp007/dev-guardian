/**
 * A verify brief never quotes an environment file, nor the file of a
 * credential finding (fix round 1 of the client-trust review, item 3).
 *
 * The client-trust pass reads git-ignored `.env.local` files, and a finding
 * there could be handed to `llm_scan` for verification: the brief quoted up
 * to 200 lines of the file, cleaned only by `scrubSecrets`, which knows a
 * provider's token shape and not `NEXT_PUBLIC_ADMIN_KEY=adm_8f7d6s5a4` — so
 * the value went to a model. The same holds for any credential finding
 * (`isCredentialFinding`, the rule `suggest_fix` already follows): its line
 * is the secret.
 */

import { posix } from 'node:path';
import { describe, expect, it } from 'vitest';
import { renderBrief } from '../../../src/llmscan/briefs.js';
import type { ProjectReader } from '../../../src/llmscan/submission.js';
import type { LlmScanTask, TaskTarget } from '../../../src/llmscan/types.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';

const ADMIN = ['adm', '8f7d6s5a4'].join('_');
const DB_PASSWORD = ['hunter', '2xQ9w'].join('');

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

function brief(file: string, text: string, rule: string, line: number): { text: string; reads: string[] } {
  const f = makeFinding({
    tool: 'semgrep',
    rule_id: rule,
    severity: 'high',
    category: 'security',
    title: 'A finding',
    message: 'Something to verify.',
    file_path: file,
    line_start: line,
  });
  const reads: string[] = [];
  const reader: ProjectReader = (_root, path) => {
    reads.push(path);
    return posix.normalize(path.replace(/\\/g, '/')) === file ? { status: 'ok', text } : { status: 'absent' };
  };
  let n = 0;
  const out = renderBrief(task({ fingerprint: f.fingerprint, files: [file] }), {
    root: 'r',
    reader,
    boundary: () => `BOUNDARY_WH_${String((n += 1))}_ZQX`,
    finding: f,
  }).text;
  return { text: out, reads };
}

describe('a verify brief withholds what is a secret', () => {
  it('T-35 an env file (a git-ignored .env.local too) is never read nor quoted', () => {
    const text = ['NEXT_PUBLIC_SUPABASE_URL=https://abcd.supabase.co', `NEXT_PUBLIC_ADMIN_KEY=${ADMIN}`, `DB_PASSWORD=${DB_PASSWORD}`].join('\n');
    for (const file of ['.env.local', 'apps/web/.env', 'apps/web/.env.production.local']) {
      const out = brief(file, text, 'client-env-public-secret', 2);
      expect(out.text).not.toContain(ADMIN);
      expect(out.text).not.toContain(DB_PASSWORD);
      expect(out.text).toContain('(not quoted: an environment file holds values, never code to read)');
      expect(out.reads).toEqual([]);
    }
  });

  it("T-35 a credential finding's file is not quoted either, whatever the file", () => {
    const text = ['export const config = {', `  password: '${DB_PASSWORD}',`, '};'].join('\n');
    const out = brief('src/config.ts', text, 'hardcoded-password', 2);
    expect(out.text).not.toContain(DB_PASSWORD);
    expect(out.text).toContain('(not quoted: the finding flags a credential, and its line is the secret)');
  });

  it('T-35 any other finding still gets its code quoted', () => {
    const text = ['export function roll() {', '  return Math.random();', '}'].join('\n');
    const out = brief('src/roll.ts', text, 'insecure-random', 2);
    expect(out.text).toContain('return Math.random();');
  });
});
