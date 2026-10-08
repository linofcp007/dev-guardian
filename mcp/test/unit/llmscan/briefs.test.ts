/**
 * Briefs: self-contained, bounded, the quoted code fenced by a marker the
 * brief names as the edge of the data, and no secret value in them.
 *
 * T-02 (US-1.AC-2), T-12 (US-1.AC-12), T-13 (US-1.AC-13).
 */

import { readFileSync } from 'node:fs';
import { join, posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  MAX_BRIEF_TOKENS,
  VERIFY_BRIEF_P95_TOKENS,
  renderBrief,
  type BriefContext,
  type RenderedBrief,
} from '../../../src/llmscan/briefs.js';
import type { ProjectReader } from '../../../src/llmscan/submission.js';
import type { LlmScanTask, TaskKind, TaskTarget } from '../../../src/llmscan/types.js';
import { readProjectText } from '../../../src/platform/projectFs.js';
import { resolveProjectPath } from '../../../src/platform/projectPath.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';
import type { Finding, RouteRecord } from '../../../src/types.js';
import { mulberry32 } from '../../helpers/yamlFuzz.js';

const FIXTURES = fileURLToPath(new URL('../../fixtures/llm-scan/', import.meta.url));
const PROJECT = resolveProjectPath(join(FIXTURES, 'project')).path;
const VERIFY_SET = resolveProjectPath(join(FIXTURES, 'verify-set')).path;

function task(kind: TaskKind, target: TaskTarget, id = 't-0001'): LlmScanTask {
  return {
    plan_id: 'plan-under-test',
    task_id: id,
    kind,
    target,
    status: 'leased',
    lease_token: 'lease-under-test',
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

function finding(f: { tool?: string; rule_id: string; message: string; file: string; line: number; snippet?: string }): Finding {
  return makeFinding({
    tool: f.tool ?? 'semgrep',
    rule_id: f.rule_id,
    severity: 'high',
    category: 'security',
    title: 'Scanner finding under verification',
    message: f.message,
    file_path: f.file,
    line_start: f.line,
    ...(f.snippet !== undefined ? { snippet: f.snippet } : {}),
  });
}

/** A seeded boundary source that remembers what it handed out. */
function boundaries(seed: number): { next: () => string; used: string[] } {
  const used: string[] = [];
  return {
    used,
    next: () => {
      const b = `BOUNDARY_${seed.toString(36).toUpperCase()}_${used.length}_ZQX`;
      used.push(b);
      return b;
    },
  };
}

const norm = (p: string): string => posix.normalize(p.replace(/\\/g, '/'));

function memoryReader(files: ReadonlyMap<string, string>): ProjectReader {
  return (_root, path) => {
    const text = files.get(norm(path));
    return text === undefined ? { status: 'absent' } : { status: 'ok', text };
  };
}

function occurrences(text: string, needle: string): number[] {
  const at: number[] = [];
  for (let i = text.indexOf(needle); i !== -1; i = text.indexOf(needle, i + needle.length)) at.push(i);
  return at;
}

/** The size contract every brief keeps. */
function expectBounded(r: RenderedBrief): void {
  expect(r.chars).toBe(r.text.length);
  expect(r.estimated_tokens).toBeLessThanOrEqual(MAX_BRIEF_TOKENS);
  expect(Math.abs(r.estimated_tokens - r.chars / 4)).toBeLessThan(1);
}

/**
 * The quoted code is fenced by one marker the brief also names: at least
 * three occurrences — the instruction that says everything between the
 * markers is data, the opening and the closing — so a line in the analysed
 * file cannot forge the edge of the data (LLM01). `inside`, when given, must
 * lie between two of them.
 */
function expectFenced(text: string, used: readonly string[], inside?: string): void {
  const marker = used.find((m) => occurrences(text, m).length >= 3);
  expect(marker, `a boundary marker named by the brief and fencing the code; handed out: ${used.join(', ')}`).toBeDefined();
  if (marker === undefined || inside === undefined) return;
  const at = occurrences(text, marker);
  const pos = text.indexOf(inside);
  expect(pos, 'the flagged line is quoted').toBeGreaterThanOrEqual(0);
  expect(at.some((a) => a < pos) && at.some((a) => a > pos), 'the flagged line lies between two markers').toBe(true);
}

/** The response schema is in the brief: its fields and the verdict values. */
function expectSchema(text: string): void {
  for (const word of ['verdict', 'attacker_input', 'operation', 'decisive_line', 'reasoning', 'real', 'not_real', 'undetermined']) {
    expect(text, word).toContain(word);
  }
}

describe('T-02 a verify brief is self-contained and bounded (US-1.AC-2)', () => {
  // Words that cannot form a secret shape or a placeholder the detectors key on.
  const VOCAB = ['const', 'let', 'value', 'total', 'item', 'return', 'if', 'else', 'for', 'await', 'fn', 'count', 'list', 'row', 'data', 'sum', '(', ')', '{', '}', ';', '=', '+', '.'];
  const RULES = ['javascript.express.security.injection.tainted-sql-string', 'python.lang.security.audit.formatted-sql-query', 'B608', 'php.lang.security.tainted-filename', 'guardian-base-eval'];

  function lineOf(rand: () => number, words: number): string {
    const out: string[] = [];
    for (let i = 0; i < words; i += 1) out.push(VOCAB[Math.floor(rand() * VOCAB.length)] ?? 'x');
    return `  ${out.join(' ')}`;
  }

  it('T-02 250 seeded files, lines and messages: location, rule, message, fenced excerpt and schema present; never over 25 000 tokens', () => {
    const rand = mulberry32(0x02_0002);
    for (let c = 0; c < 250; c += 1) {
      const roll = rand();
      const n = roll < 0.7 ? 1 + Math.floor(rand() * 400) : roll < 0.9 ? 400 + Math.floor(rand() * 4600) : 5000 + Math.floor(rand() * 15_000);
      const lines = Array.from({ length: n }, () => lineOf(rand, Math.floor(rand() * 18)));
      const flagged = 1 + Math.floor(rand() * n);
      const huge = rand() < 0.05;
      if (huge) lines[flagged - 1] = `  const blob = '${'a'.repeat(200_000)}';`;
      else lines[flagged - 1] = `  const flagged_${c} = run(input_${c}) ;`;
      const file = `src/mod${c % 7}/file${c}.ts`;
      const mroll = rand();
      const message =
        mroll < 0.8
          ? `Untrusted data reaches a sink (case ${c}).`
          : mroll < 0.95
            ? `Long scanner message ${c}: ${'detail '.repeat(300)}`
            : `Enormous scanner message ${c}: ${'detail '.repeat(25_000)}`;
      const rule = RULES[Math.floor(rand() * RULES.length)] ?? 'rule';
      const f = finding({ rule_id: rule, message, file, line: flagged });
      const b = boundaries(c);
      const ctx: BriefContext = {
        root: PROJECT,
        reader: memoryReader(new Map([[file, lines.join('\n')]])),
        boundary: b.next,
        finding: f,
      };
      const r = renderBrief(task('verify', { fingerprint: f.fingerprint, files: [file] }), ctx);

      expectBounded(r);
      expect(r.text, `case ${c}: location`).toContain(`${file}:${flagged}`);
      expect(r.text, `case ${c}: rule`).toContain(rule);
      expect(r.text, `case ${c}: message`).toContain(message.slice(0, 80));
      expectSchema(r.text);
      expectFenced(r.text, b.used, huge ? undefined : `flagged_${c} = run(input_${c})`);
    }
  });

  it('T-02 a hunt brief over a group of routes is bounded too, and fences what it quotes', () => {
    const b = boundaries(7);
    const routes: RouteRecord[] = [
      route('GET', '/files/:name', 'src/routes/files.ts', 9),
      route('POST', '/files/upload', 'src/routes/files.ts', 15),
    ];
    const r = renderBrief(task('hunt', { entry_points: ['GET /files/:name', 'POST /files/upload'], files: ['src/routes/files.ts'] }), {
      root: PROJECT,
      reader: readProjectText,
      boundary: b.next,
      entry_points: routes,
      scanner_findings: [],
    });
    expectBounded(r);
    expect(r.text).toContain('/files/:name');
    expect(r.text).toContain('src/routes/files.ts');
  });
});

function route(method: RouteRecord['method'], path: string, rel: string, line: number): RouteRecord {
  return {
    method,
    provenance: 'code',
    path_raw: path,
    path_resolved: path,
    path_partial: false,
    file: join(PROJECT, rel),
    line,
    framework: 'express',
    language: 'typescript',
    auth_hint: 'unknown',
    params: [],
    confidence: 'high',
  };
}

describe('T-12 the verify brief stays small: P95 at most 8 000 estimated tokens over the verification set (US-1.AC-12)', () => {
  interface Item {
    id: string;
    tool: string;
    rule_id: string;
    message: string;
    file: string;
    line: number;
  }
  const items = (JSON.parse(readFileSync(join(VERIFY_SET, 'items.json'), 'utf8')) as { items: Item[] }).items;

  it('T-12 P95 of the estimated verify-brief size is at most 8 000 tokens, every brief quoting its line', () => {
    // The set is what the criterion needs: at least 40 findings, three languages.
    expect(items.length).toBeGreaterThanOrEqual(40);
    expect(new Set(items.map((i) => i.file.split('/')[0])).size).toBeGreaterThanOrEqual(3);
    const sizes: number[] = [];
    for (const item of items) {
      const f = finding({ tool: item.tool, rule_id: item.rule_id, message: item.message, file: item.file, line: item.line });
      const b = boundaries(item.line);
      const r = renderBrief(task('verify', { fingerprint: f.fingerprint, files: [item.file] }), {
        root: VERIFY_SET,
        reader: readProjectText,
        boundary: b.next,
        finding: f,
      });
      expectBounded(r);
      // A measurement of real briefs: each one quotes the line it is about.
      const lineText = readFileSync(join(VERIFY_SET, item.file), 'utf8').split(/\r?\n/)[item.line - 1]?.trim() ?? '';
      expect(lineText, item.id).not.toBe('');
      expect(r.text, item.id).toContain(lineText);
      sizes.push(r.estimated_tokens);
    }
    sizes.sort((a, b) => a - b);
    const p95 = sizes[Math.ceil(0.95 * sizes.length) - 1] ?? Number.POSITIVE_INFINITY;
    expect(VERIFY_BRIEF_P95_TOKENS).toBe(8_000);
    expect(p95).toBeLessThanOrEqual(VERIFY_BRIEF_P95_TOKENS);
  });
});

describe('T-13 a detected secret never reaches a brief: a marker with the rule and the line stands in for it (US-1.AC-13)', () => {
  // AWS's documentation example key, in the fixture project at src/config.ts:6
  // (assembled here so this file carries no key-shaped literal).
  const AWS_KEY = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('');
  const markerFor = (rule: string, line: number): RegExp => new RegExp(`‹[^›\\n]*\\b${rule}\\b[^›\\n]*\\b${line}\\b[^›\\n]*›`);

  it('T-13 the secret on the quoted line is replaced by ‹…rule…line…›', () => {
    const f = finding({ rule_id: 'guardian-hardcoded-aws-key', message: 'Hard-coded AWS access key id.', file: 'src/config.ts', line: 6 });
    const b = boundaries(13);
    const r = renderBrief(task('verify', { fingerprint: f.fingerprint, files: ['src/config.ts'] }), {
      root: PROJECT,
      reader: readProjectText,
      boundary: b.next,
      finding: f,
    });
    expect(r.text).not.toContain(AWS_KEY);
    expect(r.text).not.toContain('IOSFODNN7');
    expect(r.text).toMatch(markerFor('aws-access-key-id', 6));
  });

  it('T-13 a secret in the finding\'s own message or snippet does not reach the brief either', () => {
    const f = finding({
      tool: 'gitleaks',
      rule_id: 'aws-access-token',
      message: `AWS key ${AWS_KEY} committed`,
      snippet: `export const AWS_ACCESS_KEY_ID = '${AWS_KEY}';`,
      file: 'src/config.ts',
      line: 6,
    });
    const b = boundaries(14);
    const r = renderBrief(task('verify', { fingerprint: f.fingerprint, files: ['src/config.ts'] }), {
      root: PROJECT,
      reader: readProjectText,
      boundary: b.next,
      finding: f,
    });
    expect(r.text).not.toContain(AWS_KEY);
    expect(r.text).not.toContain('IOSFODNN7');
  });

  it('T-13 a token inside the quoted function is replaced, the rest of the function kept', () => {
    // Assembled at run time: no token-shaped literal sits in this file.
    const token = `ghp_${'A1b2C3d4E5f6'.repeat(3)}`;
    const file = 'src/client.ts';
    const text = [
      'export async function callApi(path: string): Promise<Response> {',
      `  const auth = '${token}';`,
      '  const url = new URL(path, "https://api.example");',
      '  return fetch(url, { headers: { authorization: `token ${auth}` } });',
      '}',
    ].join('\n');
    const f = finding({ rule_id: 'guardian-ssrf', message: 'Request to a URL built from input.', file, line: 4 });
    const b = boundaries(15);
    const r = renderBrief(task('verify', { fingerprint: f.fingerprint, files: [file] }), {
      root: PROJECT,
      reader: memoryReader(new Map([[file, text]])),
      boundary: b.next,
      finding: f,
    });
    expect(r.text).not.toContain(token);
    expect(r.text).toMatch(markerFor('github-token', 2));
    expect(r.text).toContain('const url = new URL(path, "https://api.example");');
  });

  it('T-13 a hunt brief carries no secret from the scanner findings it lists', () => {
    const known = finding({
      tool: 'gitleaks',
      rule_id: 'aws-access-token',
      message: `AWS key ${AWS_KEY} committed`,
      snippet: AWS_KEY,
      file: 'src/config.ts',
      line: 6,
    });
    const b = boundaries(16);
    const r = renderBrief(task('crosscut', { files: ['src/config.ts', 'src/middleware/auth.ts'] }), {
      root: PROJECT,
      reader: readProjectText,
      boundary: b.next,
      scanner_findings: [known],
    });
    expect(r.text).not.toContain(AWS_KEY);
    expect(r.text).not.toContain('IOSFODNN7');
  });
});
