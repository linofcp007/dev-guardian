/**
 * `findingIdentity.ts` — the line-independent identity a finding keeps when
 * the code around it moves.
 *
 * Every case builds the findings the way a scanner does (`makeFinding`, so the
 * fingerprint is the real one) and feeds the source through a real file on
 * disk wherever the identity is meant to come from it, because "read from
 * disk" is the path modern Semgrep forces: without login its `extra.lines` is
 * the literal string "requires login".
 */

import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  assignIdentities,
  dependencyCoordinates,
  indexFindings,
  isCredentialFinding,
  makeSourceReader,
  REDACTED_SNIPPET,
  resolutionKey,
} from '../../../src/fingerprint/findingIdentity.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';
import type { Finding } from '../../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function project(files: Record<string, string>): string {
  const dir = makeTempDir('finding-identity-');
  writeFiles(dir, files);
  return dir;
}

function writeFiles(dir: string, files: Record<string, string>): void {
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, content);
  }
}

/** What modern Semgrep reports without login: real lines, redacted text. */
function semgrepHit(rule: string, path: string, line: number, lineEnd = line): Finding {
  return makeFinding({
    tool: 'semgrep',
    rule_id: rule,
    severity: 'high',
    category: 'security',
    title: rule,
    file_path: path,
    line_start: line,
    line_end: lineEnd,
    snippet: REDACTED_SNIPPET,
  });
}

function identify(dir: string, findings: Finding[]): Finding[] {
  return assignIdentities(findings, { projectPath: dir, readSource: makeSourceReader(dir) });
}

function only(findings: readonly Finding[]): Finding {
  const [first, ...rest] = findings;
  if (first === undefined || rest.length > 0) throw new Error(`expected one finding, got ${findings.length}`);
  return first;
}

const APP = ['const a = 1;', 'eval(userInput);', 'const b = 2;', ''].join('\n');
const APP_SHIFTED = ['// a comment someone added', APP].join('\n');

describe('assignIdentities — the reproduction: one line inserted above', () => {
  it('keeps the identity when the finding moves down a line, although the fingerprint changes', () => {
    const dir = project({ 'src/app.js': APP });
    const before = only(identify(dir, [semgrepHit('js.eval', 'src/app.js', 2)]));

    writeFiles(dir, { 'src/app.js': APP_SHIFTED });
    const after = only(identify(dir, [semgrepHit('js.eval', 'src/app.js', 3)]));

    expect(after.fingerprint).not.toBe(before.fingerprint); // the old key breaks…
    expect(before.identity).toMatch(/^[0-9a-f]{64}$/);
    expect(after.identity).toBe(before.identity); // …the new one does not
    expect(after.content_key).toBe(before.content_key);
  });

  it('ignores indentation and line-ending changes on the flagged line', () => {
    const dir = project({ 'a.js': 'x;\n    eval(userInput);\n' });
    const before = only(identify(dir, [semgrepHit('js.eval', 'a.js', 2)]));
    writeFiles(dir, { 'a.js': 'x;\r\n\teval(userInput);   \r\n' });
    const after = only(identify(dir, [semgrepHit('js.eval', 'a.js', 2)]));
    expect(after.identity).toBe(before.identity);
  });

  it('changes the identity when the flagged code itself changes', () => {
    const dir = project({ 'a.js': 'eval(userInput);\n' });
    const before = only(identify(dir, [semgrepHit('js.eval', 'a.js', 1)]));
    writeFiles(dir, { 'a.js': 'eval(otherInput);\n' });
    const after = only(identify(dir, [semgrepHit('js.eval', 'a.js', 1)]));
    expect(after.fingerprint).toBe(before.fingerprint); // redacted snippet, same line
    expect(after.identity).not.toBe(before.identity);
  });
});

describe('assignIdentities — occurrence', () => {
  it('tells identical lines apart by their order, and keeps both across a shift', () => {
    const body = 'eval(userInput);\nnoop();\neval(userInput);\n';
    const dir = project({ 'a.js': body });
    const before = identify(dir, [semgrepHit('js.eval', 'a.js', 3), semgrepHit('js.eval', 'a.js', 1)]);
    expect(new Set(before.map((f) => f.identity)).size).toBe(2);
    expect(before[0]?.content_key).toBe(before[1]?.content_key);

    writeFiles(dir, { 'a.js': `// header\n${body}` });
    const after = identify(dir, [semgrepHit('js.eval', 'a.js', 2), semgrepHit('js.eval', 'a.js', 4)]);
    // Order of the input does not matter; the line order does.
    expect(after.find((f) => f.line_start === 2)?.identity).toBe(
      before.find((f) => f.line_start === 1)?.identity,
    );
    expect(after.find((f) => f.line_start === 4)?.identity).toBe(
      before.find((f) => f.line_start === 3)?.identity,
    );
  });

  it('gives a repeated fingerprint the identity of its first copy (the DB keeps one row)', () => {
    const dir = project({ 'a.js': 'eval(userInput);\neval(userInput);\n' });
    const dup = semgrepHit('js.eval', 'a.js', 1);
    const out = identify(dir, [dup, { ...dup }, semgrepHit('js.eval', 'a.js', 2)]);
    expect(out[0]?.identity).toBe(out[1]?.identity);
    // The second real instance is occurrence 1, not 2: the duplicate did not count.
    const lone = identify(dir, [dup, semgrepHit('js.eval', 'a.js', 2)]);
    expect(out[2]?.identity).toBe(lone[1]?.identity);
  });

  it('is part of the identity only within one (tool, rule, path, content)', () => {
    const dir = project({ 'a.js': 'eval(userInput);\n', 'b.js': 'eval(userInput);\n' });
    const out = identify(dir, [semgrepHit('js.eval', 'a.js', 1), semgrepHit('js.eval', 'b.js', 1)]);
    expect(out[0]?.identity).not.toBe(out[1]?.identity);
  });
});

describe('assignIdentities — where the content comes from', () => {
  it('reads the lines from disk even when the snippet is present, so a snippet that embeds line numbers (bandit) does not leak them into the identity', () => {
    const dir = project({ 'x.py': 'import pickle\ndata = pickle.loads(user_input)\n' });
    const bandit = (line: number, code: string): Finding =>
      makeFinding({
        tool: 'bandit', rule_id: 'B301', severity: 'medium', category: 'security', title: 'pickle',
        file_path: 'x.py', line_start: line, line_end: line, snippet: code,
      });
    const before = only(identify(dir, [bandit(2, '1 import pickle\n2 data = pickle.loads(user_input)\n')]));
    writeFiles(dir, { 'x.py': '# header\nimport pickle\ndata = pickle.loads(user_input)\n' });
    const after = only(identify(dir, [bandit(3, '2 import pickle\n3 data = pickle.loads(user_input)\n')]));
    expect(after.identity).toBe(before.identity);
  });

  it('falls back to the snippet when the file cannot be read, and hashes the same text the same way', () => {
    const dir = project({ 'a.js': 'x;\neval(userInput);\n' });
    const fromDisk = only(identify(dir, [semgrepHit('js.eval', 'a.js', 2)]));
    const withSnippet = makeFinding({
      tool: 'semgrep', rule_id: 'js.eval', severity: 'high', category: 'security', title: 'js.eval',
      file_path: 'a.js', line_start: 2, line_end: 2, snippet: 'eval(userInput);',
    });
    // No reader at all: the only source of the text is Semgrep's own snippet
    // (a machine with `semgrep login`).
    const fromSnippet = only(assignIdentities([withSnippet], { projectPath: dir }));
    expect(fromSnippet.content_key).toBe(fromDisk.content_key);
    expect(fromSnippet.identity).toBe(fromDisk.identity);
  });

  it('never uses the "requires login" placeholder as content', () => {
    const a = only(assignIdentities([semgrepHit('js.eval', 'gone.js', 1)], {}));
    const b = only(assignIdentities([
      makeFinding({
        tool: 'semgrep', rule_id: 'js.eval', severity: 'high', category: 'security', title: 'js.eval',
        file_path: 'gone.js', line_start: 1, line_end: 1, snippet: 'requires login',
      }),
    ], {}));
    const withText = only(assignIdentities([
      makeFinding({
        tool: 'semgrep', rule_id: 'js.eval', severity: 'high', category: 'security', title: 'js.eval',
        file_path: 'gone.js', line_start: 1, line_end: 1, snippet: 'requires login ',
      }),
    ], {}));
    expect(a.content_key).toBe(b.content_key);
    // Trailing whitespace collapses: still the placeholder, still not content.
    expect(withText.content_key).toBe(a.content_key);
  });

  it('reads each file once however many findings it holds, whatever order they arrive in', () => {
    const files: Record<string, string> = { 'a.js': 'eval(1);\neval(2);\n', 'b.js': 'eval(3);\n' };
    const calls: string[] = [];
    const out = assignIdentities(
      [
        semgrepHit('js.eval', 'a.js', 1),
        semgrepHit('js.eval', 'b.js', 1),
        semgrepHit('js.eval', 'a.js', 2),
      ],
      {
        readSource: (p) => {
          calls.push(p);
          return files[p] ?? null;
        },
      },
    );
    expect(calls.sort()).toEqual(['a.js', 'b.js']);
    expect(new Set(out.map((f) => f.content_key)).size).toBe(3);
  });

  it('never reads outside the project', () => {
    const outside = project({ 'private.txt': 'outside the project\n' });
    const dir = project({ 'a.js': 'x\n' });
    const read = makeSourceReader(dir);
    expect(read(join(outside, 'private.txt'))).toBeNull();
    expect(read('../' + 'private.txt')).toBeNull();
    expect(read('a.js')).toBe('x\n');
  });

  it('uses a gitleaks commit locator, not the working tree, for a finding that lives in history', () => {
    const dir = project({ 'cfg.js': 'const k = "redacted-by-gitleaks";\n' });
    const leak = (line: number): Finding =>
      makeFinding({
        tool: 'gitleaks', rule_id: 'aws-access-token', severity: 'high', category: 'security',
        subcategory: 'secret', title: 'AWS', file_path: 'cfg.js', line_start: line, line_end: line,
        snippet: 'rule=aws-access-token;commit=0123456789abcdef0123456789abcdef01234567',
      });
    const before = only(identify(dir, [leak(1)]));
    // The working tree moves on; the commit gitleaks reported does not.
    writeFiles(dir, { 'cfg.js': 'const unrelated = 1;\n' });
    const after = only(identify(dir, [leak(1)]));
    expect(after.identity).toBe(before.identity);
  });

  it('never returns or stores the text of a secret\'s line', () => {
    // Not a real credential shape on purpose — this file must not trip the
    // repo's own secret scanners; what matters is that the text never escapes.
    const sensitive = ['plaintext', 'never', 'stored'].join('-');
    const dir = project({ 'cfg.js': `x;\nconnect("${sensitive}");\n` });
    const leak = makeFinding({
      tool: 'trivy', rule_id: 'aws-access-key-id', severity: 'critical', category: 'security',
      subcategory: 'secret', title: 'AWS', file_path: 'cfg.js', line_start: 2, line_end: 2,
    });
    const out = only(identify(dir, [leak]));
    expect(out.content_key).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(out)).not.toContain(sensitive);
    expect(out.snippet).toBeUndefined();
  });
});

/**
 * A secret's identity lands in the committed `.guardian/baseline.json`. A
 * fast unsalted hash of the line there is an offline oracle: for a
 * low-entropy value (`DB_PASSWORD=<guess>` in a scanned .env), guess, hash,
 * compare. So a credential finding's content is keyed on its rule — never on
 * the line — and its identity stays line-independent through the occurrence.
 */
describe('assignIdentities — credential findings are never keyed on their line', () => {
  const sha = (text: string): string => createHash('sha256').update(text).digest('hex');
  /** Every hash of the line a content key could plausibly have been. */
  const lineHashes = (line: string): string[] => [
    sha(line), sha(`${line}\n`), sha(`text\n${line}`), sha(`text\n${line.replace(/\s+/g, ' ').trim()}`),
  ];

  const value = (n: number): string => ['guessable', 'value', String(n)].join('-');
  const cases: Array<{ label: string; line: (v: string) => string; finding: (line: number) => Finding }> = [
    {
      label: 'trivy secret',
      line: (v) => `DB_PASSWORD=${v}`,
      finding: (line) => makeFinding({
        tool: 'trivy', rule_id: 'generic-password', severity: 'high', category: 'security',
        subcategory: 'secret', title: 's', file_path: '.env', line_start: line, line_end: line,
      }),
    },
    {
      label: 'gitleaks, working tree (no commit)',
      line: (v) => `DB_PASSWORD=${v}`,
      finding: (line) => makeFinding({
        tool: 'gitleaks', rule_id: 'generic-api-key', severity: 'high', category: 'security',
        subcategory: 'secret', title: 's', file_path: '.env', line_start: line, line_end: line,
        snippet: 'rule=generic-api-key',
      }),
    },
    {
      label: 'bandit hardcoded password (subcategory is not "secret")',
      line: (v) => `password = "${v}"`,
      finding: (line) => makeFinding({
        tool: 'bandit', rule_id: 'B105', severity: 'low', category: 'security',
        subcategory: 'hardcoded_password_string', title: 's', file_path: '.env',
        line_start: line, line_end: line, snippet: `${line} password = "x"`,
      }),
    },
    {
      label: 'the shipped base.yml credential rule (semgrep, snippet redacted)',
      line: (v) => `const key = "${v}";`,
      finding: (line) => makeFinding({
        tool: 'semgrep', rule_id: 'hardcoded-aws-key', severity: 'high', category: 'security',
        subcategory: 'hardcoded-aws-key', title: 's', file_path: '.env',
        line_start: line, line_end: line, snippet: REDACTED_SNIPPET,
      }),
    },
  ];

  for (const c of cases) {
    it(`${c.label}: same identity when the VALUE changes and when the line moves; no hash of the line`, () => {
      const dir = project({ '.env': `A=1\n${c.line(value(1))}\n` });
      const first = only(identify(dir, [c.finding(2)]));

      writeFiles(dir, { '.env': `A=1\n${c.line(value(2))}\n` }); // rotated in place
      const rotated = only(identify(dir, [c.finding(2)]));
      writeFiles(dir, { '.env': `# header\nA=1\n${c.line(value(2))}\n` }); // and moved
      const moved = only(identify(dir, [c.finding(3)]));

      expect(rotated.identity).toBe(first.identity);
      expect(rotated.content_key).toBe(first.content_key);
      expect(moved.identity).toBe(first.identity);

      const persisted = JSON.stringify([first, rotated, moved]);
      for (const v of [value(1), value(2)]) {
        for (const h of lineHashes(c.line(v))) expect(persisted).not.toContain(h);
      }
    });
  }

  it('still tells two secrets of one rule in one file apart, by order', () => {
    const dir = project({ '.env': 'A=x\nB=y\n' });
    const secret = (line: number): Finding => makeFinding({
      tool: 'trivy', rule_id: 'generic-password', severity: 'high', category: 'security',
      subcategory: 'secret', title: 's', file_path: '.env', line_start: line, line_end: line,
    });
    const out = identify(dir, [secret(1), secret(2)]);
    expect(new Set(out.map((f) => f.identity)).size).toBe(2);
  });

  it('recognises credential rules by name, and not rules that merely mention a token', () => {
    for (const f of [
      { subcategory: 'secret' },
      { rule_id: 'B105', subcategory: 'hardcoded_password_string' },
      { rule_id: 'hardcoded-private-key' },
      { rule_id: 'generic.secrets.security.detected-generic-api-key.detected-generic-api-key' },
      { rule_id: 'javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret' },
    ]) expect(isCredentialFinding(f), JSON.stringify(f)).toBe(true);
    for (const f of [
      { rule_id: 'javascript.jsonwebtoken.security.jwt-none-alg.jwt-none-alg' },
      { rule_id: 'python.django.security.audit.csrf-exempt.no-csrf-exempt', subcategory: 'csrf-token' },
      { rule_id: 'javascript.express.security.audit.express-xss', subcategory: 'vuln' },
      { rule_id: 'CVE-2022-25883', subcategory: 'cve' },
    ]) expect(isCredentialFinding(f), JSON.stringify(f)).toBe(false);
  });

  it('keeps keying an ordinary finding on its line', () => {
    const dir = project({ 'a.js': 'eval(userInput);\n' });
    const out = only(identify(dir, [semgrepHit('js.eval', 'a.js', 1)]));
    expect(out.content_key).toBe(sha('text\neval(userInput);'));
  });
});

describe('assignIdentities — occurrence tie-break', () => {
  it('does not let two findings on the same line range swap identities when the line moves', () => {
    // Same rule, same file, same line range, so the same content from disk —
    // told apart only by their snippets. The fingerprint hashes the line
    // number, so ordering ties by fingerprint reshuffles them on a shift.
    const hit = (line: number, snippet: string): Finding => makeFinding({
      tool: 'semgrep', rule_id: 'js.eval', severity: 'high', category: 'security', title: 't',
      file_path: 'a.js', line_start: line, line_end: line, snippet,
    });
    for (let line = 1; line <= 24; line += 1) {
      const dir = project({ 'a.js': `${'\n'.repeat(line - 1)}eval(a); eval(b);\n` });
      const before = identify(dir, [hit(line, 'eval(a)'), hit(line, 'eval(b)')]);
      writeFiles(dir, { 'a.js': `${'\n'.repeat(line)}eval(a); eval(b);\n` });
      const after = identify(dir, [hit(line + 1, 'eval(a)'), hit(line + 1, 'eval(b)')]);
      const bySnippet = (fs: Finding[], s: string) => fs.find((f) => f.snippet === s)?.identity;
      expect(bySnippet(after, 'eval(a)'), `line ${line}`).toBe(bySnippet(before, 'eval(a)'));
      expect(bySnippet(after, 'eval(b)'), `line ${line}`).toBe(bySnippet(before, 'eval(b)'));
    }
  });
});

describe('assignIdentities — paths', () => {

  it('normalises the path: Windows separators and an absolute path inside the project agree with the relative one', () => {
    const dir = project({ 'src/app.js': APP });
    const rel = only(identify(dir, [semgrepHit('js.eval', 'src/app.js', 2)]));
    const win = only(identify(dir, [semgrepHit('js.eval', 'src\\app.js', 2)]));
    const abs = only(identify(dir, [semgrepHit('js.eval', join(dir, 'src', 'app.js'), 2)]));
    expect(win.identity).toBe(rel.identity);
    expect(abs.identity).toBe(rel.identity);
  });
});

describe('assignIdentities — dependency findings', () => {
  const trivyCve = (installed: string, fixed: string): Finding =>
    makeFinding({
      tool: 'trivy', rule_id: 'CVE-2022-25883', severity: 'high', category: 'security',
      subcategory: 'cve', title: 'semver ReDoS', file_path: 'package-lock.json',
      snippet: `semver@${installed}->${fixed}`,
    });

  it('keys on package@installed_version, never on the fixed version', () => {
    const before = only(assignIdentities([trivyCve('5.7.1', '')], {}));
    // The advisory database learned about a fix: Trivy's snippet — and so the
    // fingerprint — change, the finding does not.
    const after = only(assignIdentities([trivyCve('5.7.1', '5.7.2, 6.3.1')], {}));
    expect(after.fingerprint).not.toBe(before.fingerprint);
    expect(after.identity).toBe(before.identity);
  });

  it('changes when the installed version changes', () => {
    const a = only(assignIdentities([trivyCve('5.7.1', '5.7.2')], {}));
    const b = only(assignIdentities([trivyCve('5.7.2', '5.7.2')], {}));
    expect(b.identity).not.toBe(a.identity);
  });

  it('recovers scoped package names and each scanner\'s own encoding', () => {
    expect(dependencyCoordinates({ tool: 'trivy', subcategory: 'cve', snippet: '@babel/core@7.0.0->7.1.0' }))
      .toEqual({ name: '@babel/core', version: '7.0.0' });
    expect(dependencyCoordinates({ tool: 'npm-audit', subcategory: 'dependency', snippet: 'lodash@<4.17.21' }))
      .toEqual({ name: 'lodash', version: '<4.17.21' });
    expect(dependencyCoordinates({ tool: 'wpscan', subcategory: 'wordpress-plugin', snippet: 'component:akismet@4.1' }))
      .toEqual({ name: 'akismet', version: '4.1' });
    // A finding with a line is source code, whatever its snippet looks like.
    expect(dependencyCoordinates({ tool: 'trivy', subcategory: 'cve', snippet: 'a@1', line_start: 3 })).toBeNull();
    expect(dependencyCoordinates({ tool: 'semgrep', subcategory: 'vuln', snippet: 'user@example.com' })).toBeNull();
  });

  it('gives a finding with no file an identity from (target, package)', () => {
    const imageVuln = (target: string): Finding =>
      makeFinding({
        tool: 'trivy', rule_id: 'CVE-2023-0001', severity: 'high', category: 'security',
        subcategory: 'cve', title: 'openssl', file_path: target, snippet: 'openssl@3.0.1->3.0.2',
      });
    const a = only(assignIdentities([imageVuln('app:1 (debian 12.1)')], {}));
    const b = only(assignIdentities([imageVuln('app:1 (debian 12.1)')], {}));
    const c = only(assignIdentities([imageVuln('worker:1 (debian 12.1)')], {}));
    expect(b.identity).toBe(a.identity);
    expect(c.identity).not.toBe(a.identity);
  });
});

describe('resolutionKey — what create_fix_pr asks "is it still there?" by', () => {
  it('ignores the occurrence and the line for source findings', () => {
    const dir = project({ 'a.js': 'eval(userInput);\nnoop();\neval(userInput);\n' });
    const [first, second] = identify(dir, [semgrepHit('js.eval', 'a.js', 1), semgrepHit('js.eval', 'a.js', 3)]);
    if (first === undefined || second === undefined) throw new Error('two findings expected');
    expect(resolutionKey(first)).not.toBeNull();
    expect(resolutionKey(first)).toBe(resolutionKey(second));
  });

  it('is (rule, package) for a dependency finding — the installed version is what a fix changes', () => {
    const cve = (installed: string, tool = 'trivy'): Finding =>
      makeFinding({
        tool, rule_id: 'CVE-2022-25883', severity: 'high', category: 'security',
        subcategory: 'cve', title: 'semver', file_path: 'package-lock.json',
        snippet: `semver@${installed}->7.5.2`,
      });
    const [a] = assignIdentities([cve('5.7.1')], {});
    const [b] = assignIdentities([cve('7.5.1')], {});
    if (a === undefined || b === undefined) throw new Error('findings expected');
    expect(resolutionKey(a)).toBe(resolutionKey(b));
  });

  it('is null for a row written before identities existed', () => {
    expect(resolutionKey(semgrepHit('js.eval', 'a.js', 1))).toBeNull();
  });
});

describe('indexFindings — identity first, fingerprint only as the fallback', () => {
  const f = (fingerprint: string, identity?: string): Finding => ({
    fingerprint, tool: 't', severity: 'low', category: 'quality', title: 't', fix_available: false,
    ...(identity !== undefined ? { identity } : {}),
  });

  it('matches by identity even when the fingerprint moved', () => {
    expect(indexFindings([f('fp1', 'id1')]).find(f('fp2', 'id1'))?.fingerprint).toBe('fp1');
  });

  it('falls back to the fingerprint when either side has no identity (a legacy row or a v1 baseline entry)', () => {
    expect(indexFindings([f('fp1')]).has(f('fp1', 'id1'))).toBe(true);
    expect(indexFindings([f('fp1', 'id1')]).has(f('fp1'))).toBe(true);
  });

  it('does not let an equal fingerprint override two different identities', () => {
    // Same rule, same line, redacted snippet — but the code on that line changed.
    expect(indexFindings([f('fp1', 'id1')]).has(f('fp1', 'id2'))).toBe(false);
  });
});
