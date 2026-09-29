/**
 * `dev-guardian check` as a user runs it (review of 3.0.0, M3):
 *
 *   - `check --file short.js --bash ls` printed "OK" and exited 0, ignoring
 *     `--file`; `--min bogus` silently became `medium`; `--jsn` was accepted.
 *     Conflicting or unknown arguments, and a bad `--min`, are a usage error
 *     now — exit 2, with a message.
 *   - A UTF-16 file — what PowerShell 5.1's `>` and `Out-File` write by
 *     default — was read as UTF-8, and a key in it read "No secrets
 *     detected". It is decoded by its byte-order mark, or when its bytes are
 *     NUL-interleaved.
 *
 * Requires a built `mcp/dist` (`npm run build`).
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { spawnSyncCapped, testTimeoutAbove } from '../helpers/spawnCap.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
/** Hang-breaker for one CLI run; nothing asserts by reaching it. */
const TIMEOUT_MS = 30_000;
// Above the cap, so a hung child is reported by the cap — naming it — and
// not by vitest's 10 s default failing the test after the fact (R7-I1).
vi.setConfig({ testTimeout: testTimeoutAbove(TIMEOUT_MS) });
const KEY = 'const k = "AKIAIOSFODNN7EXAMPLE";\n';

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'check-cli-'));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function check(...args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSyncCapped(process.execPath, [CLI, 'check', ...args], { cwd: dir, encoding: 'utf8', timeout: TIMEOUT_MS });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('check — arguments (review M3)', () => {
  it.each([
    [['--file', 'short.js', '--bash', 'ls'], /--file and --bash/],
    [['--bash', 'ls', '--file', 'short.js'], /--file and --bash/],
    [['--file', 'short.js', '--jsn'], /unknown argument: --jsn/],
    [['--bash', 'ls', 'extra'], /unknown argument: extra/],
    [['--file', 'short.js', '--min', 'bogus'], /--min must be high or medium/],
    [['--file', 'short.js', '--min=low'], /--min must be high or medium/],
    [['--file', 'short.js', '--min'], /--min needs a value/],
    [['--file'], /--file needs a value/],
    [['--bash'], /--bash needs a value/],
    [['--file', 'a.js', '--file', 'b.js'], /--file was given twice/],
    [['--bash', 'ls', '--min', 'high'], /--min applies to --file/],
    [['--file', 'short.js', '--powershell'], /--powershell applies to --bash/],
    [[], /provide --file <path> or --bash/],
  ])('check %j is a usage error (exit 2)', (args, message) => {
    writeFileSync(join(dir, 'short.js'), 'console.log(1);\n');
    const r = check(...args);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(message);
    expect(r.stdout).not.toMatch(/OK|No secrets/);
  });

  it('the valid forms still work', () => {
    writeFileSync(join(dir, 'short.js'), 'console.log(1);\n');
    writeFileSync(join(dir, 'leak.js'), KEY);
    expect(check('--file', 'short.js').status).toBe(0);
    expect(check('--file=short.js', '--min=high', '--json').status).toBe(0);
    expect(check('--file', 'leak.js', '--min', 'medium').status).toBe(1);
    expect(check('--bash', 'ls').status).toBe(0);
    expect(check('--bash=rm -rf /', '--json').status).toBe(1);
    expect(check('--bash', 'Remove-Item "C:\\Users\\" -Recurse -Force', '--powershell').status).toBe(1);
  });
});

// `--local-only` keeps Semgrep local — project rules plus the plugin's own
// packs, no registry — and nothing more: Trivy's database fetch and a .NET
// restore still go out (Semgrep's version check is off on every run since
// review 3.0, wave 2, local-only or not). The help text said "no
// registry download, no telemetry" and nothing about either half, which read
// as "nothing leaves the machine" (the same wording the tool descriptions and
// SECURITY.md now use).
describe('scan --help: what --local-only does and does not keep local', () => {
  it('names the plugin packs that still run and the traffic that still goes out', () => {
    const r = spawnSyncCapped(process.execPath, [CLI, 'scan', '--help'], { cwd: dir, encoding: 'utf8', timeout: TIMEOUT_MS });
    expect(r.status).toBe(0);
    const out = r.stdout ?? '';
    const start = out.indexOf('  --local-only');
    expect(start).toBeGreaterThan(0);
    const para = out.slice(start, out.indexOf('  --start-command', start)).replace(/\s+/g, ' ');
    expect(para).toMatch(/Keeps Semgrep local/);
    expect(para).toMatch(/plus the plugin's own packs \(the LLM-application pack still runs\)/);
    expect(para).toMatch(/no registry download/);
    expect(para).toMatch(/It is NOT "nothing leaves the machine"/);
    expect(para).toMatch(/Trivy still fetches its vulnerability database/);
    expect(para).toMatch(/restored from its NuGet feeds/);
    expect(para).toMatch(/SECURITY\.md, network egress/);
  });
});

// Round 2: the three READMEs and docs/ci.md say the same as the help text, in
// step with each other.
describe('--local-only in the READMEs and docs/ci.md (review round 2)', () => {
  it.each(['README.md', 'README.pt-PT.md', 'README.es.md', 'docs/ci.md'])(
    '%s names the plugin packs that still run and the traffic that still goes out',
    (rel) => {
      const text = readFileSync(join(REPO_ROOT, rel), 'utf8');
      const line = text.split('\n').find((l) => l.includes('--local-only') && l.includes('Trivy')) ?? '';
      expect(line).toMatch(/LLM/);
      expect(line).toMatch(/NuGet/);
      expect(line).toMatch(/SECURITY\.md#network-egress/);
      expect(line).toMatch(/Semgrep/);
    },
  );
});

describe('check --file — UTF-16 (review M3)', () => {
  const utf16be = (text: string): Buffer => {
    const le = Buffer.from(text, 'utf16le');
    for (let i = 0; i + 1 < le.length; i += 2) {
      const a = le[i] ?? 0;
      le[i] = le[i + 1] ?? 0;
      le[i + 1] = a;
    }
    return le;
  };

  it.each([
    ['UTF-16LE with a BOM (PowerShell 5.1 Out-File)', (): Buffer => Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(KEY, 'utf16le')])],
    ['UTF-16LE without a BOM', (): Buffer => Buffer.from(KEY, 'utf16le')],
    ['UTF-16BE with a BOM', (): Buffer => Buffer.concat([Buffer.from([0xfe, 0xff]), utf16be(KEY)])],
    ['UTF-16BE without a BOM', (): Buffer => utf16be(KEY)],
    ['UTF-8 with a BOM', (): Buffer => Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(KEY, 'utf8')])],
  ])('%s: the key is found (exit 1)', (_label, bytes) => {
    writeFileSync(join(dir, 'out.txt'), bytes());
    const r = check('--file', 'out.txt');
    expect(r.stdout).toMatch(/AWS access key/);
    expect(r.status).toBe(1);
  });

  it('a binary file with scattered NULs is not taken for UTF-16', () => {
    const bytes = Buffer.alloc(4096);
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = (i * 37) % 251;
    writeFileSync(join(dir, 'blob.bin'), bytes);
    expect(check('--file', 'blob.bin').status).toBe(0);
  });
});

describe('check — repository text in the human output (review of 3.0.0, item 2)', () => {
  it('a file name carrying a right-to-left override is printed with it escaped', () => {
    const rlo = String.fromCodePoint(0x202e);
    const name = `invoice${rlo}sj.exe`;
    writeFileSync(join(dir, name), KEY);
    const r = check('--file', name);
    expect(r.status).toBe(1);
    expect(r.stdout.includes(rlo)).toBe(false);
    expect(r.stdout).toContain('invoice\\u{202E}sj.exe');
  });
});
