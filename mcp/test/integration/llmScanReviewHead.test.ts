/**
 * The one head rule (3.18.0, DG-11a): llm_scan's subagents read the WORKING
 * TREE, so a finding a `review_pr` scan read at a head that is not the
 * checked-out commit cannot be verified here. The brief would quote another
 * version of the file, its hash would be pinned on that version, and an
 * independent `not_real` would demote the finding over code the review never
 * read. The rule is keyed on what the scan recorded (`meta.head_sha`), never on
 * `scanned_tree`, and holds for both inputs that name such findings: `scan_id`
 * (refused, `unsupported_target`) and `fingerprints` (each one `not_eligible`,
 * with the reason). Other scan types, and a review whose head IS checked out,
 * plan as before.
 *
 * The project is the llm-scan fixture made a real repository: `main` at the
 * base commit, `feature` one commit ahead, as `review_pr` reviews them.
 */

import { spawnSync } from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import {
  PARAM_INSERT,
  SHELL,
  SQLI,
  callTool,
  harness,
  seedScan,
  start,
  type Harness,
  type Raw,
  type SeedSpec,
} from '../helpers/llmScanHarness.js';

vi.setConfig({ testTimeout: 60_000 });
afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

function git(cwd: string, args: readonly string[]): string {
  const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

/** The fixture as a repository: `main` (base) and `feature` (one commit more, `src/routes/users.ts` changed), feature checked out. */
function repository(h: Harness): { base: string; head: string } {
  git(h.project, ['init', '-q']);
  git(h.project, ['symbolic-ref', 'HEAD', 'refs/heads/main']);
  git(h.project, ['add', '-A']);
  git(h.project, ['commit', '-qm', 'base']);
  const base = git(h.project, ['rev-parse', 'HEAD']);
  git(h.project, ['checkout', '-qb', 'feature']);
  appendFileSync(join(h.project, 'src', 'routes', 'users.ts'), '// reviewed change\n');
  git(h.project, ['commit', '-qam', 'change']);
  return { base, head: git(h.project, ['rev-parse', 'HEAD']) };
}

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const SAST_RULE = 'javascript.express.security.injection.tainted-sql-string';
const SPECS: SeedSpec[] = [
  { tool: 'semgrep', rule_id: SAST_RULE, loc: SQLI, message: 'User input flows into a SQL string.' },
  { tool: 'semgrep', rule_id: 'javascript.lang.security.detect-child-process', loc: SHELL, message: 'A child process is started with input.' },
];

/** A completed review_pr scan with `meta` as review_pr records it. */
function seedReview(h: Harness, meta: Record<string, unknown>, specs: SeedSpec[] = SPECS) {
  const seeded = seedScan(h.storage, h.db, h.project, 'review_pr', specs);
  h.db.prepare('UPDATE scans SET meta = ? WHERE id = ?').run(JSON.stringify(meta), seeded.scanId);
  return seeded;
}

function errorOf(r: Raw): Extract<Raw, { ok: false }>['error'] {
  expect(r.ok, JSON.stringify(r)).toBe(false);
  if (r.ok) throw new Error('unreachable: the assertion above failed');
  return r.error;
}

const short = (sha: string): string => sha.slice(0, 12);

describe('llm_scan verify: a review_pr scan of a head that is not checked out cannot be verified here', () => {
  it('R-2 scan_id of a review_pr scan of feature, main checked out: unsupported_target, naming both commits and what to do', async () => {
    const h = harness();
    const { base, head } = repository(h);
    const review = seedReview(h, { base_sha: base, head_sha: head, scanned_tree: 'head_checkout', changed_files: 1 });
    git(h.project, ['checkout', '-q', 'main']);
    const e = errorOf(await callTool(h, 'llm_scan_start', { project_path: h.project, modes: ['verify'], scan_id: review.scanId }));
    expect(e.code).toBe('unsupported_target');
    expect(e.message).toContain(`review_pr scan ${review.scanId} read head ${short(head)}, and ${short(base)} is checked out`);
    expect(e.message).toMatch(/llm_scan reads the working tree\. Check out the reviewed head, or run review_pr on what is checked out, and plan again\./);
    expect(h.repo.listPlans(h.project)).toEqual([]);
  });

  it('R-2b the same findings by fingerprints: each not_eligible with the reason; with none left, nothing_to_plan lists them', async () => {
    const h = harness();
    const { base, head } = repository(h);
    const review = seedReview(h, { base_sha: base, head_sha: head, scanned_tree: 'head_checkout', changed_files: 1 });
    const sast = seedScan(h.storage, h.db, h.project, 'sast', [{ tool: 'semgrep', rule_id: SAST_RULE, loc: PARAM_INSERT, message: 'User input flows into a SQL string.' }]);
    git(h.project, ['checkout', '-q', 'main']);
    const reviewed = review.findings.map((f) => f.fingerprint);
    const fromSast = sast.findings.map((f) => f.fingerprint);

    // Mixed: the sast finding is planned, the review's two are set aside with the reason.
    const out = await start(h, { modes: ['verify'], fingerprints: [...reviewed, ...fromSast] });
    expect(out.tasks_total).toBe(1);
    const reasons = new Map(out.not_eligible.map((n) => [n.fingerprint, n.reason]));
    for (const fp of reviewed) expect(reasons.get(fp), fp).toContain(`read head ${short(head)}, and ${short(base)} is checked out`);
    for (const fp of fromSast) expect(reasons.has(fp), fp).toBe(false);

    // Only the review's: nothing to plan, and the reasons travel with the refusal.
    const e = errorOf(await callTool(h, 'llm_scan_start', { project_path: h.project, modes: ['verify'], fingerprints: reviewed }));
    expect(e.code).toBe('nothing_to_plan');
    const listed = (e.retry_with as { not_eligible?: Array<{ fingerprint: string; reason: string }> } | undefined)?.not_eligible ?? [];
    expect(listed.map((n) => n.fingerprint).sort()).toEqual([...reviewed].sort());
    for (const n of listed) expect(n.reason).toContain(`review_pr scan ${review.scanId} read head ${short(head)}`);
  });

  it('R-2c the reviewed head checked out: plans as before, by scan_id and by fingerprints', async () => {
    const h = harness();
    const { base, head } = repository(h);
    const review = seedReview(h, { base_sha: base, head_sha: head, scanned_tree: 'head_checkout', changed_files: 1 });
    // feature is still checked out
    const byScan = await start(h, { modes: ['verify'], scan_id: review.scanId });
    expect(byScan.tasks_total).toBe(2);
    expect(byScan.not_eligible).toEqual([]);
    const byFingerprints = await start(h, { modes: ['verify'], fingerprints: review.findings.map((f) => f.fingerprint) });
    expect(byFingerprints.tasks_total).toBe(2);
  });

  it('R-2d a scan of another type is not judged: a sast scan plans whatever is checked out', async () => {
    const h = harness();
    repository(h);
    const sast = seedScan(h.storage, h.db, h.project, 'sast', SPECS);
    git(h.project, ['checkout', '-q', 'main']);
    expect((await start(h, { modes: ['verify'], scan_id: sast.scanId })).tasks_total).toBe(2);
    expect((await start(h, { modes: ['verify'], fingerprints: sast.findings.map((f) => f.fingerprint) })).tasks_total).toBe(2);
  });

  it('R-2e a review of the working tree, then another commit checked out: refused all the same (the head decides, not scanned_tree)', async () => {
    const h = harness();
    const { base, head } = repository(h);
    const review = seedReview(h, { base_sha: base, head_sha: head, scanned_tree: 'working_tree', changed_files: 1 });
    git(h.project, ['checkout', '-q', 'main']);
    expect(errorOf(await callTool(h, 'llm_scan_start', { project_path: h.project, modes: ['verify'], scan_id: review.scanId })).code).toBe(
      'unsupported_target',
    );
    // A commit after the review moves HEAD too.
    git(h.project, ['checkout', '-q', 'feature']);
    appendFileSync(join(h.project, 'src', 'app.ts'), '// later\n');
    git(h.project, ['commit', '-qam', 'later']);
    expect(errorOf(await callTool(h, 'llm_scan_start', { project_path: h.project, modes: ['verify'], scan_id: review.scanId })).code).toBe(
      'unsupported_target',
    );
  });

  it('a review_pr scan that records no head, or a project git cannot read: refused, never verified on a guess', async () => {
    const h = harness();
    const { base } = repository(h);
    const noHead = seedReview(h, { base_sha: base, scanned_tree: 'head_checkout' });
    const e = errorOf(await callTool(h, 'llm_scan_start', { project_path: h.project, modes: ['verify'], scan_id: noHead.scanId }));
    expect(e.code).toBe('unsupported_target');
    expect(e.message).toContain(`review_pr scan ${noHead.scanId} records no head commit`);

    const plain = harness(); // not a repository: no checked-out commit to compare with
    const review = seedReview(plain, { base_sha: 'a'.repeat(40), head_sha: 'b'.repeat(40), scanned_tree: 'head_checkout' });
    const e2 = errorOf(await callTool(plain, 'llm_scan_start', { project_path: plain.project, modes: ['verify'], scan_id: review.scanId }));
    expect(e2.code).toBe('unsupported_target');
    expect(e2.message).toContain('the checked-out commit could not be read');
  });

  it('docs/llm-scan.md names the refusal in its Errors table, and the fingerprints half', () => {
    const page = readFileSync(join(REPO_ROOT, 'docs', 'llm-scan.md'), 'utf8');
    const row = page.split(/\r?\n/).find((l) => l.startsWith('| `unsupported_target` |')) ?? '';
    expect(row).toMatch(/`review_pr` scan whose head is not the checked-out commit/);
    expect(row).toMatch(/`fingerprints` are each `not_eligible`/);
  });
});
