/**
 * `create_fix_pr` driven end to end against a real git repo, a real npm
 * registry and the real scanners: what a dry run must leave untouched — no
 * branch, the latest-scan view, risk_score.
 *
 * One of four files split from what was `createFixPr.test.ts` so that vitest
 * runs them in parallel; the harness, and where the time goes, are in
 * `test/helpers/createFixPrHarness.ts`.
 */
import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { TOOLS } from '../../src/tools/index.js';
import { okResult } from '../helpers/toolResult.js';
import {
  ctx,
  REGISTRY_BACKED_TIMEOUT_MS,
  repo,
  REQUIRE_SEMGREP,
  seedRealDepsBefore,
  setupLodashRepo,
  TRIVY_INSTALLED,
  useFixPrRepo,
  worktreeCount,
} from '../helpers/createFixPrHarness.js';

useFixPrRepo();

describe('create_fix_pr', () => {
  // Present in every run so the gate itself is visible; only EXECUTED when
  // the caller has asked for it. Without this, "trivy is missing" and "trivy
  // ran and agreed" are indistinguishable in the suite output — the exact
  // failure mode `rulePackFixture.test.ts`'s header describes, and the reason
  // that discipline exists in this repo at all.
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — this suite must be runnable end to end', () => {
    expect(
      TRIVY_INSTALLED,
      'GUARDIAN_REQUIRE_SEMGREP=1 but trivy is not on PATH, so the tests that need a ' +
        'real trivy-sourced CVE record (here: final-review.md C1) would ' +
        'have been skipped.',
    ).toBe(true);
  });

  // ------------------------------------------------------------------
  // task-7-review.md fix round: C1 (the re-scan's own report artifacts
  // committed into the PR), C2 (a dry run leaves the branch behind), I3
  // (the worktree re-scan pollutes the server's global "latest scan" view)
  // and I5 (the coverage check verifies the wrong tool for non-trivy deps
  // targets). All four need a group that reaches a REAL, non-empty file
  // diff — the semgrep fixture above never does (no reliable autofix rule
  // found), so these use a REAL, network-backed npm dependency bump
  // instead (see setupLodashRepo's own comment).
  // ------------------------------------------------------------------

  it('C2: a dry run leaves no local branch behind either, not just no worktree', async () => {
    const c = ctx();
    setupLodashRepo();
    await seedRealDepsBefore(c);
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler(
      { project_path: repo, sources: ['deps'], apply: false },
      c as never,
    );
    expect(res).toMatchObject({ ok: true, applied: false });
    if (!res) throw new Error('create_fix_pr tool not found');
    const groups = okResult<{ groups: { branch: string }[] }>(res).groups;
    expect(groups).toHaveLength(1);

    // Design §6, literally: "not a branch". Checked against the real repo's
    // OWN refs, not the tool's own report of what it did.
    const branches = execFileSync('git', ['-C', repo, 'branch', '--list'], { encoding: 'utf8' });
    expect(branches).not.toContain(groups[0]?.branch);
    expect(worktreeCount()).toBe(1);
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it('I3: does not repoint the server\'s global "latest scan" view at the verification worktree', async () => {
    const c = ctx();
    setupLodashRepo();
    await seedRealDepsBefore(c);

    const beforeLatest = c.storage.scans.getLatest();
    const beforeOpenCount = c.storage.findings.listOpen().length;
    expect(beforeLatest?.project_path).toBe(repo);
    expect(beforeOpenCount).toBeGreaterThan(0);

    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    // apply:false on purpose — I3's own defect is not gated by apply at all
    // (the re-scan runs regardless), so the SAFE DEFAULT must not leak this.
    await mod?.handler({ project_path: repo, sources: ['deps'], apply: false }, c as never);

    const afterLatest = c.storage.scans.getLatest();
    const afterOpenCount = c.storage.findings.listOpen().length;
    // Unchanged: still the real project, still the real (pre-fix) findings —
    // not the worktree, and not zero.
    expect(afterLatest?.scan_id).toBe(beforeLatest?.scan_id);
    expect(afterLatest?.project_path).toBe(repo);
    expect(afterOpenCount).toBe(beforeOpenCount);
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it.skipIf(!TRIVY_INSTALLED)('final-review.md C1: a dry run does not change what risk_score reports either — not just getLatest/listOpen', async () => {
    // task-7-review.md I3 (the test directly above) fixed getLatest() and
    // listOpen(), both queried by scans.getLatestStmt / findings.listOpen*
    // Stmt. risk_score does NOT read getLatest() for its CVE source, though:
    // it reads listHistory(50).find(s => ['deps','security_full'].includes
    // (s.scan_type)) (riskScore.ts#findLatestOfType), and listHistoryStmt
    // shipped with no WHERE clause at all — I3's fix never touched it. So the
    // exact same worktree re-scan I3 already proves does not leak into
    // getLatest()/listOpen() could still win risk_score's OWN CVE lookup.
    // Measured, before this fix, on a real project: risk_score's score fell
    // from 44 (high) to 31 (medium) and active_cves from 5 to 0, after
    // nothing but a dry run — and it did not self-correct, because the
    // contaminating row is never deleted.
    //
    // Asserted the way design §10 actually states the guarantee — "Nothing
    // the tool does in dry-run mode may change what … risk_score report[s]"
    // names risk_score itself, so this calls the real tool and diffs its
    // whole output, rather than re-checking the two repo methods I3 already
    // covers (which would stay green even with listHistoryStmt still broken —
    // that is exactly how the original gap shipped unnoticed).
    const c = ctx();
    setupLodashRepo();
    await seedRealDepsBefore(c);

    const riskScoreTool = TOOLS.find((t) => t.name === 'risk_score');
    // risk_score answers for one project (Task 8) — this one.
    const beforeRaw = await riskScoreTool?.handler({ project_path: repo }, c as never);
    if (!beforeRaw) throw new Error('risk_score tool not found');
    const before = okResult<{ components: { cves: { active_cves: number } } }>(beforeRaw);
    // Not vacuous: there must be a real, non-zero signal at risk of being
    // silently zeroed before asserting that nothing zeroes it.
    expect(before.components.cves.active_cves).toBeGreaterThan(0);

    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    await mod?.handler({ project_path: repo, sources: ['deps'], apply: false }, c as never);

    const after = await riskScoreTool?.handler({ project_path: repo }, c as never);
    expect(after).toEqual(before);
  }, REGISTRY_BACKED_TIMEOUT_MS);
});
