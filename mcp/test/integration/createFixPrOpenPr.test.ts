/**
 * `create_fix_pr` driven end to end against a real git repo, a real npm
 * registry and the real scanners: a real pull request, and a repeat run after
 * it.
 *
 * One of four files split from what was `createFixPr.test.ts` so that vitest
 * runs them in parallel; the harness, and where the time goes, are in
 * `test/helpers/createFixPrHarness.ts`.
 */
import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { TOOLS } from '../../src/tools/index.js';
import {
  addOriginRemote,
  ctx,
  ghLogContents,
  installGhStubThatReportsAnExistingPr,
  originDir,
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
        'real trivy-sourced CVE record (here: C1/I5, final review I1) would ' +
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

  it.skipIf(!TRIVY_INSTALLED)('C1/I5: opens a real pull request whose diff excludes dev-guardian\'s own scan report', async () => {
    const c = ctx();
    setupLodashRepo();
    addOriginRemote();
    await seedRealDepsBefore(c);
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler(
      { project_path: repo, sources: ['deps'], apply: true },
      c as never,
    ) as { ok: true; groups: Array<{
      outcome: string; pr: { status: string; url: string | null } | null; branch: string;
    }> };

    expect(res.ok).toBe(true);
    expect(res.groups).toHaveLength(1);
    const group = res.groups[0];
    // The real point of this fixture: verification genuinely passed (the
    // CVE is genuinely gone, nothing new appeared) and a PR was genuinely
    // opened — not a status this test assumes, one it measures. Reaching
    // this also confirms I5 did not spuriously block a target that WAS
    // genuinely re-checked (trivy did run) — I5's own dedicated test below
    // covers the negative (wpscan) side.
    expect(group).toMatchObject({ outcome: 'pr_created', pr: { status: 'created' } });
    // A real gh pr create call happened — the stub's own `echo %*`
    // re-quotes each argv token (`"pr" "create" …`), and its capture of a
    // multi-line --body argument truncates at the first embedded newline (a
    // real limitation of that mechanism) — see buildPrBody's own test for
    // why the verbatim not_run phrase (M7) is verified there instead.
    expect(ghLogContents()).toMatch(/"pr"\s+"create"/);

    // C1: the pushed commit's diff must be the real fix — never
    // dev-guardian's own .guardian/reports/** re-scan artifacts, whether
    // alongside the real change or (the actual defect) instead of it.
    const changed = execFileSync(
      'git',
      ['-C', originDir as string, 'diff-tree', '--no-commit-id', '--name-only', '-r', group?.branch ?? ''],
      { encoding: 'utf8' },
    ).trim().split('\n').filter((l) => l.length > 0);
    expect(changed).toContain('package.json');
    expect(changed.some((f) => f.startsWith('.guardian'))).toBe(false);
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it.skipIf(!TRIVY_INSTALLED)('final review I1: a repeat run after a PR was created reports pr_exists, not worktree_failed', async () => {
    // Same fixture as C1/I5 above, continued past `pr_created`: KEEPS_BRANCH
    // deliberately leaves the branch behind once a PR exists — correctly, it
    // is what the PR points at — so a repeat run's `createWorktree` collides
    // on that same deterministic branch name. Before this fix, that collision
    // was reported verbatim as `worktree_failed` (a raw git-internals
    // message) because `prExists` was never consulted; `pr.ts`'s own
    // `--state all` idempotency search — built for exactly this moment —
    // was unreachable for the entire life of the open PR.
    const c = ctx();
    setupLodashRepo();
    addOriginRemote();
    await seedRealDepsBefore(c);
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    type Result = { ok: true; groups: Array<{
      outcome: string; branch: string; note: string;
      pr: { status: string; url: string | null } | null;
    }> };

    // RUN 1 — apply:true, genuinely reaches a created PR.
    const first = await mod?.handler(
      { project_path: repo, sources: ['deps'], apply: true },
      c as never,
    ) as Result;
    expect(first.groups[0]).toMatchObject({ outcome: 'pr_created', pr: { status: 'created' } });
    const branch = first.groups[0]?.branch as string;
    expect(
      execFileSync('git', ['-C', repo, 'branch', '--list'], { encoding: 'utf8' }),
    ).toContain(branch);

    // From here on `gh pr list` must report a hit — what a real GitHub
    // remote would now genuinely show, which the beforeEach's own stateless
    // stub (always empty stdout) cannot simulate.
    installGhStubThatReportsAnExistingPr();

    // RUN 2 — apply:true again, same findings, therefore the SAME
    // deterministic branch (design §5).
    const second = await mod?.handler(
      { project_path: repo, sources: ['deps'], apply: true },
      c as never,
    ) as Result;
    expect(second.groups[0]).toMatchObject({
      outcome: 'pr_exists', branch, pr: { status: 'exists', url: null },
    });
    expect(second.groups[0]?.note.toLowerCase()).toContain('already exists');

    // RUN 3 — the SAFE DEFAULT, apply:false. Design §6's `apply` boundary is
    // stated in terms of what leaves the machine (commit/push/`gh pr
    // create`), not in terms of `gh` being touched at all, so a cautious
    // preview must be told the truth too, not just an `apply:true` retry.
    const third = await mod?.handler(
      { project_path: repo, sources: ['deps'], apply: false },
      c as never,
    ) as Result;
    expect(third.groups[0]).toMatchObject({
      outcome: 'pr_exists', branch, pr: { status: 'exists', url: null },
    });

    // Exactly one PR was ever created (run 1) — runs 2 and 3 both recognised
    // the existing one instead of attempting a duplicate (the stub fails
    // loudly on a second `pr create`, so a wrong implementation would show up
    // here as a thrown/rejected outcome, not a silent pass).
    expect(ghLogContents().match(/"pr"\s+"create"/g) ?? []).toHaveLength(1);
    // ...and `prExists` really was reached on both repeat runs — run 1's own
    // `openPr` existence check, plus one per repeat run: the review's own
    // gh.log evidence, inverted.
    expect(ghLogContents().match(/"pr"\s+"list"/g) ?? []).toHaveLength(3);

    // No worktree survives any of the three runs, and the PR's own branch is
    // still exactly where it was — neither repeat run touched it (nothing
    // KEEPS_BRANCH would want deleted, and this code path never reaches the
    // `finally` that deletes it — no worktree was ever created on it).
    expect(worktreeCount()).toBe(1);
    expect(
      execFileSync('git', ['-C', repo, 'branch', '--list'], { encoding: 'utf8' }),
    ).toContain(branch);
  // Three create_fix_pr runs, each bounded like one: 62.7 s under coverage,
  // and 122.9 s once — past the single-run bound — on a machine running three
  // suites at once (review 3.0, R7).
  }, 3 * REGISTRY_BACKED_TIMEOUT_MS);
});
