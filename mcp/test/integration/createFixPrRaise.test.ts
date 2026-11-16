/**
 * `create_fix_pr` end to end — a real git repository, the real npm registry
 * and the real Trivy; only `gh` is a stub (`test/helpers/createFixPrHarness.ts`)
 * — for the one case the cycle of `fixpr/raise.ts` exists for: the minimum
 * version that clears a package's advisories has an advisory of its own,
 * already fixed one release later.
 *
 * Measured 2026-11-14: `lodash@4.17.20` → the plan installs 4.18.0
 * (CVE-2026-4800), 4.18.0 has CVE-2026-2950 (fixed in 4.18.1), and the
 * differential refused the pull request — `not_verified`, two counts, no
 * hint. With the cycle, the same command ends verified at 4.18.1 and says
 * why it is not 4.18.0.
 *
 * LIVE DATA. What Trivy reports for a lodash version changes with every
 * advisory. The case needs a version whose minimum fix has exactly such an
 * advisory; the day it stops being one — the plan goes straight to a clean
 * version, or the raised one gets an advisory too — the first test says so
 * in words instead of failing on a diff of two objects.
 */
import { describe, expect, it } from 'vitest';
import { TOOLS, type ToolModule } from '../../src/tools/index.js';
import { okResult } from '../helpers/toolResult.js';
import {
  ctx,
  REGISTRY_BACKED_TIMEOUT_MS,
  repo,
  seedRealDepsBefore,
  setupLodashRepo,
  TRIVY_INSTALLED,
  useFixPrRepo,
  VERIFIABLE_LODASH,
  VERIFIABLE_SEVERITY_MIN,
  worktreeCount,
} from '../helpers/createFixPrHarness.js';

useFixPrRepo();

interface RaisedPackage {
  package_name: string;
  planned_version: string;
  applied_version: string;
  advisories: string[];
}
interface Group {
  outcome: string;
  commands?: string[];
  raised?: RaisedPackage[];
  note?: string;
  scan?: { still_present?: string[]; new_findings?: Array<{ severity: string; title: string }> } | null;
  tests?: { outcome?: string } | null;
}

async function dryRun(input: Record<string, unknown>, c = ctx()): Promise<Group[]> {
  await seedRealDepsBefore(c);
  const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
  if (mod === undefined) throw new Error('create_fix_pr is not registered');
  const res = await mod.handler({ project_path: repo, sources: ['deps'], apply: false, ...input }, c as never);
  return okResult<{ groups: Group[] }>(res).groups;
}

/**
 * The verification's re-scans (`deps_audit` called by `create_fix_pr`, which names the origin project in the call's
 * meta) each gain one finding the fix cannot answer: an advisory on a package the group did not upgrade. Everything
 * else is the real scan. Returns how many re-scans ran, and puts the real handler back.
 */
function withAnAdvisoryOnAnotherPackage(c: ReturnType<typeof ctx>): { rescans: () => number; restore: () => void } {
  const tool = TOOLS.find((t) => t.name === 'deps_audit');
  if (tool === undefined) throw new Error('deps_audit is not registered');
  const real: ToolModule['handler'] = tool.handler;
  let rescans = 0;
  tool.handler = async (input, context, meta) => {
    const res = await real(input, context, meta);
    const scanId = (res as { scan_id?: unknown }).scan_id;
    if (meta?.originProjectPath === undefined || !res.ok || typeof scanId !== 'string') return res;
    rescans += 1;
    c.storage.findings.bulkInsert([
      {
        scan_id: scanId,
        fingerprint: `fp-fabricated-${rescans}`,
        tool: 'trivy',
        rule_id: 'CVE-0000-00001',
        severity: 'medium',
        category: 'security',
        subcategory: 'cve',
        title: 'minimist: an advisory made up for this test',
        message: 'an advisory made up for this test',
        file_path: 'package-lock.json',
        snippet: 'minimist@1.2.5->1.2.6',
        fix_available: true,
      },
    ]);
    return res;
  };
  return { rescans: () => rescans, restore: () => { tool.handler = real; } };
}

/** The lodash versions the group's install commands name, in the order they ran. */
const installed = (g: Group | undefined): string[] =>
  (g?.commands ?? []).flatMap((c) => /npm install lodash@(\S+)/.exec(c)?.[1] ?? []);

describe('create_fix_pr raises a target whose minimum fix has an advisory of its own (fixpr-clean-target-version)', () => {
  it.skipIf(!TRIVY_INSTALLED)(
    'T-13 lodash 4.17.20, a dry run: verified with one raise — both installs in order, what was raised and why, and no worktree left',
    async () => {
      setupLodashRepo('4.17.20');
      const before = worktreeCount();
      const [group] = await dryRun({ severity_min: 'low' });
      const ran = installed(group);

      // Is this still the case the test was written for? Today's advisories decide, not the tool.
      if (ran.length === 1 && group?.outcome === 'verified_dry_run') {
        throw new Error(
          `the fixture has drifted, not create_fix_pr: the plan went straight to lodash@${ran[0] ?? '?'} and it verified — ` +
            'today no advisory stands on the minimum fix of lodash@4.17.20. Give this test a version whose minimum fix has an advisory of its own.',
        );
      }
      expect(group?.outcome, group?.note).toBe('verified_dry_run');
      expect(ran).toHaveLength(2);
      expect(group?.raised).toEqual([
        { package_name: 'lodash', planned_version: ran[0], applied_version: ran[1], advisories: [expect.stringMatching(/^(?:CVE|GHSA)-/)] },
      ]);
      expect(group?.note ?? '').toMatch(/raised/);
      expect(group?.scan?.still_present).toEqual([]);
      expect(group?.scan?.new_findings).toEqual([]);
      expect(worktreeCount()).toBe(before);
    },
    REGISTRY_BACKED_TIMEOUT_MS,
  );

  it.skipIf(!TRIVY_INSTALLED)(
    'T-13 a version whose minimum fix already verifies: one install, nothing raised — the result of before',
    async () => {
      setupLodashRepo(VERIFIABLE_LODASH);
      const [group] = await dryRun({ severity_min: VERIFIABLE_SEVERITY_MIN });
      expect(group?.outcome, group?.note).toBe('verified_dry_run');
      expect(installed(group)).toHaveLength(1);
      expect(group?.raised ?? []).toEqual([]);
      expect(group?.note ?? '').not.toMatch(/raised/);
    },
    REGISTRY_BACKED_TIMEOUT_MS,
  );

  // The one line of the handler that joins the cycle's account to the group's note had no test of its own
  // (3.11.0): the text is held by `raise.test.ts`, the joining only shows on a real `not_verified`. Here the
  // verification finds one advisory no higher version of the upgraded package answers.
  it.skipIf(!TRIVY_INSTALLED)(
    'a new advisory on a package the fix did not upgrade: not_verified after ONE round, the note names it with the version that clears it and says why nothing was raised, and the tests did not run',
    async () => {
      setupLodashRepo('4.17.20');
      const c = ctx();
      const fabricated = withAnAdvisoryOnAnotherPackage(c);
      let group: Group | undefined;
      try {
        [group] = await dryRun({ severity_min: 'low' }, c);
      } finally {
        fabricated.restore();
      }
      expect(group?.outcome, group?.note).toBe('not_verified');
      // One round and one re-scan: a raisable advisory beside one that is not raises nothing.
      expect(installed(group)).toHaveLength(1);
      expect(fabricated.rescans()).toBe(1);
      expect(group?.raised ?? []).toEqual([]);
      const note = group?.note ?? '';
      expect(note).toMatch(/^not_verified: the scan differential did not pass \(0 target\(s\) still present, \d+ new finding\(s\)\) — no pull request opened\. New: /);
      expect(note).toContain('minimist@1.2.5: CVE-0000-00001 (fixed in 1.2.6)');
      expect(note).toMatch(/\. Target not raised: .*CVE-0000-00001 is on minimist@1\.2\.5, a package that is not one this fix upgraded/);
      // The project's tests are not run on a tree that failed the scan differential.
      expect(group?.tests?.outcome).toBe('not_run');
    },
    REGISTRY_BACKED_TIMEOUT_MS,
  );
});
