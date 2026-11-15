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
import { TOOLS } from '../../src/tools/index.js';
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
}

async function dryRun(input: Record<string, unknown>): Promise<Group[]> {
  const c = ctx();
  await seedRealDepsBefore(c);
  const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
  if (mod === undefined) throw new Error('create_fix_pr is not registered');
  const res = await mod.handler({ project_path: repo, sources: ['deps'], apply: false, ...input }, c as never);
  return okResult<{ groups: Group[] }>(res).groups;
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
});
