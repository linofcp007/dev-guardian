/**
 * Why a `create_fix_pr` group that a live-data test expected to end in a pull
 * request did not — when the reason is the vulnerability database, not the
 * tool.
 *
 * The tests that drive `create_fix_pr` with the real Trivy and the real npm
 * registry assert an outcome that depends on today's advisories. The upgrade
 * plan installs the MINIMUM version that clears every active CVE of the
 * package (`tools/depsUpdatePlan.ts`), and `judgeScan` (`fixpr/verify.ts`)
 * refuses a pull request when that version carries a CVE the installed one
 * did not: "a version bump that trades CVE-A for CVE-B is not a fix". Both
 * are right — and the day an advisory is published against the version a
 * fixture upgrades to, a test that expected `pr_created` reads `not_verified`
 * with nothing wrong in the product. It happened to `lodash@4.17.20`: by
 * November 2026 its minimum fix was 4.18.0, and 4.18.0 had CVE-2026-2950.
 * The two tests failed with a diff of two objects, in the only runs that
 * have a Trivy to run them with.
 *
 * So a test that expects a pull request asks this first, and a fixture that
 * drifted fails saying so.
 */

/** What these helpers read of a `create_fix_pr` group. */
export interface FixGroupOutcome {
  outcome: string;
  commands?: readonly string[];
  scan?: {
    still_present?: readonly string[];
    new_findings?: ReadonlyArray<{ severity: string; title: string }>;
  } | null;
}

/**
 * The explanation, or null when the group is not a case of a fixture that
 * drifted: only `not_verified` WITH findings the before-scan did not have.
 * Targets still present, a failed test run or any other outcome is the
 * tool's own answer, and the test's own assertion reports it.
 */
export function fixtureDriftExplanation(group: FixGroupOutcome | undefined): string | null {
  const fresh = group?.scan?.new_findings ?? [];
  if (group === undefined || group.outcome !== 'not_verified' || fresh.length === 0) return null;
  const ran = (group.commands ?? []).join(' ; ') || '(no command recorded)';
  return (
    `the fixture has drifted, not create_fix_pr: after \`${ran}\`, today's vulnerability database reports ` +
    `${fresh.length} finding(s) the fixture's own version did not have — ` +
    `${fresh.map((f) => `${f.severity}: ${f.title}`).join('; ')}. ` +
    'create_fix_pr refused the pull request, as it is built to (a version bump that trades one CVE for another is not a fix). ' +
    'Give the fixture a version whose minimum fix is clean today: see VERIFIABLE_LODASH in test/helpers/createFixPrHarness.ts.'
  );
}

/** Fails, with {@link fixtureDriftExplanation}, when the group is such a case. */
export function expectNoFixtureDrift(group: FixGroupOutcome | undefined): void {
  const why = fixtureDriftExplanation(group);
  if (why !== null) throw new Error(why);
}
