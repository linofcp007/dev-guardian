/**
 * Shared, pure version-comparison helpers for the dependency pipeline
 * (`deps_update_plan`'s CVE-merge/npm/pip branches, `pipAudit.ts`'s own
 * fix-version selection). Extracted so both places pick a fix version the
 * same, correct way rather than maintaining two copies that can drift.
 *
 * Fix round 1, CRITICAL item 1: a scanner's "fixed_version" is not always
 * an upgrade. pip-audit lists ONE fix per still-maintained release branch
 * (installed `2.0.1`, `fix_versions: ["1.11.27","2.2.9","3.0.1"]` — `1.11.27`
 * is an OLDER branch's backport, not a fix FOR a 2.0.1 install), and a CVE
 * row can simply be stale (recorded against an older installed version than
 * what is on disk now). Naively taking `fix_versions[0]`, or trusting a
 * stored `fixed_version` without comparing it to the CURRENT installed
 * version, can propose `npm install pkg@<older>` / `pip==<older>` labelled
 * `security` — a downgrade presented as a fix.
 */

import { compareVersions } from '../pkgvet/versions.js';

/** `1.2.3`, `1.2`, or `1` — optionally `v`-prefixed — and nothing else. The
 *  only shape this module trusts as an installable, comparable version;
 *  anything else (an open range, a comma-separated list of branches, free
 *  text) is treated as "no usable version" by every function below. */
export function isCleanVersion(v: string | undefined): v is string {
  return v !== undefined && /^v?\d+(\.\d+)*$/i.test(v.trim());
}

/**
 * The one version comparator (review 8, finding 16: three, two of them named
 * `compareVersions` with different pre-release and garbage handling):
 * `pkgvet/versions.ts`'s — the dotted release numerically, then dev < pre-release
 * < final < post, then the suffix segment by segment (`beta.2 < beta.10`,
 * `alpha < beta`). Every caller here gates its input first (`isCleanVersion`,
 * `isLooseVersion`), where it orders exactly as this module's own numeric and
 * pre-release comparisons did. (`platform/semverCompare.ts#compareSemver` is
 * another job: it pulls `major.minor[.patch]` out of a tool's `--version`
 * text, and answers null when there is none.)
 */
export { compareVersions };

/**
 * The smallest candidate that is STRICTLY GREATER than `installed` — never
 * equal (a "fix" equal to what is already installed fixes nothing) and
 * never lower (a downgrade). Returns `undefined` when `installed` is not a
 * clean version, no candidate is a clean version above it, or the candidate
 * list is empty: "no safe minimum could be determined" is the caller's cue
 * to skip and report the package as unplanned, never to guess.
 */
export function minCleanVersionAbove(
  installed: string | undefined,
  candidates: readonly (string | undefined)[],
): string | undefined {
  if (!isCleanVersion(installed)) return undefined;
  let best: string | undefined;
  for (const c of candidates) {
    if (!isCleanVersion(c)) continue;
    if (compareVersions(c, installed) <= 0) continue; // downgrade or no-op — excluded
    if (best === undefined || compareVersions(c, best) < 0) best = c;
  }
  return best;
}

/** `1.2.3`, `1.2`, `1`, optionally `v`-prefixed, optionally with a
 *  dash-separated PRE-RELEASE suffix (`2.0.0-beta.1`) — everything
 *  `isCleanVersion` accepts, PLUS a pre-release tag. Still rejects an open
 *  range, a comma-separated branch list, or free text. */
export function isLooseVersion(v: string | undefined): v is string {
  return v !== undefined && /^v?\d+(\.\d+)*(-[0-9A-Za-z.]+)?$/.test(v.trim());
}

/**
 * `minCleanVersionAbove`'s counterpart for a possibly PRE-RELEASE
 * `installed` version (fix round 3, item N2): the CANDIDATE fix must still
 * be `isCleanVersion` (never propose installing a pre-release as "the
 * fix"), but `installed` only needs to be `isLooseVersion` — so
 * `2.0.0-beta.1` can still be correctly recognised as BELOW a `2.0.1` fix,
 * using real pre-release precedence rather than being rejected outright by
 * `isCleanVersion`'s stricter regex. That outright rejection is what made a
 * pre-release install read as "no safe version above it" — indistinguishable
 * from "already past the fix" — when the fix was, in fact, still ahead of
 * it.
 */
export function minCleanVersionAboveLoose(
  installed: string | undefined,
  candidates: readonly (string | undefined)[],
): string | undefined {
  if (!isLooseVersion(installed)) return undefined;
  let best: string | undefined;
  for (const c of candidates) {
    if (!isCleanVersion(c)) continue;
    if (compareVersions(c, installed) <= 0) continue;
    if (best === undefined || compareVersions(c, best) < 0) best = c;
  }
  return best;
}
