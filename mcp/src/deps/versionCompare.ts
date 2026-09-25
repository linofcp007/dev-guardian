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

/** `1.2.3`, `1.2`, or `1` — optionally `v`-prefixed — and nothing else. The
 *  only shape this module trusts as an installable, comparable version;
 *  anything else (an open range, a comma-separated list of branches, free
 *  text) is treated as "no usable version" by every function below. */
export function isCleanVersion(v: string | undefined): v is string {
  return v !== undefined && /^v?\d+(\.\d+)*$/i.test(v.trim());
}

/**
 * Numeric dotted-segment comparison. Both inputs SHOULD already be clean
 * (`isCleanVersion`) — a non-clean input degrades to a string comparison
 * rather than throwing, so a caller that forgets to gate still gets an
 * answer, just not a numerically meaningful one.
 */
export function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^v/i, '').split('.').map((n) => parseInt(n, 10));
  const pb = b.replace(/^v/i, '').split('.').map((n) => parseInt(n, 10));
  if (pa.some(Number.isNaN) || pb.some(Number.isNaN)) return a.localeCompare(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

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

function parseLoose(v: string): { core: number[]; pre: string[] | null } {
  const m = /^v?(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.]+))?$/i.exec(v.trim());
  const core = (m?.[1] ?? '0').split('.').map((n) => parseInt(n, 10));
  const pre = m?.[2] ? m[2].split('.') : null;
  return { core, pre };
}

/**
 * Semver-ish comparison that ALSO understands a pre-release suffix (fix
 * round 3, item N2): the dotted numeric CORE is compared exactly like
 * `compareVersions`; when the cores are equal, a version WITH a
 * pre-release suffix is ALWAYS lower precedence than the same core with
 * none (`2.0.0-beta.1 < 2.0.0`), and two pre-release suffixes compare
 * segment by segment (numeric segments numerically, everything else as a
 * string) — the common `beta.1 < beta.2` / `alpha < beta` shapes, not the
 * full SPDX/semver alphanumeric-identifier spec.
 *
 * Both inputs SHOULD already pass `isLooseVersion` — an input that does not
 * parse degrades to treating its whole numeric core as `0`, which is
 * deliberately conservative (reads as "very old") rather than throwing.
 */
export function compareVersionsLoose(a: string, b: string): number {
  const pa = parseLoose(a);
  const pb = parseLoose(b);
  const len = Math.max(pa.core.length, pb.core.length);
  for (let i = 0; i < len; i += 1) {
    const diff = (pa.core[i] ?? 0) - (pb.core[i] ?? 0);
    if (diff !== 0) return diff;
  }
  if (pa.pre === null && pb.pre === null) return 0;
  if (pa.pre === null) return 1; // a is a real release; b (same core) is a pre-release of it
  if (pb.pre === null) return -1;
  const plen = Math.max(pa.pre.length, pb.pre.length);
  for (let i = 0; i < plen; i += 1) {
    const sa = pa.pre[i];
    const sb = pb.pre[i];
    if (sa === undefined) return -1; // fewer pre-release fields sort lower
    if (sb === undefined) return 1;
    const na = /^\d+$/.test(sa) ? parseInt(sa, 10) : null;
    const nb = /^\d+$/.test(sb) ? parseInt(sb, 10) : null;
    if (na !== null && nb !== null) {
      if (na !== nb) return na - nb;
    } else {
      const c = sa.localeCompare(sb);
      if (c !== 0) return c;
    }
  }
  return 0;
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
    if (compareVersionsLoose(c, installed) <= 0) continue;
    if (best === undefined || compareVersions(c, best) < 0) best = c;
  }
  return best;
}
