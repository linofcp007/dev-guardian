/**
 * Tiny semver-ish comparator.
 *
 * We avoid a full semver dep because all we ever need is "does the
 * installed version meet the floor we documented?". Pre-release tags
 * (`-rc1`, `+meta`) are tolerated by ignoring everything after the first
 * `-` or `+`. Garbage input returns `null` which callers treat as
 * "version unknown — assume not OK".
 */

export function compareSemver(a: string, b: string): number | null {
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return null;
  if (pa.major !== pb.major) return pa.major - pb.major;
  if (pa.minor !== pb.minor) return pa.minor - pb.minor;
  return pa.patch - pb.patch;
}

export function meetsFloor(installed: string, floor: string): boolean | null {
  const cmp = compareSemver(installed, floor);
  if (cmp === null) return null;
  return cmp >= 0;
}

function parse(input: string): { major: number; minor: number; patch: number } | null {
  if (!input) return null;
  const m = /v?(\d+)\.(\d+)(?:\.(\d+))?/.exec(input);
  if (!m) return null;
  const majorStr = m[1];
  const minorStr = m[2];
  if (majorStr === undefined || minorStr === undefined) return null;
  const major = Number(majorStr);
  const minor = Number(minorStr);
  const patch = m[3] === undefined ? 0 : Number(m[3]);
  if (!Number.isFinite(major) || !Number.isFinite(minor) || !Number.isFinite(patch)) return null;
  return { major, minor, patch };
}
