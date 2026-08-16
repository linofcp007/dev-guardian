/**
 * `rankFiles` — ranks findings by file, descending, pure.
 *
 * Findings with no meaningful `file_path` are grouped under one explicit
 * `'(no file)'` bucket rather than dropped or scattered under a falsy key,
 * so they are never silently missing from the ranking. Three distinct
 * values land here, and `||` (not `??`) is what catches all three:
 *   - `undefined` — what the `Finding` type declares for "absent".
 *   - `null` — what a row read back from SQLite can surface at runtime
 *     even though the static type doesn't say so.
 *   - `''` — not hypothetical: `toRelativeIfPossible`
 *     (`runners/scannerParsers/index.ts`) returns exactly `''` when a
 *     finding's `file_path` IS the project root (a finding about the
 *     project as a whole, not one file inside it), and it feeds semgrep,
 *     trivy, gitleaks and every other parser that normalises paths.
 *     `report/sarif.ts` already treats this exact case as known and real
 *     (see its test "omits the location... when file_path IS the project
 *     root") — `??` would miss it here, the same class of bug Task 1 had
 *     in the other direction (`??` not falling through on `false`).
 *
 * A whitespace-only path (e.g. `'   '`) is deliberately NOT folded in here.
 * Unlike `''`, no code path in this repo produces one today, so there is no
 * evidence it means "absent" rather than a genuine (if odd) value; folding
 * it in on spec would also hide a real anomaly — if a parser bug ever did
 * emit one, showing it as its own odd-looking bucket surfaces that bug,
 * where merging it into `'(no file)'` would bury it under the
 * well-understood "whole project" case above.
 *
 * Ties break on `file_path` ascending, not on iteration or insertion order.
 * Every entry going into the sort already has a distinct `file_path` (they
 * are the grouped-by key), so no two entries ever compare equal — the
 * comparator alone is a strict total order, and the result cannot depend on
 * whether the JS engine's sort happens to be stable. Without this, the same
 * input could sort differently across runs or engines, which reads to a
 * user as "something moved" when nothing did (see the task brief).
 *
 * `remaining_files` is the count of distinct files beyond the `limit`
 * slice, so "N hottest files" can never be misread as "N files have
 * findings" (design doc §6, §8).
 */

import type { Finding } from '../types.js';
import type { Hotspot } from './types.js';

const NO_FILE = '(no file)';

export function rankFiles(
  findings: readonly Finding[],
  limit: number,
): { hotspots: Hotspot[]; remaining_files: number } {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    // `||`, not `??` — see the module doc comment above: `''` must fall
    // through to NO_FILE too, and `??` only catches null/undefined.
    const key = finding.file_path || NO_FILE;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  const ranked: Hotspot[] = [...counts.entries()]
    .map(([file_path, count]) => ({ file_path, count }))
    .sort((a, b) => {
      if (a.count !== b.count) return b.count - a.count;
      if (a.file_path < b.file_path) return -1;
      if (a.file_path > b.file_path) return 1;
      return 0;
    });

  const hotspots = ranked.slice(0, limit);

  return { hotspots, remaining_files: ranked.length - hotspots.length };
}
