/**
 * `rankFiles` — ranks findings by file, descending, pure.
 *
 * Findings with no `file_path` (null or undefined — the type says the
 * latter, but a row read back from SQLite can surface the former) are
 * grouped under one explicit `'(no file)'` bucket rather than dropped or
 * scattered under a falsy key, so they are never silently missing from the
 * ranking.
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
    const key = finding.file_path ?? NO_FILE;
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
