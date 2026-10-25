/**
 * `compareFindings` — the delta between two scans, pure.
 *
 * Findings match as every cross-scan reader matches them
 * (`fingerprint/findingIdentity.ts#indexFindings`): by identity, the
 * fingerprint only where a side has none. On fingerprints alone, one line
 * inserted above an unchanged finding read "+1 new · -1 resolved" on the
 * dashboard and in `status`, while the `classifyDiff` that decides what was
 * not re-measured, beside it, already matched by identity.
 *
 * Each side counts a finding once, not per array entry (the design of
 * record), so a side that (a caller merging scans could produce this) holds a
 * repeated finding is never double-counted.
 *
 * `new_count` is always the TRUE count of findings present in `to` but
 * not in `from`. `new_findings` may be capped to `cap` entries for display;
 * when it is, `new_count` still reports the true count and a
 * `TruncationNotice` is returned describing the cut — never both a capped
 * list AND a capped count, which is the exact "something that did not
 * happen acquiring the appearance of having happened" this dashboard exists
 * to refuse (the design of record).
 */

import { indexFindings } from '../fingerprint/findingIdentity.js';
import type { Finding } from '../types.js';
import type { FindingDelta, TruncationNotice } from './types.js';

export function compareFindings(
  from: { scan_id: string; findings: readonly Finding[] },
  to: { scan_id: string; findings: readonly Finding[] },
  cap: number,
): { delta: FindingDelta; truncation: TruncationNotice | null } {
  const fromIndex = indexFindings(from.findings);
  const toIndex = indexFindings(to.findings);

  let unchangedCount = 0;
  let resolvedCount = 0;
  const seenFrom = indexFindings<Finding>([]);
  for (const finding of from.findings) {
    if (seenFrom.has(finding)) continue;
    seenFrom.add(finding);
    if (toIndex.has(finding)) unchangedCount += 1;
    else resolvedCount += 1;
  }

  // One representative Finding per new finding, in `to`'s order: one
  // repeated within `to.findings` contributes exactly one row, as a repeat
  // counts once on the `from` side above.
  const seenNew = indexFindings<Finding>([]);
  const newFindings: Finding[] = [];
  for (const finding of to.findings) {
    if (fromIndex.has(finding) || seenNew.has(finding)) continue;
    seenNew.add(finding);
    newFindings.push(finding);
  }

  const shownNewFindings = newFindings.slice(0, cap);
  const truncation: TruncationNotice | null =
    shownNewFindings.length < newFindings.length
      ? {
          what: 'new_findings',
          shown: shownNewFindings.length,
          total: newFindings.length,
          reason:
            `new_findings exceeds the cap of ${cap}; showing the first ` +
            `${shownNewFindings.length} of ${newFindings.length}`,
        }
      : null;

  return {
    delta: {
      from_scan_id: from.scan_id,
      to_scan_id: to.scan_id,
      new_count: newFindings.length,
      resolved_count: resolvedCount,
      unchanged_count: unchangedCount,
      new_findings: shownNewFindings,
    },
    truncation,
  };
}
