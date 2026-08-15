/**
 * `compareFindings` — the fingerprint delta between two scans, pure.
 *
 * Computed over fingerprint SETS, not array lengths (design doc §7), so a
 * side that (a caller merging scans could produce this) holds a repeated
 * fingerprint is never double-counted.
 *
 * `new_count` is always the TRUE count of fingerprints present in `to` but
 * not in `from`. `new_findings` may be capped to `cap` entries for display;
 * when it is, `new_count` still reports the true count and a
 * `TruncationNotice` is returned describing the cut — never both a capped
 * list AND a capped count, which is the exact "something that did not
 * happen acquiring the appearance of having happened" this dashboard exists
 * to refuse (design doc §2, §8).
 */
export function compareFindings(from, to, cap) {
    const fromFingerprints = new Set(from.findings.map((finding) => finding.fingerprint));
    const toFingerprints = new Set(to.findings.map((finding) => finding.fingerprint));
    let unchangedCount = 0;
    let resolvedCount = 0;
    for (const fingerprint of fromFingerprints) {
        if (toFingerprints.has(fingerprint))
            unchangedCount += 1;
        else
            resolvedCount += 1;
    }
    // One representative Finding per new fingerprint, in `to`'s order. A
    // fingerprint repeated within `to.findings` must contribute exactly one
    // row here, same as it contributes exactly one member of `toFingerprints`
    // above — array iteration with a `seen` guard, not `toFingerprints`
    // itself, because we need the actual Finding objects, not just the keys.
    const seenNew = new Set();
    const newFindings = [];
    for (const finding of to.findings) {
        if (fromFingerprints.has(finding.fingerprint))
            continue;
        if (seenNew.has(finding.fingerprint))
            continue;
        seenNew.add(finding.fingerprint);
        newFindings.push(finding);
    }
    const shownNewFindings = newFindings.slice(0, cap);
    const truncation = shownNewFindings.length < newFindings.length
        ? {
            what: 'new_findings',
            shown: shownNewFindings.length,
            total: newFindings.length,
            reason: `new_findings exceeds the cap of ${cap}; showing the first ` +
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
//# sourceMappingURL=delta.js.map