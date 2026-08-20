/**
 * Turning a drift report into the one sentence a user actually sees.
 *
 * ---- The rules this file is enforcing --------------------------------
 *
 * **It is one line.** It goes into `ScanResult.warnings`, which is a
 * `string[]` rendered inline next to a scan's counts. Anything longer
 * competes with the findings for attention and loses on both sides.
 *
 * **It is never a finding and never an error.** Nothing here can change a
 * scan's status, its severity counts, or the CI exit code — `ci/gate.ts`
 * derives that from findings and coverage, and warnings are not an input to
 * either. A config being out of date is not a vulnerability in the user's
 * code, and dressing it as one would be a lie that also breaks their build.
 *
 * **Silence is the default.** Only two states speak unprompted:
 * `upstream_update` (we shipped something they never received) and `diverged`
 * (the same, but the refresh will need a merge). A user who edited their own
 * config — the common case, and the intended one — is told nothing at all,
 * because a warning that fires on almost every project trains people to skip
 * the line, and the next thing they skip is the one that mattered.
 *
 * **The wording differs per state.** "Your copy moved", "our copy moved" and
 * "both moved" have different remedies; a shared phrasing would send someone
 * to merge a file that needed no merge, or to overwrite one that did.
 */
const PREFIX = 'config drift:';
/**
 * The advisory line, or `null` when there is nothing worth saying.
 *
 * `null` covers: no manifest (nothing recorded, so nothing knowable), and
 * every project where the only differences are the user's own.
 */
export function buildDriftAdvisory(report) {
    if (!report.manifest_present)
        return null;
    const upstream = report.entries.filter((e) => e.state === 'upstream_update');
    const diverged = report.entries.filter((e) => e.state === 'diverged');
    const pending = report.entries.filter((e) => e.state === 'pending_merge');
    if (upstream.length === 0 && diverged.length === 0 && pending.length === 0)
        return null;
    const clauses = [];
    if (upstream.length > 0) {
        clauses.push(`${list(upstream.map(installedBy))} ${upstream.length === 1 ? 'is' : 'are'} unchanged since ` +
            `install, but plugin v${currentVersion(upstream)} ships a newer baseline — a rule fix you ` +
            `never received may be missing.`);
    }
    if (diverged.length > 0) {
        clauses.push(`${list(diverged.map((e) => e.target))} changed on both sides since install, so bringing ` +
            `${diverged.length === 1 ? 'it' : 'them'} up to date needs a merge.`);
    }
    if (pending.length > 0) {
        clauses.push(`a newer baseline is already waiting at ${list(pending.map(deliveredPath))} — merge it into ` +
            `${list(pending.map((e) => e.target))} and delete the .new file to clear this notice.`);
    }
    if (upstream.length > 0 || diverged.length > 0) {
        clauses.push('Run init_project with refresh=true and apply=false to preview, then apply=true to update; ' +
            'a file you have edited is written alongside as <name>.new, never over.');
    }
    return `${PREFIX} ${clauses.join(' ')}`;
}
function installedBy(entry) {
    return `${entry.target} (installed by plugin v${entry.recorded_plugin_version})`;
}
function deliveredPath(entry) {
    return entry.delivered_as ?? `${entry.target}.new`;
}
/**
 * Every entry carries the same running version; taking it from the first is
 * enough, and the fallback keeps the sentence grammatical rather than
 * inventing a number if the list is somehow empty.
 */
function currentVersion(entries) {
    return entries[0]?.current_plugin_version ?? 'unknown';
}
function list(items) {
    if (items.length <= 1)
        return items[0] ?? '';
    return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1] ?? ''}`;
}
//# sourceMappingURL=advisory.js.map