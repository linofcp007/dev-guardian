/**
 * Comparing what the manifest recorded against what is on both disks now.
 *
 * ---- Why four states and not one -------------------------------------
 *
 * "The config changed" is not actionable, because the overwhelmingly common
 * reason it changed is that the user edited it — which is the whole point of
 * copying the file into their project rather than reading ours. A single
 * "changed" warning would fire on almost every project, be correct almost
 * every time, and be ignored by everyone within a week; the state that
 * actually needs a human, "we shipped a fix and you never got it", would go
 * out with it. So the two hashes are tracked independently and their four
 * combinations are named separately, and only two of the four ever speak.
 *
 * ---- Why no advisory at all without a manifest -----------------------
 *
 * A project initialised before this existed has a `.semgrep.yml` on disk and
 * nothing that says where it came from. If its content matches what we ship
 * today, it is in sync and there is nothing to say. If it does not, we cannot
 * distinguish "an old copy of ours" from "a file the user wrote themselves
 * that happens to share the name" — and warning the second user that their
 * own config is missing our fix is worse than saying nothing. That gap is why
 * `init_project` adopts a byte-identical file into the manifest on any run,
 * why `refresh` exists as an explicit adoption path, and why the release
 * notes have to carry the b51a2dc message in plain words for everyone the
 * check cannot reach.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { hashConfigFile } from './hash.js';
import { readManifest } from './manifest.js';
/**
 * Classifies every manifest entry. Never throws: an unreadable manifest, a
 * vanished config or a locked file all degrade to a quiet, honest state.
 */
export function detectConfigDrift(input) {
    const manifest = readManifest(input.projectPath);
    if (manifest === null)
        return { manifest_present: false, entries: [] };
    return {
        manifest_present: true,
        entries: manifest.entries.map((entry) => classify(entry, input)),
    };
}
function classify(entry, input) {
    const base = {
        target: entry.target,
        source: entry.source,
        recorded_plugin_version: entry.plugin_version,
        current_plugin_version: input.currentVersion,
    };
    const sourceHash = hashConfigFile(join(input.configsDir, entry.source));
    if (sourceHash === null)
        return { ...base, state: 'source_missing' };
    const targetPath = join(input.projectPath, entry.target);
    const targetHash = hashConfigFile(targetPath);
    if (targetHash === null)
        return { ...base, state: 'target_missing' };
    // A refresh that could not overwrite safely left the new baseline beside
    // the user's file. While that file is still there the merge is outstanding,
    // and that is the only thing worth saying — the hashes below would say
    // `in_sync`, because the manifest was updated to record the delivery.
    if (entry.delivered_as !== undefined && existsSync(join(input.projectPath, entry.delivered_as))) {
        return { ...base, state: 'pending_merge', delivered_as: entry.delivered_as };
    }
    const oursMoved = sourceHash !== entry.source_sha256;
    const theirsMoved = targetHash !== entry.target_sha256;
    if (oursMoved && theirsMoved)
        return { ...base, state: 'diverged' };
    if (oursMoved)
        return { ...base, state: 'upstream_update' };
    if (theirsMoved)
        return { ...base, state: 'local_edit' };
    return { ...base, state: 'in_sync' };
}
//# sourceMappingURL=detect.js.map