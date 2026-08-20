/**
 * Installing and re-syncing the baseline configs, with provenance.
 *
 * ---- The one rule everything else is arranged around ------------------
 *
 * **The user owns their copy.** Nothing here overwrites a file the user has
 * touched, under any flag, ever. `init_project` copies these configs into the
 * project precisely so they can be edited; a tool that silently reverts those
 * edits to ship a rule fix would be trading a dead Semgrep rule for lost work,
 * which is a worse bug than the one it set out to fix.
 *
 * That gives three writing behaviours, and the plan below is just the
 * bookkeeping needed to pick between them:
 *
 *   - the file is absent → `create` it (this is plain `init_project`);
 *   - the file is present and provably untouched since we wrote it →
 *     `update_in_place` is safe, because there is nothing of theirs to lose;
 *   - anything else → `write_alongside`: the new baseline lands as
 *     `<target>.new` and their file is not opened for writing at all.
 *
 * "Anything else" deliberately includes *provenance unknown* — a project that
 * predates the manifest. An old copy of ours and a config the user wrote by
 * hand that happens to share a filename are indistinguishable from the bytes,
 * and the cost of guessing wrong is asymmetric: a needless `.new` file is
 * noise, a clobbered hand-written config is data loss.
 *
 * ---- Why `write_alongside` updates the manifest, and what that means ---
 *
 * After delivering `<target>.new` the entry records the *delivered* source
 * hash and version, and points `delivered_as` at the file. The user's own
 * hash is re-recorded as whatever it is now. That combination reads as
 * `pending_merge` for as long as the `.new` file exists, and falls silent
 * once they merge and delete it.
 *
 * The alternative — leaving the entry untouched so the advisory keeps firing
 * until the merge is provably done — cannot work: a merged file keeps the
 * user's customisations, so it will never equal our baseline, and the warning
 * would be permanent and unclearable. A warning nobody can clear is a warning
 * everybody filters. The trade-off accepted here is that deleting the `.new`
 * without merging it also silences the notice; the user asked for the
 * refresh, was handed the file, and acted on it.
 */
import { copyFileSync, existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { hashConfigFile } from './hash.js';
import { buildProvenanceHeader, commentPrefixFor } from './header.js';
import { emptyManifest, findManifestEntry, readManifest, upsertManifestEntry, writeManifest, } from './manifest.js';
/** Suffix for a baseline delivered next to a file we must not overwrite. */
const ALONGSIDE_SUFFIX = '.new';
export function refreshConfigs(input) {
    let manifest = readManifest(input.projectPath) ?? emptyManifest();
    let manifestTouched = false;
    const plan = [];
    for (const file of input.files) {
        const srcPath = join(input.configsDir, file.source);
        const srcHash = hashConfigFile(srcPath);
        if (srcHash === null) {
            plan.push({
                ...ids(file),
                action: 'source_missing',
                reason: `shipped baseline not found at configs/${file.source}`,
            });
            continue;
        }
        const dstPath = join(input.projectPath, file.target);
        const entry = findManifestEntry(manifest, file.target);
        if (!existsSync(dstPath)) {
            plan.push({ ...ids(file), action: 'create', reason: file.reason });
            if (!input.apply)
                continue;
            if (installFile({ srcPath, dstPath, source: file.source, version: input.currentVersion })) {
                manifest = upsertManifestEntry(manifest, record(file, input.currentVersion, srcHash, srcHash, 'copied'));
                manifestTouched = true;
            }
            continue;
        }
        const dstHash = hashConfigFile(dstPath);
        if (dstHash === null) {
            plan.push({
                ...ids(file),
                action: 'up_to_date',
                reason: 'file present but unreadable — left alone',
            });
            continue;
        }
        if (entry === null) {
            // Provenance unknown. Identical content is the one case where it is not
            // a guess: nobody hand-writes a byte-for-byte copy of our baseline.
            if (dstHash === srcHash) {
                plan.push({
                    ...ids(file),
                    action: 'adopt',
                    reason: 'already identical to the shipped baseline — recording provenance',
                });
                if (!input.apply)
                    continue;
                manifest = upsertManifestEntry(manifest, record(file, input.currentVersion, srcHash, dstHash, 'adopted'));
                manifestTouched = true;
                continue;
            }
            const written = deliverAlongside(input, file, srcPath, dstPath, srcHash, dstHash, manifest);
            plan.push({
                ...ids(file),
                action: 'write_alongside',
                reason: 'this file predates provenance tracking — an older copy of ours and your own config ' +
                    'are indistinguishable, so it is never overwritten',
                alongside_path: alongside(file.target),
            });
            if (written !== null) {
                manifest = written;
                manifestTouched = true;
            }
            continue;
        }
        const oursMoved = srcHash !== entry.source_sha256;
        const theirsMoved = dstHash !== entry.target_sha256;
        if (!oursMoved) {
            plan.push({
                ...ids(file),
                action: 'up_to_date',
                reason: theirsMoved
                    ? 'your copy is edited; the shipped baseline has not changed since install'
                    : 'identical to the shipped baseline',
            });
            continue;
        }
        if (!theirsMoved) {
            plan.push({
                ...ids(file),
                action: 'update_in_place',
                reason: `untouched since install (plugin v${entry.plugin_version}) — safe to update`,
            });
            if (!input.apply)
                continue;
            if (installFile({ srcPath, dstPath, source: file.source, version: input.currentVersion })) {
                manifest = upsertManifestEntry(manifest, record(file, input.currentVersion, srcHash, srcHash, entry.provenance));
                manifestTouched = true;
            }
            continue;
        }
        const written = deliverAlongside(input, file, srcPath, dstPath, srcHash, dstHash, manifest);
        plan.push({
            ...ids(file),
            action: 'write_alongside',
            reason: 'changed on both sides since install — merge required, your file is untouched',
            alongside_path: alongside(file.target),
        });
        if (written !== null) {
            manifest = written;
            manifestTouched = true;
        }
    }
    if (input.apply && manifestTouched)
        writeManifest(input.projectPath, manifest);
    return { applied: input.apply, plan };
}
/**
 * Records provenance for a config already sitting in the project that is
 * byte-identical to the shipped baseline.
 *
 * Used by plain `init_project` on the files it skips as `already_exists`, so
 * a project that predates the manifest picks one up simply by running init
 * again — no new flag, no writes to any file the user owns. Deliberately
 * silent about files that merely *look* like ours: see the `entry === null`
 * branch above for why identical content is the only safe signal.
 */
export function adoptIdenticalConfigs(input) {
    let manifest = readManifest(input.projectPath) ?? emptyManifest();
    const adopted = [];
    for (const file of input.files) {
        if (findManifestEntry(manifest, file.target) !== null)
            continue;
        const srcHash = hashConfigFile(join(input.configsDir, file.source));
        const dstHash = hashConfigFile(join(input.projectPath, file.target));
        if (srcHash === null || dstHash === null || srcHash !== dstHash)
            continue;
        manifest = upsertManifestEntry(manifest, record(file, input.currentVersion, srcHash, dstHash, 'adopted'));
        adopted.push(file.target);
    }
    if (adopted.length > 0)
        writeManifest(input.projectPath, manifest);
    return adopted;
}
/**
 * Writes a config into the project, stamping the provenance header where the
 * format has comment syntax. Returns whether the write landed.
 *
 * JSON targets are copied byte-for-byte: `renovate.json` is read by Renovate's
 * own strict JSON parser, so a `//` line would break the tool the file
 * configures. That single exception is the reason the manifest, not the
 * header, is the provenance mechanism.
 */
export function installFile(input) {
    try {
        mkdirSync(dirname(input.dstPath), { recursive: true });
        const prefix = commentPrefixFor(input.formatHint ?? input.dstPath);
        if (prefix === null) {
            copyFileSync(input.srcPath, input.dstPath);
            return true;
        }
        const header = buildProvenanceHeader({
            source: input.source,
            pluginVersion: input.version,
            prefix,
        });
        writeFileSync(input.dstPath, header + readFileSync(input.srcPath, 'utf8'), 'utf8');
        return true;
    }
    catch {
        return false;
    }
}
/** `.semgrep.yml` -> `.semgrep.yml.new` */
function alongside(target) {
    return `${target}${ALONGSIDE_SUFFIX}`;
}
function ids(file) {
    return { target: file.target, source: file.source };
}
function record(file, version, sourceHash, targetHash, provenance) {
    return {
        target: file.target,
        source: file.source,
        plugin_version: version,
        source_sha256: sourceHash,
        target_sha256: targetHash,
        recorded_at: new Date().toISOString(),
        provenance,
    };
}
/**
 * Writes `<target>.new` and returns the manifest with the delivery recorded,
 * or `null` when nothing was written (dry run, or the write did not land).
 *
 * The `.new` file is ours, not the user's, so overwriting a previous one is
 * not a clobber — it is replacing a stale delivery with a current one.
 */
function deliverAlongside(input, file, srcPath, dstPath, srcHash, dstHash, manifest) {
    if (!input.apply)
        return null;
    const relativeNew = alongside(file.target);
    const written = installFile({
        srcPath,
        dstPath: `${dstPath}${ALONGSIDE_SUFFIX}`,
        source: file.source,
        version: input.currentVersion,
        formatHint: file.target,
    });
    if (!written)
        return null;
    const existing = findManifestEntry(manifest, file.target);
    const entry = {
        ...record(file, input.currentVersion, srcHash, dstHash, existing?.provenance ?? 'adopted'),
        delivered_as: relativeNew,
        delivered_at: new Date().toISOString(),
    };
    return upsertManifestEntry(manifest, entry);
}
//# sourceMappingURL=refresh.js.map