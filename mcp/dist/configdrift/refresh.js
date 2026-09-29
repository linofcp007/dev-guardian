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
import { join } from 'node:path';
import { describeReadRefusal, describeWriteRefusal, presentInProject, projectEntryKind, readProjectBytes, writeProjectFile, } from '../platform/projectFs.js';
import { hashConfigFile, MAX_CONFIG_FILE_BYTES } from './hash.js';
import { buildProvenanceHeader, commentPrefixFor } from './header.js';
import { emptyManifest, findManifestEntry, readManifest, upsertManifestEntry, writeManifest, } from './manifest.js';
/**
 * Name for a baseline delivered next to a file we must not overwrite.
 *
 * ---- Why not a plain `<target>.new` ----------------------------------
 *
 * Because `.new` is not ours. A user can perfectly well be keeping their own
 * `.semgrep.yml.new`, and writing over it to deliver a baseline is the same
 * data loss `write_alongside` exists to prevent — the asymmetry (a needless
 * extra file is noise; a clobbered file is gone) does not stop applying just
 * because the suffix looks like scratch space. Two things follow:
 *
 *   - the name carries `dev-guardian` and the plugin version, so it is not a
 *     name anyone else would land on by accident, and two deliveries from
 *     different releases are told apart on sight rather than overwriting each
 *     other;
 *   - and even so, a path that already exists and is NOT recorded in the
 *     manifest as our own previous delivery is refused, not overwritten.
 *     `alongside_blocked` reports it and leaves both files alone.
 */
function alongsideName(target, version) {
    return `${target}.dev-guardian-${version}.new`;
}
export function refreshConfigs(input) {
    let manifest = readManifest(input.projectPath) ?? emptyManifest();
    let manifestTouched = false;
    const plan = [];
    for (const file of input.files) {
        const srcHash = hashConfigFile(input.configsDir, file.source);
        if (srcHash === null) {
            plan.push({
                ...ids(file),
                action: 'source_missing',
                reason: `shipped baseline not found at configs/${file.source}`,
            });
            continue;
        }
        const entry = findManifestEntry(manifest, file.target);
        const install = {
            configsDir: input.configsDir,
            projectPath: input.projectPath,
            source: file.source,
            target: file.target,
            version: input.currentVersion,
        };
        // `lstat`, never `existsSync`: a dangling link reads as absent to the
        // latter, and the create below would have followed it out of the project.
        const kind = projectEntryKind(join(input.projectPath, file.target));
        if (kind === 'link' || kind === 'directory' || kind === 'other') {
            plan.push({
                ...ids(file),
                action: 'refused',
                reason: `${file.target} is ${kind === 'link' ? 'a link (a symlink or a junction)' : 'not a regular file'} — ` +
                    'it is never read or written through. Replace it with a regular file to have it managed.',
            });
            continue;
        }
        if (kind === 'absent') {
            plan.push({ ...ids(file), action: 'create', reason: file.reason });
            if (!input.apply)
                continue;
            if (installFile({ ...install, mode: 'create' }).ok) {
                manifest = upsertManifestEntry(manifest, record(file, input.currentVersion, srcHash, srcHash, 'copied'));
                manifestTouched = true;
            }
            continue;
        }
        const dstHash = hashConfigFile(input.projectPath, file.target);
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
            const delivery = deliverAlongside({
                input,
                file,
                srcHash,
                dstHash,
                manifest,
                reason: 'this file predates provenance tracking — an older copy of ours and your own config ' +
                    'are indistinguishable, so it is never overwritten',
            });
            plan.push(delivery.item);
            if (delivery.manifest !== null) {
                manifest = delivery.manifest;
                manifestTouched = true;
            }
            continue;
        }
        // A delivery already made and not yet merged outranks everything below.
        // Re-running the refresh must not rewrite that file: the user may have
        // started merging INTO it, which would make a second delivery a clobber of
        // their work — the same mistake, one directory along. It also keeps a
        // stream of `.new` files from piling up for someone who is simply not
        // ready to merge yet. `detectConfigDrift` gives `pending_merge` the same
        // precedence, so the advisory and the plan say the same thing.
        if (entry.delivered_as !== undefined && presentInProject(input.projectPath, entry.delivered_as)) {
            plan.push({
                ...ids(file),
                action: 'pending_merge',
                reason: `${entry.delivered_as} is still waiting to be merged into ${file.target}. Merge it ` +
                    'and delete it, then run the refresh again.',
                alongside_path: entry.delivered_as,
            });
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
            if (installFile({ ...install, mode: 'replace' }).ok) {
                manifest = upsertManifestEntry(manifest, record(file, input.currentVersion, srcHash, srcHash, entry.provenance));
                manifestTouched = true;
            }
            continue;
        }
        const delivery = deliverAlongside({
            input,
            file,
            srcHash,
            dstHash,
            manifest,
            reason: 'changed on both sides since install — merge required, your file is untouched',
        });
        plan.push(delivery.item);
        if (delivery.manifest !== null) {
            manifest = delivery.manifest;
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
        // A link is never adopted: the refresh would refuse to manage it.
        if (projectEntryKind(join(input.projectPath, file.target)) !== 'file')
            continue;
        const srcHash = hashConfigFile(input.configsDir, file.source);
        const dstHash = hashConfigFile(input.projectPath, file.target);
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
 * format has comment syntax, and says whether the write landed and, when it
 * did not, why.
 *
 * JSON targets are copied byte-for-byte: `renovate.json` is read by Renovate's
 * own strict JSON parser, so a `//` line would break the tool the file
 * configures. That single exception is the reason the manifest, not the
 * header, is the provenance mechanism.
 *
 * The write goes through `platform/projectFs.ts`: `create` only where nothing
 * is at the name, `replace` only over a regular file, through a temp file
 * renamed into place, and never through a link or a directory that links out
 * of the project.
 */
export function installFile(input) {
    const src = readProjectBytes(input.configsDir, input.source, MAX_CONFIG_FILE_BYTES);
    if (src.status !== 'ok') {
        const why = src.status === 'absent' ? 'not found' : describeReadRefusal(src.reason);
        return { ok: false, reason: `shipped baseline configs/${input.source}: ${why}` };
    }
    const prefix = commentPrefixFor(input.formatHint ?? input.target);
    const content = prefix === null
        ? src.bytes
        : buildProvenanceHeader({ source: input.source, pluginVersion: input.version, prefix }) +
            src.bytes.toString('utf8');
    const w = writeProjectFile(input.projectPath, input.target, content, { mode: input.mode });
    return w.ok ? { ok: true } : { ok: false, reason: describeWriteRefusal(w.reason, w.detail) };
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
 * Delivers the baseline beside a file we must not overwrite, and reports what
 * happened.
 *
 * Two outcomes. Normally the file lands at
 * `<target>.dev-guardian-<version>.new` and the manifest records the delivery,
 * so the drift advisory reads `pending_merge` until the user merges and
 * deletes it. But if something is already sitting at that path and the
 * manifest does not say we put it there, nothing is written: `alongside_blocked`
 * names the path and leaves both files untouched. Overwriting a file we did
 * not create is the data loss this whole branch exists to avoid, and a name
 * that merely looks like scratch space is not proof of ownership.
 *
 * `manifest` comes back `null` when nothing was written — a dry run, a failed
 * write, or a blocked path — so the caller records no delivery that did not
 * happen.
 */
function deliverAlongside(args) {
    const { input, file, manifest } = args;
    const relativeNew = alongsideName(file.target, input.currentVersion);
    const existing = findManifestEntry(manifest, file.target);
    const oursAlready = existing?.delivered_as === relativeNew;
    const present = presentInProject(input.projectPath, relativeNew);
    if (present && !oursAlready) {
        return {
            item: {
                ...ids(file),
                action: 'alongside_blocked',
                reason: `a newer baseline is ready for ${file.target}, but ${relativeNew} already exists and ` +
                    'was not written by dev-guardian — nothing was overwritten. Move or delete that file ' +
                    'and run the refresh again.',
                alongside_path: relativeNew,
            },
            manifest: null,
        };
    }
    const item = {
        ...ids(file),
        action: 'write_alongside',
        reason: args.reason,
        alongside_path: relativeNew,
    };
    if (!input.apply)
        return { item, manifest: null };
    const written = installFile({
        configsDir: input.configsDir,
        source: file.source,
        projectPath: input.projectPath,
        target: relativeNew,
        version: input.currentVersion,
        mode: present ? 'replace' : 'create',
        formatHint: file.target,
    });
    if (!written.ok)
        return { item, manifest: null };
    const entry = {
        ...record(file, input.currentVersion, args.srcHash, args.dstHash, existing?.provenance ?? 'adopted'),
        delivered_as: relativeNew,
        delivered_at: new Date().toISOString(),
    };
    return { item, manifest: upsertManifestEntry(manifest, entry) };
}
//# sourceMappingURL=refresh.js.map