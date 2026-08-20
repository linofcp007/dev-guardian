/**
 * `init_project` — bootstrap a project with the dev-guardian config set.
 *
 * Steps:
 *   1. Run detect-stack to know what we're working with (or reuse the
 *      latest snapshot).
 *   2. Pick a profile-specific list of config files to install from the
 *      plugin's `configs/` directory into the project root.
 *   3. When `apply=true` (default), copy missing files, stamping provenance
 *      (`configdrift/`) so a later release can tell whether the project's
 *      copy is still the one we shipped. Files that already exist are
 *      skipped (idempotent) — with one exception that writes nothing the
 *      user owns: a file byte-identical to our baseline is adopted into the
 *      manifest, so projects that predate provenance tracking pick it up
 *      just by running init again.
 *   4. When `refresh=true`, additionally compare each config against the
 *      shipped baseline and report (or, with `apply=true`, act on) the
 *      difference. See `configdrift/refresh.ts` for why an edited file is
 *      never overwritten, under any flag.
 *   5. Run `scripts/scan/initial-scan.sh` so the response includes a
 *      first-pass summary of the project's current security state.
 *
 * ---- Why step 3 grew a provenance stamp -------------------------------
 *
 * Skipping an existing target is the right call — the user owns and edits
 * those files — but on its own it meant a fix to a shipped config never
 * reached anyone who had already run init. `configs/semgrep/base.yml`'s
 * `wp-unescaped-output` rule could not match anything at all (`pattern: echo
 * $_GET[$X]` is not valid PHP); it was fixed in b51a2dc, and every project
 * initialised before that still runs the dead rule. Nothing recorded what had
 * been copied, so nothing could notice. Now something does.
 *
 * Profiles:
 *   - minimal   → gitleaks + renovate
 *   - standard  → minimal + semgrep + pre-commit
 *   - paranoid  → standard (placeholder — extra hardening tracked as
 *                  follow-up; see notes in CHANGELOG when added)
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { adoptIdenticalConfigs, installFile, refreshConfigs, } from '../configdrift/refresh.js';
import { hashConfigFile } from '../configdrift/hash.js';
import { emptyManifest, readManifest, upsertManifestEntry, writeManifest, } from '../configdrift/manifest.js';
import { configsDirFromScriptsDir } from '../platform/configsDir.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { resolveVersion } from '../platform/version.js';
import { runShellScript } from '../runners/shellRunner.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
const GITLEAKS = {
    source: 'gitleaks/gitleaks.toml',
    target: '.gitleaks.toml',
    reason: 'baseline secret scan rules',
};
const RENOVATE = {
    source: 'renovate/renovate.json',
    target: 'renovate.json',
    reason: 'dependency update bot config',
};
const SEMGREP = {
    source: 'semgrep/base.yml',
    target: '.semgrep.yml',
    reason: 'baseline SAST rules',
};
const PRECOMMIT = {
    source: 'pre-commit/pre-commit-config.yaml',
    target: '.pre-commit-config.yaml',
    reason: 'pre-commit hooks',
};
const PROFILE_FILES = {
    minimal: [GITLEAKS, RENOVATE],
    standard: [GITLEAKS, RENOVATE, SEMGREP, PRECOMMIT],
    paranoid: [GITLEAKS, RENOVATE, SEMGREP, PRECOMMIT],
};
const tool = {
    name: 'init_project',
    title: 'Bootstrap project with dev-guardian configs',
    description: 'Install gitleaks/renovate/semgrep/pre-commit configs into the project (idempotent), then ' +
        'run scripts/scan/initial-scan.sh for a first-pass status. Profile=minimal|standard|paranoid. ' +
        'Copied files are stamped with their source and plugin version in .dev-guardian/configs.json, ' +
        'so later scans can tell you when a shipped config has been fixed since yours was installed. ' +
        'refresh=true compares your copies against the current baselines: with apply=false it only ' +
        'reports what would change, and with apply=true it updates files you never edited in place ' +
        'and writes <name>.new alongside the ones you did. An edited file is never overwritten.',
    inputSchema: {
        project_path: ProjectPath,
        profile: z.enum(['minimal', 'standard', 'paranoid']).optional(),
        apply: z
            .boolean()
            .optional()
            .describe('When false, return only the proposed file list without writing. Default: true.'),
        refresh: z
            .boolean()
            .optional()
            .describe('Opt-in re-sync of already-installed configs against the shipped baselines. Reports the ' +
            'per-file action; only writes when apply is also true, and never over a file you edited ' +
            '(that one is delivered as <name>.new instead). Default: false.'),
    },
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return failDomain('not_a_git_repo', e.message);
    }
    const profile = inp.profile ?? 'standard';
    const apply = inp.apply ?? true;
    const refresh = inp.refresh === true;
    const configsDir = configsDirFromScriptsDir(ctx.scriptsDir);
    const proposals = PROFILE_FILES[profile];
    const version = resolveVersion();
    const written = [];
    const skipped = [];
    const failed = [];
    let manifest = readManifest(projectPath) ?? emptyManifest();
    let manifestTouched = false;
    // `refresh` is a superset of the plain copy path — its `create` action does
    // exactly what the loop below does — so the two never both run. Letting the
    // loop write first and then asking refresh what it would have done reports
    // `up_to_date` for a file that had just been created, which is true and
    // useless.
    let refreshResult;
    if (refresh) {
        refreshResult = refreshConfigs({
            projectPath,
            configsDir,
            currentVersion: version,
            files: proposals,
            apply,
        });
        for (const item of refreshResult.plan) {
            const spec = proposals.find((p) => p.target === item.target);
            if (spec === undefined)
                continue;
            if (item.action === 'source_missing') {
                failed.push({ ...spec, error: item.reason });
            }
            else if (item.action === 'create' && apply) {
                written.push(spec);
            }
            else {
                skipped.push({ ...spec, reason_skipped: item.action });
            }
        }
    }
    if (!refresh) {
        for (const p of proposals) {
            const src = join(configsDir, p.source);
            const dst = join(projectPath, p.target);
            if (!existsSync(src)) {
                failed.push({ ...p, error: `source missing: ${src}` });
                continue;
            }
            if (existsSync(dst)) {
                skipped.push({ ...p, reason_skipped: 'already_exists' });
                continue;
            }
            if (!apply)
                continue;
            if (!installFile({ srcPath: src, dstPath: dst, source: p.source, version })) {
                failed.push({ ...p, error: 'could not write the file' });
                continue;
            }
            written.push(p);
            const srcHash = hashConfigFile(src);
            if (srcHash !== null) {
                manifest = upsertManifestEntry(manifest, {
                    target: p.target,
                    source: p.source,
                    plugin_version: version,
                    source_sha256: srcHash,
                    target_sha256: srcHash,
                    recorded_at: new Date().toISOString(),
                    provenance: 'copied',
                });
                manifestTouched = true;
            }
        }
    }
    if (apply && manifestTouched)
        writeManifest(projectPath, manifest);
    // Adoption pass for the files we skipped. Writes nothing the user owns —
    // it only records provenance for a copy that is byte-identical to ours, so
    // a project that predates the manifest starts being drift-checked from the
    // next `init_project` run onward.
    const adopted = apply && !refresh && skipped.length > 0
        ? adoptIdenticalConfigs({ projectPath, configsDir, currentVersion: version, files: proposals })
        : [];
    // Read the latest stack snapshot (if any) so the response carries
    // stack context without forcing detect_stack on the model.
    const stackSnapshot = readLatestStackSnapshot(ctx);
    // initial-scan.sh is a status reporter; we capture stdout and return it
    // as a free-form `initial_state` string.
    let initialStateLines = [];
    if (apply && ctx.shell) {
        const scriptPath = join(ctx.scriptsDir, 'scan', 'initial-scan.sh');
        if (existsSync(scriptPath)) {
            const r = await runShellScript({
                shell: ctx.shell,
                scriptPath,
                args: [projectPath],
                cwd: projectPath,
            });
            initialStateLines = r.stdout.split(/\r?\n/).filter((l) => l.length > 0);
        }
    }
    return {
        ok: true,
        profile,
        applied: apply,
        plugin_version: version,
        files_written: written,
        files_skipped: skipped,
        files_failed: failed,
        files_adopted: adopted,
        ...(refreshResult ? { refresh: refreshResult } : {}),
        stack_snapshot: stackSnapshot
            ? stackSnapshot
            : null,
        initial_state: initialStateLines,
    };
}
function readLatestStackSnapshot(ctx) {
    const latest = ctx.storage.stack.getLatest();
    return latest?.snapshot ?? null;
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=initProject.js.map