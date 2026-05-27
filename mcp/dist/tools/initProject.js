/**
 * `init_project` — bootstrap a project with the dev-guardian config set.
 *
 * Steps:
 *   1. Run detect-stack to know what we're working with (or reuse the
 *      latest snapshot).
 *   2. Pick a profile-specific list of config files to install from the
 *      plugin's `configs/` directory into the project root.
 *   3. When `apply=true` (default), copy missing files. Files that
 *      already exist are skipped (idempotent).
 *   4. Run `scripts/scan/initial-scan.sh` so the response includes a
 *      first-pass summary of the project's current security state.
 *
 * Profiles:
 *   - minimal   → gitleaks + renovate
 *   - standard  → minimal + semgrep + pre-commit
 *   - paranoid  → standard (placeholder — extra hardening tracked as
 *                  follow-up; see notes in CHANGELOG when added)
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, } from 'node:fs';
import { dirname, join } from 'node:path';
import { z } from 'zod';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runShellScript } from '../runners/shellRunner.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
const PROFILE_FILES = {
    minimal: [
        { source: 'gitleaks/gitleaks.toml', target: '.gitleaks.toml', reason: 'baseline secret scan rules' },
        { source: 'renovate/renovate.json', target: 'renovate.json', reason: 'dependency update bot config' },
    ],
    standard: [
        { source: 'gitleaks/gitleaks.toml', target: '.gitleaks.toml', reason: 'baseline secret scan rules' },
        { source: 'renovate/renovate.json', target: 'renovate.json', reason: 'dependency update bot config' },
        { source: 'semgrep/base.yml', target: '.semgrep.yml', reason: 'baseline SAST rules' },
        {
            source: 'pre-commit/pre-commit-config.yaml',
            target: '.pre-commit-config.yaml',
            reason: 'pre-commit hooks',
        },
    ],
    paranoid: [
        { source: 'gitleaks/gitleaks.toml', target: '.gitleaks.toml', reason: 'baseline secret scan rules' },
        { source: 'renovate/renovate.json', target: 'renovate.json', reason: 'dependency update bot config' },
        { source: 'semgrep/base.yml', target: '.semgrep.yml', reason: 'baseline SAST rules' },
        {
            source: 'pre-commit/pre-commit-config.yaml',
            target: '.pre-commit-config.yaml',
            reason: 'pre-commit hooks',
        },
    ],
};
const tool = {
    name: 'init_project',
    title: 'Bootstrap project with dev-guardian configs',
    description: 'Install gitleaks/renovate/semgrep/pre-commit configs into the project (idempotent), then ' +
        'run scripts/scan/initial-scan.sh for a first-pass status. Profile=minimal|standard|paranoid.',
    inputSchema: {
        project_path: ProjectPath,
        profile: z.enum(['minimal', 'standard', 'paranoid']).optional(),
        apply: z
            .boolean()
            .optional()
            .describe('When false, return only the proposed file list without writing. Default: true.'),
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
    const configsDir = resolveConfigsDir(ctx.scriptsDir);
    const proposals = PROFILE_FILES[profile];
    const written = [];
    const skipped = [];
    const failed = [];
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
        try {
            mkdirSync(dirname(dst), { recursive: true });
            copyFileSync(src, dst);
            written.push(p);
        }
        catch (e) {
            failed.push({ ...p, error: e.message });
        }
    }
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
        files_written: written,
        files_skipped: skipped,
        files_failed: failed,
        stack_snapshot: stackSnapshot
            ? stackSnapshot
            : null,
        initial_state: initialStateLines,
    };
}
function resolveConfigsDir(scriptsDir) {
    // scriptsDir is dev-guardian/scripts/. Configs sit next to it.
    return join(scriptsDir, '..', 'configs');
}
function readLatestStackSnapshot(ctx) {
    const latest = ctx.storage.stack.getLatest();
    return latest?.snapshot ?? null;
}
// Silence the unused-import warning when readFileSync is not used.
void readFileSync;
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=initProject.js.map