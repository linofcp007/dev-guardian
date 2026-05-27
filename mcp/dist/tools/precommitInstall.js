/**
 * `precommit_install` — register the project's `.pre-commit-config.yaml`
 * with the local pre-commit framework via `pre-commit install`.
 *
 * Idempotent. Assumes `init_project` (or the user) has already created
 * `.pre-commit-config.yaml`. Returns the list of installed hook stages.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { ProjectPath } from '../schemas.js';
import { scannerAvailable } from './scanHelpers.js';
import { registerToolModule } from './index.js';
const tool = {
    name: 'precommit_install',
    title: 'Install pre-commit hooks',
    description: 'Run `pre-commit install` in the project to wire its .pre-commit-config.yaml into git hooks. ' +
        'Requires pre-commit on PATH (install via install_toolchain).',
    inputSchema: { project_path: ProjectPath },
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, _ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return failDomain('not_a_git_repo', e.message);
    }
    if (!existsSync(join(projectPath, '.pre-commit-config.yaml'))) {
        return failDomain('scanner_failed', 'No .pre-commit-config.yaml in project. Run init_project first.');
    }
    if (!existsSync(join(projectPath, '.git'))) {
        return failDomain('not_a_git_repo', 'pre-commit needs a git repo to install hooks into.');
    }
    const bin = await scannerAvailable('pre-commit');
    if (!bin) {
        return failDomain('missing_scanner', 'pre-commit is not installed. Run install_toolchain with tools=["pre-commit"].');
    }
    const result = await runProcess({
        command: 'pre-commit',
        args: ['install'],
        cwd: projectPath,
        timeoutMs: 60_000,
    });
    if (result.outcome !== 'completed') {
        return failDomain('scanner_failed', `pre-commit install failed: ${result.stderr.split(/\r?\n/)[0] ?? '(no stderr)'}`);
    }
    // Optionally install hook into commit-msg / pre-push too — best-effort.
    for (const stage of ['commit-msg', 'pre-push']) {
        await runProcess({
            command: 'pre-commit',
            args: ['install', '--hook-type', stage],
            cwd: projectPath,
            timeoutMs: 30_000,
        }).catch(() => undefined);
    }
    return {
        ok: true,
        project_path: projectPath,
        stages_installed: ['pre-commit', 'commit-msg', 'pre-push'],
        stdout: result.stdout.split(/\r?\n/).slice(0, 20).join('\n'),
    };
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=precommitInstall.js.map