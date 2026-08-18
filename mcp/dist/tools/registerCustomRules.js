/**
 * `register_custom_rules` — discover the project's own Semgrep rule
 * directory and persist it, so `scan_sast` and `bug_hunt` run it alongside
 * their own packs.
 *
 * Looks for, in order: `.semgrep/`, `semgrep/`, `rules/`. If any contains
 * `.yml`/`.yaml` files, that path is registered under
 * `runtime_meta['custom_semgrep_configs']` (the key is
 * `CUSTOM_RULES_META_KEY`, shared with the readers).
 *
 * ---- The reading side, and how long it did not exist -----------------
 *
 * Until this was wired, NOTHING read the key back. `scan_sast` built
 * `['--config=auto']`; `bug_hunt` built its own pack list; the only other
 * mention of the key anywhere in the repo was a test asserting it had been
 * WRITTEN. So the write half was covered by tests and the read half had
 * never been built, while this tool's own description promised callers that
 * "scan_sast / bug_hunt will then pick them up" and its success payload told
 * them to "re-run scan_sast / bug_hunt to apply the new rule set". Both were
 * false for every user who ever called it.
 *
 * The gap was recorded here, which is the only reason it was findable — but
 * the note pointed at a "TODO_FOLLOWUPS below" block that exists nowhere in
 * the repository, so the pointer was dangling too.
 *
 * `resolveCustomSemgrepConfigs` (`../platform/customRules.ts`) is now that
 * reading side, and it drops registered paths that no longer exist: a
 * `--config` that fails to resolve aborts the ENTIRE semgrep run, so a stale
 * registration would otherwise turn every later scan into a total outage.
 */
import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { z } from 'zod';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { CUSTOM_RULES_META_KEY } from '../platform/customRules.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    project_path: ProjectPath,
    paths: z
        .array(z.string())
        .optional()
        .describe('Explicit paths or globs to register. When omitted, auto-discovers .semgrep/ etc.'),
    clear: z
        .boolean()
        .optional()
        .describe('When true, remove any previously registered custom rules and exit.'),
};
const tool = {
    name: 'register_custom_rules',
    title: 'Register custom Semgrep rules',
    description: 'Discover or accept a list of paths to Semgrep YAML rules and persist them. ' +
        'scan_sast and bug_hunt then run them as extra --config packs alongside their own. ' +
        'A registered path that later disappears is skipped rather than failing the scan. ' +
        'Pass clear=true to remove the registration.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
/** Shared with the readers so the writer and readers cannot drift apart. */
const META_KEY = CUSTOM_RULES_META_KEY;
async function handler(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return failDomain('not_a_git_repo', e.message);
    }
    if (inp.clear) {
        ctx.storage.runtimeMeta.delete(META_KEY);
        return { ok: true, cleared: true };
    }
    const discovered = inp.paths && inp.paths.length > 0
        ? inp.paths.map((p) => resolve(projectPath, p))
        : autoDiscover(projectPath);
    if (discovered.length === 0) {
        return {
            ok: true,
            registered: [],
            note: 'No .semgrep/ or rules/ directory with YAML files found.',
        };
    }
    ctx.storage.runtimeMeta.setJson(META_KEY, discovered);
    return {
        ok: true,
        registered: discovered,
        note: 'Re-run scan_sast / bug_hunt to apply the new rule set.',
    };
}
function autoDiscover(projectPath) {
    const out = [];
    for (const dir of ['.semgrep', 'semgrep', 'rules']) {
        const abs = join(projectPath, dir);
        if (!existsSync(abs))
            continue;
        try {
            const hasYaml = readdirSync(abs).some((f) => /\.ya?ml$/.test(f));
            if (hasYaml)
                out.push(abs);
        }
        catch {
            /* ignore */
        }
    }
    return out;
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=registerCustomRules.js.map