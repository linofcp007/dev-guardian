/**
 * `register_custom_rules` — discover the project's own Semgrep rules and
 * persist them, so `scan_sast` and `bug_hunt` run them alongside their own
 * packs.
 *
 * Auto-discovery looks at `.semgrep/`, `semgrep/`, `rules/`. Explicit `paths`
 * may be files, directories or globs (`rules/**\/*.yml`), relative to the
 * project.
 *
 * ---- What changed in Task 11 (2026-09-25 review) ----------------------
 *
 *   - **Globs are expanded.** They used to be stored literally, and the
 *     reader's existence check dropped them — while this tool answered `ok`.
 *     A pattern now registers the files it matches, and one that matches
 *     nothing is `rejected` with that reason.
 *   - **Registration is per canonical project** (`customRulesMetaKey`), not
 *     global: project A's rules used to run on project B.
 *   - **Every file is validated as a Semgrep rules file**
 *     (`validateSemgrepRulesFile`). Auto-discovery registered `rules/`
 *     whatever it held; Prometheus alerts there made every later `scan_sast`
 *     exit 7 with 0 files scanned, and `rules: []` scanned nothing with exit
 *     0. A directory is registered when it holds at least one valid rules
 *     file; its invalid files are `rejected`, and the reader
 *     (`../platform/customRules.ts`) skips them on every scan.
 *   - **Nothing valid means nothing written.** A call that registers nothing
 *     leaves the previous registration exactly as it was, and says so.
 *
 * ---- Semgrep compiles them too (follow-up X, fix round 4) --------------
 *
 * The shape check passed `languages: [klingon]`, and one such file makes
 * Semgrep refuse the whole configuration (exit 8, nothing scanned) on every
 * later scan. When Semgrep is installed, every file that passed the shape
 * check is compiled with `semgrep --validate` (`runners/semgrepValidate.ts`,
 * bounded, metrics off) and one it refuses is `rejected` with Semgrep's own
 * message. A directory holding a refused file is registered as its accepted
 * files, one by one, so the refused one never reaches a scan. When Semgrep is
 * not installed, or could not answer, the shape check stands and the result
 * says the files were not validated by Semgrep (`semgrep_validated: false`).
 *
 * The reading side (`resolveCustomSemgrepConfigs`) did not exist at all
 * until 2026-08-18 — see its module comment.
 */
import { existsSync, statSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { z } from 'zod';
import { CUSTOM_RULES_META_KEY, customRulesMetaKey, validateSemgrepRulesFile, yamlFilesUnder, } from '../platform/customRules.js';
import { expandGlob, hasGlobMagic } from '../platform/glob.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { validateRuleFiles } from '../runners/semgrepValidate.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
import { scannerAvailable } from './scanHelpers.js';
const inputSchema = {
    project_path: ProjectPath,
    paths: z
        .array(z.string())
        .optional()
        .describe('Files, directories or globs (e.g. rules/**/*.yml), relative to the project. When omitted, ' +
        'auto-discovers .semgrep/, semgrep/ and rules/.'),
    clear: z
        .boolean()
        .optional()
        .describe("When true, remove this project's registered custom rules — and the 2.0.x global registration, for every project — and exit."),
};
const tool = {
    name: 'register_custom_rules',
    title: 'Register custom Semgrep rules',
    description: 'Discover or accept paths/globs to Semgrep YAML rules and persist them for THIS project ' +
        '(registrations are per project). scan_sast and bug_hunt then run them as extra --config packs. ' +
        'Every file is checked to be a Semgrep rules file (non-empty rules:, each rule with id, message, ' +
        'languages, severity and a pattern) and, when Semgrep is installed, compiled with semgrep --validate ' +
        '(an unknown language or a broken pattern is refused with Semgrep\'s message) — anything else is ' +
        'returned in `rejected` with a reason and never registered, so a stray YAML (e.g. Prometheus alerts in ' +
        'rules/) cannot break later scans; semgrep_validated says whether Semgrep looked. A ' +
        'registered path that later disappears or stops validating is skipped rather than failing the ' +
        'scan. Pass clear=true to remove the registration.',
    inputSchema,
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
    if (inp.clear) {
        ctx.storage.runtimeMeta.delete(customRulesMetaKey(projectPath));
        // The 2.0.x registration was global, and clear removed it: it still
        // does, which also ends the notice scans give about it.
        ctx.storage.runtimeMeta.delete(CUSTOM_RULES_META_KEY);
        return { ok: true, cleared: true };
    }
    const explicit = inp.paths !== undefined && inp.paths.length > 0;
    const collected = explicit ? collectExplicit(projectPath, inp.paths ?? []) : collectDiscovered(projectPath);
    const rejected = collected.rejected;
    const semgrep = await compileWithSemgrep(projectPath, collected.registered, rejected);
    const registered = semgrep.registered;
    const semgrepNote = semgrep.note === null ? '' : ` ${semgrep.note}`;
    if (registered.length === 0) {
        return {
            ok: true,
            registered: [],
            rejected,
            semgrep_validated: semgrep.validated,
            note: (explicit
                ? 'Nothing registered: no path named a valid Semgrep rules file. The previous registration is unchanged.'
                : 'No .semgrep/, semgrep/ or rules/ directory with a valid Semgrep rules file found. ' +
                    'The previous registration is unchanged.') + semgrepNote,
        };
    }
    ctx.storage.runtimeMeta.setJson(customRulesMetaKey(projectPath), registered);
    return {
        ok: true,
        registered,
        rejected,
        semgrep_validated: semgrep.validated,
        note: (rejected.length > 0
            ? `Registered ${registered.length} path(s); ${rejected.length} rejected (see \`rejected\`). ` +
                'Re-run scan_sast / bug_hunt to apply the new rule set.'
            : 'Re-run scan_sast / bug_hunt to apply the new rule set.') + semgrepNote,
    };
}
function isDirectory(path) {
    try {
        return statSync(path).isDirectory();
    }
    catch {
        return false;
    }
}
/**
 * The shape-checked `registered` paths, compiled by Semgrep when it is
 * installed (see the module comment): a file it refuses moves to
 * `rejected` with its message; a directory holding one is registered as its
 * accepted files.
 */
async function compileWithSemgrep(projectPath, registered, rejected) {
    if (registered.length === 0)
        return { registered: [], validated: false, note: null };
    if (!(await scannerAvailable('semgrep'))) {
        return {
            registered: [...registered],
            validated: false,
            note: 'Not validated by Semgrep (it is not installed): only the rule-file shape was checked, so a rule ' +
                'Semgrep cannot compile (an unknown language, a broken pattern) would still fail later scans.',
        };
    }
    // The files each entry stands for, as the reader passes them to Semgrep.
    const filesOf = (entry) => isDirectory(entry) ? yamlFilesUnder(entry).filter((f) => validateSemgrepRulesFile(f).ok) : [entry];
    const verdict = await validateRuleFiles([...new Set(registered.flatMap(filesOf))], projectPath);
    if (!verdict.validated) {
        return {
            registered: [...registered],
            validated: false,
            note: `Not validated by Semgrep (${verdict.reason}): only the rule-file shape was checked.`,
        };
    }
    const kept = [];
    let split = false;
    for (const entry of registered) {
        const files = filesOf(entry);
        const refused = files.filter((f) => verdict.invalid.has(f));
        for (const f of refused)
            rejected.push({ path: f, reason: `Semgrep refused it: ${verdict.invalid.get(f) ?? ''}` });
        if (refused.length === 0) {
            kept.push(entry);
            continue;
        }
        if (isDirectory(entry)) {
            const accepted = files.filter((f) => !verdict.invalid.has(f));
            kept.push(...accepted);
            if (accepted.length > 0)
                split = true;
        }
    }
    return {
        registered: [...new Set(kept)],
        validated: true,
        note: split
            ? 'A directory holding a file Semgrep refused is registered as its accepted files, one by one: a file ' +
                'added to it later is not picked up — register the directory again once the refused file is fixed.'
            : null,
    };
}
/** A directory counts when at least one YAML file in it validates; each
 *  invalid one is reported. A file counts when it validates. */
function consider(path, registered, rejected) {
    let isDir;
    try {
        isDir = statSync(path).isDirectory();
    }
    catch {
        rejected.push({ path, reason: 'does not exist' });
        return;
    }
    if (!isDir) {
        const verdict = validateSemgrepRulesFile(path);
        if (verdict.ok)
            registered.push(path);
        else
            rejected.push({ path, reason: verdict.reason });
        return;
    }
    const files = yamlFilesUnder(path);
    let valid = 0;
    for (const file of files) {
        const verdict = validateSemgrepRulesFile(file);
        if (verdict.ok)
            valid += 1;
        else
            rejected.push({ path: file, reason: verdict.reason });
    }
    if (valid > 0)
        registered.push(path);
    else if (files.length === 0)
        rejected.push({ path, reason: 'holds no .yml/.yaml file' });
}
function collectExplicit(projectPath, paths) {
    const registered = [];
    const rejected = [];
    for (const raw of paths) {
        if (hasGlobMagic(raw)) {
            if (isAbsolute(raw)) {
                rejected.push({ path: raw, reason: 'a glob must be relative to the project' });
                continue;
            }
            const matches = expandGlob(projectPath, raw).filter((p) => {
                try {
                    return statSync(p).isFile();
                }
                catch {
                    return false;
                }
            });
            if (matches.length === 0) {
                rejected.push({ path: raw, reason: 'matched no file' });
                continue;
            }
            for (const match of matches)
                consider(match, registered, rejected);
            continue;
        }
        consider(resolve(projectPath, raw), registered, rejected);
    }
    return { registered: [...new Set(registered)], rejected };
}
function collectDiscovered(projectPath) {
    const registered = [];
    const rejected = [];
    for (const dir of ['.semgrep', 'semgrep', 'rules']) {
        const abs = join(projectPath, dir);
        if (!existsSync(abs))
            continue;
        consider(abs, registered, rejected);
    }
    return { registered, rejected };
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=registerCustomRules.js.map