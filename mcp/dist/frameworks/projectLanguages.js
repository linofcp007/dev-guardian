/**
 * The source languages of one project — what OWASP coverage
 * (`frameworks/coverage.ts`) is judged against, since a scanner's rules
 * only see the languages they were written for.
 *
 * The detect_stack snapshot when there is one (its languages come from
 * manifests — `go.mod`, `package.json` — so a stray script does not make
 * Python a project language), otherwise the files' extensions. Plus, in
 * both cases, the languages detect_stack CANNOT report
 * (`languages.ts#DETECT_STACK_LANGUAGES`: no C#, Swift, C, …) found among
 * the files: a snapshot's silence about a language it cannot see is not
 * evidence the project has none, and dropping it would let a C# project
 * read as having no language at all.
 *
 * Unknown is `null`, never `[]`: a project directory that cannot be read
 * has languages nobody measured. Coverage then claims nothing
 * language-specific as tested.
 */
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { PROJECT_WALK_EXCLUDE } from '../runners/projectFiles.js';
import { canonicalLanguage, DETECT_STACK_LANGUAGES, languageOfFile } from './languages.js';
/** Directories the file walk visits at most — the same ceiling detect_stack's manifest walk uses. */
const MAX_DIRS = 20_000;
/**
 * The source languages among the files under `root`, skipping the
 * directories no scan of the project's own files reads (dependencies,
 * build output, caches) and hidden ones. `complete: false` when the walk
 * stopped at {@link MAX_DIRS}; `languages: null` when `root` itself cannot
 * be read.
 */
export function languagesFromFiles(root) {
    let top;
    try {
        top = readdirSync(root, { withFileTypes: true });
    }
    catch {
        return { languages: null, complete: false };
    }
    const found = new Set();
    const stack = [{ dir: root, entries: top }];
    let visited = 0;
    while (stack.length > 0) {
        const next = stack.pop();
        if (next === undefined)
            break;
        visited += 1;
        if (visited > MAX_DIRS)
            return { languages: [...found].sort(), complete: false };
        let entries = next.entries;
        if (entries === null) {
            try {
                entries = readdirSync(next.dir, { withFileTypes: true });
            }
            catch {
                continue;
            }
        }
        for (const entry of entries) {
            if (entry.isDirectory()) {
                if (!PROJECT_WALK_EXCLUDE.has(entry.name) && !entry.name.startsWith('.')) {
                    stack.push({ dir: join(next.dir, entry.name), entries: null });
                }
            }
            else if (entry.isFile()) {
                const lang = languageOfFile(entry.name);
                if (lang !== null)
                    found.add(lang);
            }
        }
    }
    return { languages: [...found].sort(), complete: true };
}
function snapshotLanguages(snapshot) {
    if (snapshot === null || typeof snapshot !== 'object')
        return null;
    const raw = snapshot.languages;
    if (!Array.isArray(raw) || !raw.every((l) => typeof l === 'string'))
        return null;
    return [...new Set(raw.map(canonicalLanguage).filter((l) => l !== null))];
}
export function resolveProjectLanguages(stack, projectPath) {
    const files = languagesFromFiles(projectPath);
    const walkNote = files.complete ? '' : `, file walk stopped after ${MAX_DIRS} directories`;
    let persisted = null;
    try {
        persisted = stack.getLatestForProject(projectPath);
    }
    catch {
        persisted = null;
    }
    const fromSnapshot = persisted === null ? null : snapshotLanguages(persisted.snapshot);
    if (persisted !== null && fromSnapshot !== null) {
        const invisible = (files.languages ?? []).filter((l) => !DETECT_STACK_LANGUAGES.includes(l));
        const languages = [...new Set([...fromSnapshot, ...invisible])].sort();
        const extra = invisible.length > 0 ? `, plus file extensions for ${invisible.join(', ')} (detect_stack cannot detect it)` : '';
        return { languages, source: `detect_stack snapshot of ${persisted.captured_at}${extra}${walkNote}` };
    }
    if (files.languages === null) {
        return { languages: null, source: 'could not be determined (the project directory could not be read)' };
    }
    return { languages: files.languages, source: `file extensions (no detect_stack snapshot)${walkNote}` };
}
//# sourceMappingURL=projectLanguages.js.map