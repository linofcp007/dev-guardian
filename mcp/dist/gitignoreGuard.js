/**
 * Ensure the target project's `.gitignore` excludes `.guardian/*` while
 * re-including `.guardian/baseline.json`.
 *
 * Called once at server startup (after the storage is opened, so we know
 * which project root we're operating on). Idempotent: a project with the
 * current form already in place is left alone.
 *
 * **Why `.guardian/*`, never bare `.guardian/`.** The CI gate needs a
 * COMMITTED `.guardian/baseline.json` (`ci/baseline.ts`), but git cannot
 * re-include a file under a directory that is itself excluded —
 * `!.guardian/baseline.json` is silently powerless once anything upstream of
 * it excludes `.guardian/` as a directory, regardless of line order. `*`
 * excludes the directory's CONTENTS instead of the directory itself, which
 * is what makes the per-file negation below it able to do anything at all.
 *
 * **Upgrading, not just detecting.** Every earlier release of this tool
 * wrote the bare `.guardian/` line (or one of its `/.guardian`,
 * `.guardian`, `/.guardian/` spellings) — a project that already has one
 * needs it REMOVED, not merely supplemented: appending the new block below
 * an old bare line changes nothing, because the bare line still excludes
 * the directory outright. So `alreadyIgnored` is followed by an upgrade
 * pass whenever any of the old spellings survives, regardless of whether
 * the new block is also already present.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const HEADER = '# dev-guardian outputs';
const ENTRY = '.guardian/*';
const BASELINE_NEGATION = '!.guardian/baseline.json';
/** Every bare spelling this tool has ever written for the old, unfixed entry. */
const OLD_DIRECTORY_PATTERNS = new Set([
    '.guardian',
    '.guardian/',
    '/.guardian',
    '/.guardian/',
]);
export function ensureGuardianIgnored(projectPath) {
    const gitignorePath = join(projectPath, '.gitignore');
    if (!existsSync(join(projectPath, '.git'))) {
        return { updated: false, reason: 'not_a_repo' };
    }
    try {
        if (!existsSync(gitignorePath)) {
            writeFileSync(gitignorePath, `${HEADER}\n${ENTRY}\n${BASELINE_NEGATION}\n`, 'utf8');
            return { updated: true, reason: 'created' };
        }
        const original = readFileSync(gitignorePath, 'utf8');
        const lines = original.split(/\r?\n/);
        const hasOldPattern = lines.some((l) => OLD_DIRECTORY_PATTERNS.has(l.trim()));
        // Every old bare line is dropped outright — see the module comment on
        // why its mere presence elsewhere in the file defeats the negation,
        // however the rest of the file reads.
        const kept = lines.filter((l) => !OLD_DIRECTORY_PATTERNS.has(l.trim()));
        const hasEntry = kept.some((l) => l.trim() === ENTRY);
        const hasNegation = kept.some((l) => l.trim() === BASELINE_NEGATION);
        if (!hasOldPattern && hasEntry && hasNegation) {
            return { updated: false, reason: 'already_present' };
        }
        const missing = [];
        if (!hasEntry)
            missing.push(ENTRY);
        if (!hasNegation)
            missing.push(BASELINE_NEGATION);
        const trimmedBody = kept.join('\n').replace(/\n+$/, '');
        const next = (trimmedBody.length > 0 ? `${trimmedBody}\n` : '') +
            (missing.length > 0 ? `${HEADER}\n${missing.join('\n')}\n` : '');
        writeFileSync(gitignorePath, next, 'utf8');
        return { updated: true, reason: hasOldPattern ? 'upgraded' : 'added' };
    }
    catch {
        return { updated: false, reason: 'unwritable' };
    }
}
//# sourceMappingURL=gitignoreGuard.js.map