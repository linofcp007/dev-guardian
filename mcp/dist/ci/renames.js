/**
 * Which files of the project were renamed since its baseline was recorded —
 * so the CI gate matches a finding in a renamed file to the entry the
 * baseline holds under the old path (review 8, finding 6: a `git mv` of
 * `src/app.js` and a `py/` directory made 13 baselined findings new, exit 1;
 * with `--baseline-ref <base>` a pull request could not even accept them).
 *
 * `git diff -M --name-status` between the commit the baseline belongs to and
 * the working tree: renames committed since and renames staged now (a `git mv`)
 * alike. The commit is the `--baseline-ref` one when given, else the last
 * commit that changed `.guardian/baseline.json` (HEAD when none did). A plain
 * `mv` that git has not seen (an untracked new path) is not a rename to git
 * either. Paths are project-relative and `/`-separated, as findings are keyed.
 *
 * Never throws: not a repository, no commits, or any git failure is no
 * rename — the gate then matches as it always did.
 */
import { BASELINE_RELATIVE_PATH } from './baseline.js';
import { git, repoState, splitNul } from '../runners/git.js';
/** New project-relative path → the path it had at `since` (or the baseline's commit). */
export async function renamesSince(projectPath, since) {
    const out = new Map();
    try {
        const state = await repoState(projectPath);
        if (state.kind !== 'has_commits')
            return out;
        let base = since;
        if (base === null) {
            const last = await git(projectPath, ['log', '-1', '--format=%H', '--', BASELINE_RELATIVE_PATH]);
            const sha = last.exitCode === 0 ? last.stdout.trim() : '';
            base = /^[0-9a-f]{40,64}$/.test(sha) ? sha : 'HEAD';
        }
        // `--relative`: paths relative to the project, and only renames inside it.
        const diff = await git(projectPath, ['diff', '--relative', '-M', '--name-status', '-z', base, '--']);
        if (diff.exitCode !== 0)
            return out;
        const fields = splitNul(diff.stdout);
        for (let i = 0; i < fields.length;) {
            const status = fields[i] ?? '';
            if (/^[RC]\d*$/.test(status)) {
                const from = fields[i + 1];
                const to = fields[i + 2];
                if (status.startsWith('R') && from !== undefined && to !== undefined)
                    out.set(to, from);
                i += 3;
            }
            else {
                i += 2;
            }
        }
    }
    catch {
        /* no rename: the gate matches as it always did */
    }
    return out;
}
//# sourceMappingURL=renames.js.map