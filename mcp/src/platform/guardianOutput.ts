/**
 * What dev-guardian generates in a project's ROOT `.guardian/` — the one
 * part of a project no scan of its own files reads.
 *
 * 3.3.0 kept every directory NAMED `.guardian`, at any depth, out of Semgrep
 * (`--exclude=.guardian`, unanchored on purpose) and out of gitleaks' working
 * tree pass. A pull request adding `lib/.guardian/handler.js` with a command
 * injection, required from `index.js`, then passed the CI gate with exit 0
 * and coverage `full` — `--baseline-ref` / `--rules-ref` included — and
 * `map_attack_surface` never saw its routes (review 10, finding 1). A folder
 * of that name below the root is the project's code like any other: only
 * what dev-guardian itself writes, at the root, is left out, by exact
 * project-relative path:
 *
 *   - `.guardian/reports/` — every scan's raw reports (1.5 MB a run);
 *   - `.guardian/guardian.db` and the files SQLite keeps beside it;
 *   - `.guardian/dashboard.html` (the CLI's `dashboard`), `.guardian/last-grill.md`
 *     (the grill skill) and `.guardian/.gitignore` (the CLI's).
 *
 * The files a team shares (`baseline.json`, `scan.yml`, …) and anything else
 * at the root `.guardian/` are read like any other file.
 *
 * A file git TRACKS among those paths was never written there by
 * dev-guardian alone — the generated output is git-ignored — and a scanner
 * that leaves the path out would never read it: Semgrep names it as a
 * coverage gap (`runners/semgrepCoverageGaps.ts`), never a silent pass.
 *
 * ---- Semgrep's `--exclude` -----------------------------------------------
 *
 * Measured on Semgrep 1.176.1 (`test/e2e/guardianDirScan.test.ts`):
 *
 *   - `--exclude=.guardian` (no slash) matches a directory of that name at
 *     ANY depth — the 3.3.0 hole;
 *   - a slash at the start of a pattern or inside it (`/.guardian`,
 *     `.guardian/reports`) anchors it, as gitignore says — but at the GIT
 *     ROOT inside a work tree, at the target only outside one (as
 *     `platform/guardianIgnore.ts` measured). In a project below its
 *     repository's root, `--exclude=/.guardian` excludes nothing of the
 *     project's own;
 *   - from Git Bash, MSYS rewrites an argument that starts with `/` into a
 *     Windows path (`/.guardian` → `C:/Program Files/Git/.guardian`), so a
 *     hand measurement there reads "a leading slash excludes nothing" in
 *     every case (review 10 did). dev-guardian spawns Semgrep without a
 *     shell: the flag arrives as written.
 *
 * So the flags are the anchored form with NO prefix. Whichever of those two
 * anchors Semgrep uses, a pattern can only name `<anchor>/.guardian/…`, and
 * the anchor is the project or one of its ancestors: it never reaches a
 * `.guardian` below the project's root. A project below its repository's
 * root (`packages/api`) is not excluded by them at all — it relies on the
 * `.gitignore` lines the server and the CLI write (`gitignoreGuard.ts`),
 * which Semgrep honours through git; reading its reports costs time, never
 * a finding missed.
 */

/** The directory's name. */
export const DOT_GUARDIAN = '.guardian';

/** The generated directories, project-relative (no trailing slash). */
const OUTPUT_DIRS: readonly string[] = ['.guardian/reports'];

/** The generated files, project-relative. */
const OUTPUT_FILES: readonly string[] = [
  '.guardian/guardian.db',
  '.guardian/guardian.db-wal',
  '.guardian/guardian.db-shm',
  '.guardian/guardian.db-journal',
  '.guardian/dashboard.html',
  '.guardian/last-grill.md',
  '.guardian/.gitignore',
];

/** Every generated path, project-relative and `/`-separated — directories first, then files. */
export const ROOT_OUTPUT_PATHS: readonly string[] = [...OUTPUT_DIRS, ...OUTPUT_FILES];

/**
 * Whether a project-relative path (`/` or `\` separated, a leading `./`
 * allowed) is the root `.guardian/`'s generated output. Case-sensitive, as
 * dev-guardian writes these names: a `.Guardian/reports/x.js` is read.
 */
export function isGuardianOutput(rel: string): boolean {
  let p = rel.split('\\').join('/');
  while (p.startsWith('./')) p = p.slice(2);
  return OUTPUT_FILES.includes(p) || OUTPUT_DIRS.some((dir) => p === dir || p.startsWith(`${dir}/`));
}

/** Semgrep's flags for the generated output — see the module comment for why this spelling. */
export function semgrepGuardianOutputExcludes(): string[] {
  return ROOT_OUTPUT_PATHS.map((p) => `--exclude=${p}`);
}
