/**
 * Every raw `node:fs` read or write left in `mcp/src`, and why it is not a
 * read or write of the scanned repository — which goes through
 * `platform/projectFs.ts` (or `hooks/configFile.ts`'s bounded reader).
 *
 * The review of 3.0.0 found about 112 raw `readFileSync` sites against three
 * uses of the hardened reader, and one of them — the startup `.gitignore`
 * upkeep — wrote through a dangling link and read `/dev/zero` until the
 * server was OOM-killed. This test is the lint that keeps the count honest:
 * it fails when a tracked `fs` call appears in a file, or in a number, this
 * list does not name, and when the list names more than the code holds (a
 * converted site must leave the list, or the list stops meaning anything).
 *
 * `kind`:
 *   - `own` — dev-guardian's own files: the plugin's shipped assets, its data
 *     directory, a temp directory it created, a report directory
 *     `ensureReportDir` verified (no link on the way) or created.
 *   - `user` — a path the operator named (a registered rule pack, `--out`,
 *     the project directory itself, a host config in the user's home).
 *   - `repo-safe` — the repository's, and safe as written: a listing typed
 *     from `Dirent`s that never descends a link, a `stat` that opens nothing,
 *     or a walk already judged link by link.
 *   - `repo-deferred` — the repository's and NOT yet converted, because the
 *     directory is another reviewer's this wave (`runners/`, `skillaudit/`,
 *     `hooks/`). Named so the gap is visible, with what it risks.
 *
 * Counted per file and per `fs` function (`readFileSync`, `statSync`, …), not
 * per line, so an unrelated edit does not move it.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { countSites, findFsCallSites } from '../../helpers/fsCallSites.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const MCP = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

type Kind = 'own' | 'user' | 'repo-safe' | 'repo-deferred';

interface Allowed {
  apis: Record<string, number>;
  kind: Kind;
  reason: string;
}

const ALLOWED: Record<string, Allowed> = {
  'src/ci/refConfig.ts': {
    apis: { writeFileSync: 2 },
    kind: 'repo-safe',
    reason:
      "one write copies the base ref's config into the run's own temp directory; the other is " +
      '--reset-exclusions-from (CI only, clean checkout) restoring an exclusion file after lstat-checking ' +
      'every path segment and unlinking the old one, written with flag wx; every read goes through projectFs',
  },
  'src/dast/evidence.ts': {
    apis: { writeFileSync: 1 },
    kind: 'own',
    reason: 'evidence files into the report directory ensureReportDir verified or created',
  },
  'src/fixpr/semgrepFix.ts': {
    apis: { writeFileSync: 1, statSync: 1 },
    kind: 'own',
    reason: 'writes filtered rule copies into its own mkdtemp directory; statSync of a rule config opens nothing (its read is bounded)',
  },
  'src/frameworks/projectLanguages.ts': {
    apis: { readdirSync: 1, readdir: 1 },
    kind: 'repo-safe',
    reason: 'Dirent-typed walk: descends only entries that are directories themselves, never a link; names only',
  },
  'src/hooks/dataRegistry.ts': {
    apis: { readdirSync: 1 },
    kind: 'own',
    reason: "the per-user data directory's registry listing, the hook's own guard path; never the project",
  },
  'src/hooks/guardedPath.ts': {
    apis: { statSync: 1 },
    kind: 'repo-safe',
    reason: "hooks/ (another reviewer's): a stat of an already-opened path's identity; opens nothing",
  },
  'src/hostsetup/setup.ts': {
    apis: { readdirSync: 1, readFileSync: 3, writeFileSync: 1 },
    kind: 'own',
    reason:
      "the plugin's own legacy templates and host-rules/ template, and a user-scope MCP config in the user's " +
      'home (the user\'s own file); every project-scope file goes through projectFs',
  },
  'src/mcpaudit/launch.ts': {
    apis: { stat: 1 },
    kind: 'user',
    reason: "is-it-a-file check of a command named by the user's own MCP config; opens nothing",
  },
  'src/pkgvet/popular.ts': { apis: { readFileSync: 1 }, kind: 'own', reason: "the plugin's shipped popular-package list" },
  'src/pkgvet/privateRegistry.ts': {
    apis: { readdirSync: 2 },
    kind: 'repo-safe',
    reason: 'names only, after walkLinksUnder refused network/device links; the workspace walk descends Dirent directories only',
  },
  'src/platform/configsDir.ts': { apis: { readdirSync: 1 }, kind: 'own', reason: "the plugin's shipped configs/ directory" },
  'src/platform/customRules.ts': {
    apis: { statSync: 2 },
    kind: 'user',
    reason: 'is-it-a-directory of a path the user registered; opens nothing (the read is readSmallText, bounded)',
  },
  'src/platform/pathSpelling.ts': {
    apis: { statSync: 2 },
    kind: 'own',
    reason:
      "paths stored in the user's own registered database (startup canonicalisation, `db adopt --rehome` run by " +
      'the user); network and device paths are never looked up, and an untrusted database is never read here',
  },
  'src/platform/projectFs.ts': {
    apis: { readdirSync: 1 },
    kind: 'repo-safe',
    reason: 'listProjectDir itself: lists a directory realpathInProject placed inside the project, Dirent-typed',
  },
  'src/platform/projectPath.ts': {
    apis: { statSync: 1 },
    kind: 'user',
    reason: 'is-it-a-directory of the project_path argument itself',
  },
  'src/platform/version.ts': { apis: { readFileSync: 1 }, kind: 'own', reason: "the plugin's own plugin.json / package.json" },
  'src/runners/git.ts': {
    apis: { readFileSync: 1, readdirSync: 1 },
    kind: 'repo-deferred',
    reason:
      "runners/ (another reviewer's): reads git's shallow file at the path git names, and lists a submodule " +
      'directory by name; unbounded read of a path inside the git directory',
  },
  'src/runners/gitleaksScan.ts': {
    apis: { copyFileSync: 1, writeFileSync: 2 },
    kind: 'repo-deferred',
    reason:
      "runners/ (another reviewer's): copies uncommitted project files (lstat-checked regular files, size-capped) " +
      'into a temp dir; the two writes are its own temp config and report',
  },
  'src/runners/projectFiles.ts': {
    apis: { readdirSync: 1 },
    kind: 'repo-safe',
    reason: "runners/ (another reviewer's): Dirent-typed walk, names only, never descends a link",
  },
  'src/runners/repoConfig.ts': {
    apis: { readdirSync: 2, statSync: 1, readFileSync: 1 },
    kind: 'repo-deferred',
    reason:
      "runners/ (another reviewer's): stat-size check then readFileSync of a repository config — a FIFO " +
      '(size 0) at that name blocks the read; listings are Dirent-typed',
  },
  'src/runners/scannerParsers/trivy.ts': {
    apis: { readFileSync: 4, readdirSync: 1 },
    kind: 'repo-deferred',
    reason:
      "runners/ (another reviewer's): Trivy's own report (own) and the repository's yarn.lock, Python manifest " +
      'and workspace manifests, read unbounded',
  },
  'src/runners/semgrepConfigs.ts': {
    apis: { readdirSync: 1 },
    kind: 'repo-safe',
    reason: "runners/ (another reviewer's): names at the project root only",
  },
  'src/runners/semgrepRuleIds.ts': {
    apis: { readFileSync: 2, readdirSync: 2 },
    kind: 'repo-deferred',
    reason:
      "runners/ (another reviewer's): rule files of the packs a scan loads — the plugin's own and the " +
      "project's Semgrep config — read unbounded",
  },
  'src/runners/stackDetect.ts': {
    apis: { readFileSync: 2, readdirSync: 1 },
    kind: 'repo-deferred',
    reason:
      "runners/ (another reviewer's): /proc/version (system) and readTextSafe of repository manifests, read " +
      'whole before being cut to maxBytes',
  },
  'src/runners/syftRun.ts': { apis: { writeFileSync: 1 }, kind: 'own', reason: 'its neutral config, into its own temp directory' },
  'src/runners/trivyConfig.ts': {
    apis: { statSync: 1, readFileSync: 1, readdirSync: 1 },
    kind: 'repo-deferred',
    reason:
      "runners/ (another reviewer's): stat-size check then readFileSync of the repository's Trivy config — a " +
      'FIFO (size 0) at that name blocks the read',
  },
  'src/runners/trivyRun.ts': {
    apis: { writeFileSync: 1, readFileSync: 1 },
    kind: 'own',
    reason: "its neutral config and Trivy's report, in its own directories",
  },
  'src/secrets/verify/rawReport.ts': {
    apis: { readdirSync: 1 },
    kind: 'own',
    reason: 'sweeps its own guardian-verify-* directories in the OS temp directory (lstat-checked)',
  },
  'src/skillaudit/ingest.ts': {
    apis: { statSync: 1, writeFileSync: 1, readdirSync: 1, readFileSync: 1 },
    kind: 'repo-deferred',
    reason:
      "skillaudit/ (another reviewer's): the skill under review is untrusted by design and ingest has its own " +
      'lstat/realpath containment and size cap; the write is a download into its own temp directory',
  },
  'src/storage/db.ts': {
    apis: { writeFileSync: 1, statSync: 1 },
    kind: 'own',
    reason: "storage/ (another reviewer's): its own database directory probe and size",
  },
  'src/storage/dbRegistry.ts': {
    apis: { readdirSync: 2, writeFileSync: 1 },
    kind: 'own',
    reason: "the user's own database registry under the per-user data directory (0700, owner-checked, temp+rename)",
  },
  'src/storage/migrations/runner.ts': {
    apis: { readdirSync: 2, readFileSync: 2 },
    kind: 'own',
    reason: "storage/ (another reviewer's): the plugin's shipped migrations",
  },
  'src/storage/userData.ts': {
    apis: { statSync: 1 },
    kind: 'own',
    reason: "the per-user data directory's own ownership and mode check",
  },
  'src/surface/scanSemgrep.ts': {
    apis: { copyFileSync: 1 },
    kind: 'own',
    reason: "the plugin's route rule pack, staged into its own temp directory",
  },
  'src/surface/specDiscover.ts': {
    apis: { readdirSync: 1 },
    kind: 'repo-safe',
    reason: 'Dirent-typed walk for spec candidates, never descends a link; each candidate is read through projectFs',
  },
  'src/tools/depsAudit.ts': {
    apis: { writeFileSync: 2 },
    kind: 'own',
    reason: 'scanner output into the report directory ensureReportDir verified or created',
  },
  'src/tools/exportVex.ts': {
    apis: { writeFileSync: 1, readFileSync: 1 },
    kind: 'own',
    reason: 'the VEX document into a verified report directory, and the SBOM generate_sbom itself wrote',
  },
  'src/tools/generateSbom.ts': {
    apis: { statSync: 1, readFileSync: 1 },
    kind: 'own',
    reason: "Syft's output file in a verified report directory",
  },
  'src/tools/healthStatus.ts': { apis: { statSync: 1 }, kind: 'own', reason: 'the size of its own database file' },
  'src/tools/perfCheck.ts': {
    apis: { readFileSync: 2, writeFileSync: 1 },
    kind: 'own',
    reason: 'Lighthouse / k6 output in a verified report directory',
  },
  'src/tools/registerCustomRules.ts': {
    apis: { statSync: 3 },
    kind: 'user',
    reason: 'is-it-a-file/directory of the paths the user registers; opens nothing',
  },
  'src/tools/sbomDiff.ts': {
    apis: { readFileSync: 1 },
    kind: 'own',
    reason: 'an SBOM file generate_sbom wrote, at the path its own scan row recorded',
  },
  'src/tools/scanIac.ts': {
    apis: { writeFileSync: 1 },
    kind: 'own',
    reason: 'scanner output into a verified report directory',
  },
  'src/tools/scanSast.ts': {
    apis: { writeFileSync: 2, readFileSync: 1, readdirSync: 1 },
    kind: 'own',
    reason: "the neutral Bandit config and SARIF targets into its own directories, and the build's SARIF read back from its own mkdtemp directory",
  },
  'src/tools/scanSkill.ts': {
    apis: { writeFileSync: 2 },
    kind: 'own',
    reason: 'the audit report into the directory ensureReportDir verified or created',
  },
  'src/tools/vetPackages.ts': {
    apis: { statSync: 1 },
    kind: 'user',
    reason: 'is-it-a-directory of the project_dir argument itself',
  },
  'src/tools/wpVulnCheck.ts': {
    apis: { readdirSync: 1, readFileSync: 1, writeFileSync: 1 },
    kind: 'own',
    reason: "WPScan's report in its own cache directory, and pruning that directory",
  },
  'src/treeHash/cacheKey.ts': {
    apis: { readdirSync: 1, statSync: 1 },
    kind: 'repo-safe',
    reason: 'rule-pack keying: a Dirent-typed walk and a stat that opens nothing; the hashing is hashRegularFileSync (non-blocking, regular files only)',
  },
  'src/treeHash/computeTreeHash.ts': {
    apis: { readdir: 1, stat: 1 },
    kind: 'repo-safe',
    reason: 'Dirent-typed walk that never descends a link, and a stat of an entry already typed a regular file; the content is hashProjectFile',
  },
  'src/wordpress/vulnFeed.ts': {
    apis: { readFile: 1, writeFileSync: 1 },
    kind: 'own',
    reason: "the vulnerability feed cache in dev-guardian's own data directory",
  },
};

describe('raw fs calls in mcp/src', () => {
  const sites = findFsCallSites(MCP, join(MCP, 'src'));
  const actual = countSites(sites);

  it('every raw read or write of a file is on the list, in the number the list says', () => {
    const unexpected: string[] = [];
    for (const [file, perApi] of actual) {
      const allowed = ALLOWED[file];
      for (const [api, n] of perApi) {
        const want = allowed?.apis[api] ?? 0;
        if (n !== want) {
          const where = sites
            .filter((s) => s.file === file && s.api === api)
            .map((s) => `    ${s.file}:${s.line}  ${s.text}`)
            .join('\n');
          unexpected.push(`${file}: ${api} x${n}, list says ${want}\n${where}`);
        }
      }
    }
    expect(
      unexpected,
      'A raw fs call of the scanned repository must go through platform/projectFs.ts ' +
        '(readProjectText / readProjectBytes / listProjectDir / writeProjectFile). If this one is ' +
        "dev-guardian's own file or a path the user named, add it to ALLOWED with the reason.",
    ).toEqual([]);
  });

  it('the list names nothing the code no longer holds', () => {
    const stale: string[] = [];
    for (const [file, allowed] of Object.entries(ALLOWED)) {
      for (const [api, want] of Object.entries(allowed.apis)) {
        const n = actual.get(file)?.get(api) ?? 0;
        if (n < want) stale.push(`${file}: ${api} list says ${want}, code has ${n}`);
      }
    }
    expect(stale, 'a converted site must leave the list').toEqual([]);
  });

  it('every entry says why', () => {
    for (const [file, allowed] of Object.entries(ALLOWED)) {
      expect(allowed.reason.length, file).toBeGreaterThan(20);
    }
  });

  it('the scan finds an aliased import and a namespace import (positive control)', () => {
    const root = makeTempDir('fs-sites-control-');
    mkdirSync(join(root, 'src'));
    writeFileSync(
      join(root, 'src', 'a.ts'),
      [
        "import { readFileSync as rf, statSync } from 'node:fs';",
        "import * as fsp from 'node:fs/promises';",
        '// readFileSync(x) in a comment is not a call',
        "const s = 'writeFileSync(y)';",
        "rf('a');",
        "void fsp.readFile('b');",
        "statSync('c');",
        'const o = { readFileSync: (x: string) => x };',
        "o.readFileSync('d');",
      ].join('\n'),
    );
    const found = findFsCallSites(root, join(root, 'src')).map((x) => `${x.api}@${x.line}`);
    expect(found).toEqual(['readFileSync@5', 'readFile@6', 'statSync@7']);
  });
});
