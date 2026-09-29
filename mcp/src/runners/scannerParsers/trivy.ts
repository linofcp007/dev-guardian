/**
 * Trivy JSON output parser.
 *
 * One parser handles three Trivy modes (the JSON layouts overlap):
 *   - `trivy fs --scanners vuln,license` → Results[].Vulnerabilities[],
 *                                         Results[].Licenses[]
 *   - `trivy config Dockerfile`          → Results[].Misconfigurations[]
 *   - `trivy config <iac>`               → Results[].Misconfigurations[]
 *
 * Vulnerabilities additionally feed the `cves` table so the
 * `guardian://cves/active` resource can serve dedicated CVE queries
 * without re-deriving them from `findings`.
 */

import { existsSync, readdirSync, readFileSync, type Dirent } from 'node:fs';
import { dirname, join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { Category, Finding, Severity } from '../../types.js';
import { PROJECT_WALK_EXCLUDE } from '../projectFiles.js';
import {
  asArray,
  dependencyTaxonomy,
  getNumber,
  getProp,
  getString,
  makeFinding,
  SECRET_CWE,
  normalizeSeverity,
  parseInputAsJson,
  toRelativeIfPossible,
  type ParserContext,
  type ParserCveInput,
  type ParserOutput,
  type ScannerParser,
} from './index.js';

export const TRIVY_TOOL_NAME = 'trivy';

export const trivyParser: ScannerParser = {
  name: TRIVY_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const root = parseInputAsJson(input);
    const findings: Finding[] = [];
    const cves: ParserCveInput[] = [];

    for (const result of asArray(getProp(root, 'Results'))) {
      const target = getString(result, 'Target') ?? '';

      for (const v of asArray(getProp(result, 'Vulnerabilities'))) {
        const finding = mapVulnerability(v, target, ctx);
        if (finding) findings.push(finding);
        const cve = mapVulnerabilityCve(v);
        if (cve) cves.push(cve);
      }

      for (const l of asArray(getProp(result, 'Licenses'))) {
        const finding = mapLicense(l, target, ctx);
        if (finding) findings.push(finding);
      }

      for (const m of asArray(getProp(result, 'Misconfigurations'))) {
        const finding = mapMisconfiguration(m, target, ctx);
        if (finding) findings.push(finding);
      }

      for (const s of asArray(getProp(result, 'Secrets'))) {
        const finding = mapSecret(s, target, ctx);
        if (finding) findings.push(finding);
      }
    }

    return { findings, cves };
  },
};

function mapVulnerability(raw: unknown, target: string, ctx: ParserContext): Finding | null {
  const cveId = getString(raw, 'VulnerabilityID');
  const pkg = getString(raw, 'PkgName');
  if (!cveId || !pkg) return null;
  const severity = normalizeSeverity(getString(raw, 'Severity'));
  const title = getString(raw, 'Title') ?? `${cveId} in ${pkg}`;
  const installed = getString(raw, 'InstalledVersion');
  const fixed = getString(raw, 'FixedVersion');
  const description = getString(raw, 'Description');

  const input: Parameters<typeof makeFinding>[0] = {
    tool: TRIVY_TOOL_NAME,
    rule_id: cveId,
    severity,
    category: 'security',
    subcategory: 'cve',
    title,
    fix_available: fixed !== undefined && fixed.length > 0,
    file_path: toRelativeIfPossible(target, ctx.project_path),
    // A vulnerable dependency is CWE-1395 and A03 whatever the flaw inside
    // it; the advisory's own CweIDs name that flaw, in `cwe` only.
    taxonomy: dependencyTaxonomy(asArray(getProp(raw, 'CweIDs'))),
  };
  if (description !== undefined) input.message = description;
  // The advisory's other ids as Trivy's database gives them (the GHSA id of
  // a CVE, for a language package) — never the CVEs its description names.
  input.vuln_aliases = asArray(getProp(raw, 'VendorIDs'));
  // Trivy "snippet" surrogate: enough package metadata to make the
  // fingerprint unique per (cve, package, installed_version) tuple.
  //
  // The `->fixed` half is also in the fingerprint, so the fingerprint changes
  // when the advisory database learns of a fix — the project did not change
  // at all. It stays, byte for byte, because suppressions and v1
  // `baseline.json` files from 2.0.x name these findings by that
  // fingerprint. The line-independent identity every cross-scan comparison
  // matches on first reads only `pkg@installed` out of this string
  // (`fingerprint/findingIdentity.ts#dependencyCoordinates`, which also
  // relies on the name ending at the LAST `@` before `->`): keep that shape.
  input.snippet = `${pkg}@${installed ?? ''}->${fixed ?? ''}`;
  return makeFinding(input);
}

function mapVulnerabilityCve(raw: unknown): ParserCveInput | null {
  const cveId = getString(raw, 'VulnerabilityID');
  const pkg = getString(raw, 'PkgName');
  if (!cveId || !pkg) return null;
  const cve: ParserCveInput = {
    cve_id: cveId,
    package_name: pkg,
    severity: normalizeSeverity(getString(raw, 'Severity')),
  };
  const installed = getString(raw, 'InstalledVersion');
  if (installed !== undefined) cve.installed_version = installed;
  const fixed = getString(raw, 'FixedVersion');
  if (fixed !== undefined) cve.fixed_version = fixed;
  return cve;
}

function mapLicense(raw: unknown, target: string, ctx: ParserContext): Finding | null {
  const pkg = getString(raw, 'PkgName');
  const license = getString(raw, 'Name');
  if (!license) return null;
  const severity = normalizeSeverity(getString(raw, 'Severity'));
  const title = `License '${license}' on ${pkg ?? target}`;

  const input: Parameters<typeof makeFinding>[0] = {
    tool: TRIVY_TOOL_NAME,
    rule_id: `license:${license}`,
    severity,
    category: 'license',
    subcategory: license.toLowerCase(),
    title,
    file_path: toRelativeIfPossible(target, ctx.project_path),
    snippet: pkg ? `pkg:${pkg}` : `license:${license}`,
  };
  return makeFinding(input);
}

function mapMisconfiguration(raw: unknown, target: string, ctx: ParserContext): Finding | null {
  const id = getString(raw, 'ID') ?? getString(raw, 'AVDID');
  if (!id) return null;
  const severity = normalizeSeverity(getString(raw, 'Severity'));
  const title = getString(raw, 'Title') ?? id;
  const message = getString(raw, 'Description');
  const cause = getProp(raw, 'CauseMetadata');
  const lineStart = getNumber(cause, 'StartLine');
  const lineEnd = getNumber(cause, 'EndLine') ?? lineStart;
  const type = getString(raw, 'Type')?.toLowerCase();
  const category: Category = 'security';
  const subcategory = type ?? 'misconfiguration';

  const input: Parameters<typeof makeFinding>[0] = {
    tool: TRIVY_TOOL_NAME,
    rule_id: id,
    severity,
    category,
    subcategory,
    title,
    file_path: toRelativeIfPossible(target, ctx.project_path),
  };
  if (message !== undefined) input.message = message;
  if (lineStart !== undefined) input.line_start = lineStart;
  if (lineEnd !== undefined) input.line_end = lineEnd;
  const fixHint = getString(raw, 'Resolution');
  if (fixHint !== undefined) input.snippet = fixHint;
  return makeFinding(input);
}

function mapSecret(raw: unknown, target: string, ctx: ParserContext): Finding | null {
  const ruleId = getString(raw, 'RuleID') ?? getString(raw, 'Rule');
  if (!ruleId) return null;
  const severity: Severity = normalizeSeverity(getString(raw, 'Severity') ?? 'HIGH');
  const lineStart = getNumber(raw, 'StartLine');
  const lineEnd = getNumber(raw, 'EndLine') ?? lineStart;
  const input: Parameters<typeof makeFinding>[0] = {
    tool: TRIVY_TOOL_NAME,
    rule_id: ruleId,
    severity,
    category: 'security',
    subcategory: 'secret',
    title: getString(raw, 'Title') ?? ruleId,
    file_path: toRelativeIfPossible(target, ctx.project_path),
    taxonomy: { cwe: [SECRET_CWE] },
  };
  if (lineStart !== undefined) input.line_start = lineStart;
  if (lineEnd !== undefined) input.line_end = lineEnd;
  return makeFinding(input);
}

// ---------------------------------------------------------------- manifest coverage
//
// Task 10, item 1: a bare `.csproj` (no `packages.lock.json`) is silently
// "not scanned" by Trivy fs — reproduced against Trivy 0.69.3: the JSON
// report omits the `Results` key entirely (identical to an empty project),
// while stderr only ever logs `Number of language-specific files num=0`.
// The caller (scanDeps.ts / depsAudit.ts) used to read that as `ok`, 0
// findings — a clean bill of health for a project that was never scanned.
//
// The same silent gap exists for `package.json` without any npm/yarn/pnpm
// lockfile and for `composer.json` without `composer.lock` — confirmed the
// same way. And (final review, I4) for Gradle and Python, measured on
// 0.69.3: `Results: []` for a `build.gradle` / `build.gradle.kts` without
// `gradle.lockfile`, a PEP 621 `pyproject.toml` without `poetry.lock` /
// `uv.lock`, a `Pipfile` without `Pipfile.lock`, a `requirements-dev.txt`
// (Trivy reads `requirements.txt` only) and an UNPINNED `requirements.txt`
// (`django`, no `==`) — and a setuptools project: Trivy reads neither
// `setup.py` nor `setup.cfg` (a `setup.py` with `install_requires` beside a
// `[build-system]`-only `pyproject.toml` read full, 0 findings). A pinned
// `requirements.txt` is read on its own (Type
// `pip`, Target `requirements.txt`), so it covers Python like a lock file.
// `go.mod` is scanned from the bare manifest (a `gomod` Result, with or
// without `require` lines) — but one Trivy cannot parse gets no Result,
// `num=0`, exit 0, and is a gap like the others (review I1).
//
// Review I1 also took the check off the ROOT: it read the top-level
// directory only and called a buried manifest "Trivy's own concern" — and
// Trivy skips a buried manifest with no lock file just as silently
// (`web/package.json`, `api/pyproject.toml`: no Results, coverage full). The
// project is walked now, and each manifest judged in its own directory
// (`assessManifestCoverage` below).
//
// Nor is there a gap for a `package.json` that declares no dependency at
// all. Measured against 0.69.3: such a manifest produces no `Results` key
// WITH a `package-lock.json` beside it as much as without one, so the
// report is byte-for-byte the bare-manifest gap above — but nothing was
// missed, and no lock file a user could add would change what Trivy says.
// Flagged, it turned every package.json kept only for `scripts` (and the
// CI CLI's own clean e2e fixture) into a permanently INCOMPLETE scan. Only
// npm gets this test: its manifest is the whole declaration. A `.csproj`
// with no `PackageReference` still draws packages from
// `Directory.Packages.props`, `Directory.Build.props` and the SDK's own
// framework reference, so an empty-looking one stays a gap.
//
// The boundary of that exclusion: it takes the manifest out BEFORE the
// "did Trivy cover it?" question, so it must hold only where nothing could
// be missed — the manifest AND every root lock file lock nothing. A lock
// file that still locks packages (a stale one, left behind when a
// dependency was deleted from package.json) is something to audit: `npm ci`
// installs from it. Trivy 0.69.3 does report such a lock file (v1, v3 and
// yarn.lock measured), so npm reads covered either way today; if a Trivy
// ever stops, the gap is reported instead of hidden. A lock file this code
// does not read (pnpm-lock.yaml, bun.lock, bun.lockb) or cannot parse
// counts as locking something. test/e2e/trivyManifestCoverage.test.ts pins
// both measured facts on the Trivy on PATH.

interface EcosystemManifest {
  /** Human label used in `ManifestCoverageGap.ecosystem`. */
  ecosystem: string;
  /** Matches a file name, in any directory the walk reads, against this ecosystem. */
  matches: (name: string) => boolean;
  /** Trivy `Results[].Type` values that count as this ecosystem being
   *  covered by whatever Trivy actually scanned (its lockfile, not
   *  necessarily the manifest file itself — Trivy reports the LOCKFILE as
   *  `Target`, so the Target's file name is never compared: only its
   *  DIRECTORY, with the manifest's, beside the Type). */
  trivyTypes: readonly string[];
  /** The file names Trivy reads for those Types — the `Target` of their
   *  Results, and so the `file_path` of every CVE / license finding they
   *  produce. `history/runNames.ts` keys those findings by ecosystem with
   *  it, so a gap here vetoes exactly the findings it could have hidden. */
  lockfiles: readonly string[];
  /** True when the manifest at this path declares nothing Trivy could
   *  report on, so its missing Result is not a gap. Absent: always a gap. */
  declaresNothing?: (path: string) => boolean;
  /** How to give Trivy something to read: the lock file to generate, and how. */
  fix: string;
}

const ECOSYSTEM_MANIFESTS: readonly EcosystemManifest[] = [
  {
    ecosystem: 'npm',
    matches: (n) => n === 'package.json',
    trivyTypes: ['npm', 'yarn', 'pnpm', 'bun'],
    lockfiles: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock'],
    declaresNothing: npmManifestDeclaresNothing,
    fix: 'commit the lock file your package manager writes (package-lock.json, yarn.lock, pnpm-lock.yaml or bun.lock)',
  },
  {
    ecosystem: 'composer',
    matches: (n) => n === 'composer.json',
    trivyTypes: ['composer'],
    lockfiles: ['composer.lock'],
    fix: 'commit composer.lock (composer update writes it)',
  },
  {
    ecosystem: 'dotnet',
    // A project file, never a `.sln`: a solution only lists projects, and the
    // walk judges each of them in its own directory — where its
    // packages.lock.json is (review I1). Judged at the solution's directory,
    // every solution with its projects below it would read as a gap.
    matches: (n) => /\.(csproj|fsproj|vbproj)$/i.test(n),
    trivyTypes: ['nuget'],
    lockfiles: ['packages.lock.json', 'packages.config'],
    fix: 'set RestorePackagesWithLockFile to true, run dotnet restore and commit packages.lock.json',
  },
  {
    ecosystem: 'rubygems',
    matches: (n) => n === 'Gemfile',
    trivyTypes: ['bundler'],
    lockfiles: ['Gemfile.lock'],
    fix: 'commit Gemfile.lock (bundle lock writes it)',
  },
  {
    ecosystem: 'cargo',
    matches: (n) => n === 'Cargo.toml',
    trivyTypes: ['cargo'],
    lockfiles: ['Cargo.lock'],
    fix: 'commit Cargo.lock (cargo generate-lockfile writes it)',
  },
  {
    ecosystem: 'gradle',
    matches: (n) => n === 'build.gradle' || n === 'build.gradle.kts',
    trivyTypes: ['gradle'],
    lockfiles: ['gradle.lockfile'],
    // `--write-locks` writes nothing until locking is switched on in the build.
    fix:
      'enable dependencyLocking { lockAllConfigurations() } in the build, then run ' +
      'gradle dependencies --write-locks and commit gradle.lockfile',
  },
  {
    ecosystem: 'python',
    matches: (n) =>
      n === 'pyproject.toml' ||
      n === 'Pipfile' ||
      n === 'setup.py' ||
      n === 'setup.cfg' ||
      /^requirements.*\.txt$/i.test(n),
    trivyTypes: ['pip', 'pipenv', 'poetry', 'uv'],
    lockfiles: ['requirements.txt', 'Pipfile.lock', 'poetry.lock', 'uv.lock'],
    declaresNothing: pythonManifestDeclaresNothing,
    fix:
      'commit poetry.lock, uv.lock or Pipfile.lock (poetry lock, uv lock, pipenv lock), ' +
      'or pin every dependency (==) in requirements.txt',
  },
  {
    // Trivy reads go.mod itself (measured on 0.69.3: a `gomod` Result for a
    // go.mod with or without `require` lines). One it cannot parse gets no
    // Result at all — `Number of language-specific files num=0`, exit 0 —
    // which used to read full (review I1).
    ecosystem: 'go',
    matches: (n) => n === 'go.mod',
    trivyTypes: ['gomod'],
    lockfiles: ['go.mod', 'go.sum'],
    fix: 'Trivy read nothing from it: make go.mod parse (go mod tidy reports why it does not) and re-run',
  },
];

/** Every ecosystem the coverage check can report a gap for (`ManifestCoverageGap.ecosystem`). */
export const MANIFEST_ECOSYSTEMS: readonly string[] = ECOSYSTEM_MANIFESTS.map((e) => e.ecosystem);

/** How to give Trivy a file it reads for `ecosystem`, or null for one this table does not know. */
export function lockFileAdvice(ecosystem: string): string | null {
  return ECOSYSTEM_MANIFESTS.find((e) => e.ecosystem === ecosystem)?.fix ?? null;
}

/** Each ecosystem with the lock file names Trivy reports its Results under. */
export const MANIFEST_ECOSYSTEM_LOCKFILES: ReadonlyArray<{ ecosystem: string; lockfiles: readonly string[] }> =
  ECOSYSTEM_MANIFESTS.map((e) => ({ ecosystem: e.ecosystem, lockfiles: e.lockfiles }));

/**
 * The ecosystem whose lock file a Trivy Result `Target` (a finding's
 * `file_path`) names, at any depth, or null — an OS package in an image, a
 * `go.mod`, a `requirements.txt`: nothing the coverage check reports on.
 */
export function manifestEcosystemOfTarget(target: string): string | null {
  const base = target.slice(Math.max(target.lastIndexOf('/'), target.lastIndexOf('\\')) + 1).toLowerCase();
  const eco = ECOSYSTEM_MANIFESTS.find((e) => e.lockfiles.some((l) => l.toLowerCase() === base));
  return eco?.ecosystem ?? null;
}

/** npm dependency fields; `workspaces` because the members declare theirs. */
const NPM_DECLARING_FIELDS = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
  'bundleDependencies',
  'bundledDependencies',
  'workspaces',
] as const;

/** `undefined`, `{}` and `[]`; anything else (`null`, `true`, entries) may hold something. */
function isEmptyField(v: unknown): boolean {
  if (v === undefined) return true;
  if (Array.isArray(v)) return v.length === 0;
  return typeof v === 'object' && v !== null && Object.keys(v).length === 0;
}

/** Parsed JSON, BOM tolerated, or `undefined` when the file does not parse. */
function readJsonFile(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, '')) as unknown;
  } catch {
    return undefined;
  }
}

/** Root npm lock files this code reads: they lock nothing when every `packages` key is the root (`''`) and v1's `dependencies` is empty. */
const NPM_JSON_LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json'] as const;
/** Root npm lock files this code does not read: present, each may lock something. */
const NPM_UNREAD_LOCKFILES = ['pnpm-lock.yaml', 'bun.lock', 'bun.lockb'] as const;

/**
 * Whether every npm lock file at the root of `dir` is absent or locks
 * nothing. A lock file that does not parse, or one this code does not read,
 * may lock something: see the module comment on this exclusion's boundary.
 */
function npmLockFilesLockNothing(dir: string): boolean {
  for (const name of NPM_UNREAD_LOCKFILES) if (existsSync(join(dir, name))) return false;
  for (const name of NPM_JSON_LOCKFILES) {
    const path = join(dir, name);
    if (!existsSync(path)) continue;
    const lock = readJsonFile(path);
    if (typeof lock !== 'object' || lock === null || Array.isArray(lock)) return false;
    const { packages, dependencies } = lock as Record<string, unknown>;
    if (packages !== undefined) {
      if (typeof packages !== 'object' || packages === null || Array.isArray(packages)) return false;
      if (Object.keys(packages).some((k) => k !== '')) return false;
    }
    if (!isEmptyField(dependencies)) return false;
  }
  const yarnLock = join(dir, 'yarn.lock');
  if (existsSync(yarnLock)) {
    let text: string;
    try {
      text = readFileSync(yarnLock, 'utf8');
    } catch {
      return false;
    }
    // Only the `# ...` header and blank lines: what yarn writes with nothing to lock.
    if (text.split(/\r?\n/).some((line) => line.trim() !== '' && !line.trimStart().startsWith('#'))) return false;
  }
  return true;
}

/**
 * A `package.json` that parses to an object, whose every dependency field
 * (and `workspaces`) is absent, `{}` or `[]`, and beside which no root lock
 * file locks anything. Anything else (a field with entries,
 * `bundleDependencies: true`, a manifest that does not parse, a stale lock
 * file still locking packages) may declare something, and stays a gap.
 */
function npmManifestDeclaresNothing(path: string): boolean {
  const manifest = readJsonFile(path);
  if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest)) return false;
  const fields = manifest as Record<string, unknown>;
  return NPM_DECLARING_FIELDS.every((k) => isEmptyField(fields[k])) && npmLockFilesLockNothing(dirname(path));
}

/** A TOML value that is literally empty: `[]` or `{}`, an optional trailing comment. */
const EMPTY_TOML_VALUE = /^(\[\s*\]|\{\s*\})\s*(#.*)?$/;
/** Key names that declare dependencies in whatever table they sit in (setuptools' dynamic ones included). */
const PY_DEPENDENCY_KEYS: ReadonlySet<string> = new Set(['dependencies', 'optional-dependencies', 'dev-dependencies']);
/** Tables whose every key is a dependency (Poetry's `python` constraint aside). */
const PY_DEPENDENCY_TABLES =
  /^(project\.optional-dependencies(\..+)?|dependency-groups|tool\.poetry\.(dependencies|dev-dependencies|group\.[^.]+\.dependencies)|tool\.pdm\.dev-dependencies|packages|dev-packages)$/;

/**
 * Python's "declares nothing" — nothing Trivy could have missed, so no gap:
 * a `requirements*.txt` with no line but blanks and comments; a `setup.py`
 * / `setup.cfg` that never mentions `install_requires` / `extras_require`;
 * a `Pipfile` with no entry under `[packages]` / `[dev-packages]`; a `pyproject.toml`
 * that declares no dependency — the common tool-config-only file (`[tool.ruff]`,
 * `[build-system]`), or a `[project]` without `dependencies`. Read line by
 * line, conservatively: a dependency key whose value is not literally `[]` /
 * `{}` (a multi-line array included), an entry in a dependency table
 * (Poetry's lone `python` constraint aside), a table header this reader
 * cannot parse, or a file it cannot read — each may declare something, and
 * stays a gap.
 */
function pythonManifestDeclaresNothing(path: string): boolean {
  let text: string;
  try {
    text = readFileSync(path, 'utf8').replace(/^﻿/, '');
  } catch {
    return false;
  }
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'));
  if (/\.txt$/i.test(path)) return lines.length === 0;
  // setuptools: Trivy reads neither file. `install_requires` / `extras_require`
  // anywhere (a keyword argument in setup.py, a key or an
  // `[options.extras_require]` section in setup.cfg) may declare something.
  if (/(^|[\\/])setup\.py$/i.test(path)) return !/\b(install_requires|extras_require)\b/.test(text);
  if (/(^|[\\/])setup\.cfg$/i.test(path)) {
    return !/^\s*(install_requires|extras_require)\s*=/m.test(text) && !/^\s*\[options\.extras_require\]/m.test(text);
  }

  let table = '';
  for (const line of lines) {
    if (line.startsWith('[')) {
      const header = /^\[\[?\s*([^\]]+?)\s*\]\]?\s*(#.*)?$/.exec(line);
      if (header?.[1] === undefined) return false;
      table = header[1].replace(/["'\s]/g, '');
      continue;
    }
    const kv = /^["']?([A-Za-z0-9_.-]+)["']?\s*=\s*(.*)$/.exec(line);
    // Not a key: the continuation of a value whose key was already judged.
    if (kv?.[1] === undefined || kv[2] === undefined) continue;
    const key = kv[1];
    const empty = EMPTY_TOML_VALUE.test(kv[2]);
    const lastSegment = key.slice(key.lastIndexOf('.') + 1);
    if (PY_DEPENDENCY_KEYS.has(lastSegment) && !empty) return false;
    if (PY_DEPENDENCY_TABLES.test(table) && !empty && !(table.startsWith('tool.poetry.') && key === 'python')) {
      return false;
    }
  }
  return true;
}

export interface ManifestCoverageGap {
  ecosystem: string;
  /** The manifest file(s) Trivy read nothing for, project-relative (`/`), sorted. */
  files: string[];
}

export interface ManifestCoverageAssessment {
  /** Ecosystems with a manifest Trivy's own output shows no Result for — in
   *  the manifest's directory, or its workspace root's. Empty when nothing
   *  was missed. */
  gaps: ManifestCoverageGap[];
  /** Whether Trivy's `Results` array had ANY entry at all (any ecosystem,
   *  not just the ones in {@link ECOSYSTEM_MANIFESTS}) — used to tell a
   *  scan that recognised nothing whatsoever (skip the tool run entirely)
   *  from one that covered some ecosystems but missed others (still ok,
   *  reduced coverage). */
  sawAnyResults: boolean;
  /** Why the walk did not read every directory — manifests below were not checked. Absent: it did. */
  walkIncomplete?: string;
}

export interface ManifestWalkOptions {
  /**
   * The project's `.guardianignore` (`ProjectExclusions.ignores`): a path it
   * excludes is not the project's own code, and Trivy was told to skip it.
   */
  ignores?: ((relPath: string, isDir?: boolean) => boolean) | null;
  /** Directories the walk reads at most. Default {@link MAX_MANIFEST_WALK_DIRS}. */
  maxDirs?: number;
}

/** The ceiling detect_stack's manifest walk and the project-languages walk use. */
const MAX_MANIFEST_WALK_DIRS = 20_000;

interface FoundManifest {
  /** Project-relative, `/`-separated. */
  rel: string;
  /** Its directory, `''` for the root. */
  dir: string;
  abs: string;
  eco: EcosystemManifest;
}

/** The directory part of a `/`- or `\`-separated path, `/`-separated (`''` at the top). */
function dirOf(path: string): string {
  const posix = path.replace(/\\/g, '/').replace(/^\.\//, '');
  const i = posix.lastIndexOf('/');
  return i < 0 ? '' : posix.slice(0, i);
}

/**
 * Directories the manifest walk does not enter besides `PROJECT_WALK_EXCLUDE`
 * (round 4, items 4 and 5): version control, the package managers' own
 * caches, and bower's and jspm's dependency directories — what is in them is
 * not the project's manifest. Every other hidden directory IS walked: Trivy
 * reads them, and a GitHub composite action's `.github/actions/notify/
 * package.json` with no lock read full while the walk skipped `.github`.
 * Examples, docs and fixtures are walked too — whether one ships is the
 * project's to say, in `.guardianignore` (the coverage warning says so).
 */
const MANIFEST_WALK_EXCLUDE: ReadonlySet<string> = new Set([
  '.git',
  '.hg',
  '.svn',
  '.bzr',
  '_darcs',
  'CVS',
  '.yarn',
  '.pnpm-store',
  '.npm',
  '.gradle',
  '.m2',
  '.terraform',
  'bower_components',
  'jspm_packages',
]);

/**
 * Every manifest of a {@link ECOSYSTEM_MANIFESTS} ecosystem under the
 * project, bounded: the directories no scan of the project's own files
 * reads (`node_modules`, `vendor`, build output, virtualenvs, caches — the
 * `PROJECT_WALK_EXCLUDE` every other walk uses), {@link MANIFEST_WALK_EXCLUDE}
 * and `.guardianignore` entries are not entered, symbolic links are not
 * followed, and at most `maxDirs` directories are read.
 */
function walkManifests(
  projectPath: string,
  opts: ManifestWalkOptions,
): { found: FoundManifest[]; incomplete?: string } | null {
  const maxDirs = opts.maxDirs ?? MAX_MANIFEST_WALK_DIRS;
  const ignores = opts.ignores ?? null;
  const found: FoundManifest[] = [];
  const stack: string[] = [''];
  let visited = 0;
  let rootRead = false;
  const unreadable: string[] = [];
  while (stack.length > 0) {
    const rel = stack.pop();
    if (rel === undefined) break;
    if (visited >= maxDirs) {
      return { found, incomplete: `the manifest walk stopped after ${maxDirs} directories` };
    }
    visited += 1;
    const abs = rel === '' ? projectPath : join(projectPath, ...rel.split('/'));
    let entries: Dirent[];
    try {
      entries = readdirSync(abs, { withFileTypes: true });
    } catch {
      if (rel === '') return null;
      unreadable.push(`${rel}/`);
      continue;
    }
    if (rel === '') rootRead = true;
    for (const e of entries) {
      const child = rel === '' ? e.name : `${rel}/${e.name}`;
      if (e.isDirectory()) {
        if (PROJECT_WALK_EXCLUDE.has(e.name) || MANIFEST_WALK_EXCLUDE.has(e.name)) continue;
        if (ignores !== null && ignores(child, true)) continue;
        stack.push(child);
      } else if (e.isFile()) {
        const eco = ECOSYSTEM_MANIFESTS.find((m) => m.matches(e.name));
        if (eco === undefined) continue;
        if (ignores !== null && ignores(child, false)) continue;
        found.push({ rel: child, dir: rel, abs: join(abs, e.name), eco });
      }
    }
  }
  if (!rootRead) return null;
  if (unreadable.length > 0) {
    const shown = unreadable.slice(0, 3).join(', ');
    return { found, incomplete: `could not read ${shown}${unreadable.length > 3 ? ` and ${unreadable.length - 3} more` : ''}` };
  }
  return { found };
}

// ---------------------------------------------------------------- workspaces
//
// A workspace member has no lock file of its own: the workspace root's lock
// file locks it, and Trivy reports that one file (`package-lock.json`,
// `Cargo.lock`, `uv.lock`, measured on 0.69.3 for npm). So a member is
// covered by a Result of its ecosystem at an ancestor that DECLARES it a
// member — never by any ancestor's lock: a root lock file says nothing about
// a separate project below it that has none (the reproduction). Only what
// the root declares counts: npm / yarn `workspaces` (an array, or
// `{ packages: [...] }`), `pnpm-workspace.yaml` `packages`, Cargo
// `[workspace] members` / `exclude`, uv `[tool.uv.workspace] members` /
// `exclude`. Gradle and .NET lock per project, so no workspace applies.

/** A workspace glob, relative to its root: `*` one segment, `**` any depth. */
function workspaceGlob(pattern: string): RegExp | null {
  const p = pattern.trim().replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '');
  if (p === '' || p.startsWith('/') || p.split('/').includes('..')) return null;
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const c = p.charAt(i);
    if (c === '*') {
      if (p.charAt(i + 1) === '*') {
        re += '.*';
        i += 1;
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${re}$`);
}

interface WorkspaceDecl {
  include: string[];
  exclude: string[];
}

/** The quoted strings of a TOML array `key = [ … ]` inside `table` (possibly multi-line). */
function tomlArrayIn(text: string, table: string, key: string): string[] | null {
  const lines = text.split(/\r?\n/);
  let inTable = false;
  let collecting = false;
  let buf = '';
  for (const raw of lines) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!collecting && line.startsWith('[')) {
      const header = /^\[\s*([^\]]+?)\s*\]$/.exec(line);
      inTable = header?.[1]?.replace(/["'\s]/g, '') === table;
      continue;
    }
    if (!inTable) continue;
    if (!collecting) {
      const m = new RegExp(`^${key}\\s*=\\s*(\\[.*)$`).exec(line);
      if (m?.[1] === undefined) continue;
      collecting = true;
      buf = m[1];
    } else {
      buf += ` ${line}`;
    }
    if (buf.includes(']')) {
      const items = [...buf.matchAll(/"([^"]*)"|'([^']*)'/g)].map((x) => x[1] ?? x[2] ?? '');
      return items;
    }
  }
  return null;
}

function workspaceOf(rootAbs: string, ecosystem: string): WorkspaceDecl | null {
  const read = (name: string): string | null => {
    try {
      return readFileSync(join(rootAbs, name), 'utf8').replace(/^﻿/, '');
    } catch {
      return null;
    }
  };
  if (ecosystem === 'npm') {
    const include: string[] = [];
    const exclude: string[] = [];
    const add = (p: string): void => {
      if (p.startsWith('!')) exclude.push(p.slice(1));
      else include.push(p);
    };
    const manifest = readJsonFile(join(rootAbs, 'package.json'));
    if (typeof manifest === 'object' && manifest !== null && !Array.isArray(manifest)) {
      const ws = (manifest as Record<string, unknown>)['workspaces'];
      const list = Array.isArray(ws)
        ? ws
        : typeof ws === 'object' && ws !== null
          ? (ws as Record<string, unknown>)['packages']
          : undefined;
      if (Array.isArray(list)) for (const p of list) if (typeof p === 'string') add(p);
    }
    const pnpm = read('pnpm-workspace.yaml');
    if (pnpm !== null) {
      try {
        const doc = parseYaml(pnpm) as unknown;
        const pkgs = typeof doc === 'object' && doc !== null ? (doc as Record<string, unknown>)['packages'] : undefined;
        if (Array.isArray(pkgs)) for (const p of pkgs) if (typeof p === 'string') add(p);
      } catch {
        /* not a workspace we can read: no member */
      }
    }
    return include.length > 0 ? { include, exclude } : null;
  }
  if (ecosystem === 'cargo' || ecosystem === 'python') {
    const text = read(ecosystem === 'cargo' ? 'Cargo.toml' : 'pyproject.toml');
    if (text === null) return null;
    const table = ecosystem === 'cargo' ? 'workspace' : 'tool.uv.workspace';
    const include = tomlArrayIn(text, table, 'members');
    if (include === null || include.length === 0) return null;
    return { include, exclude: tomlArrayIn(text, table, 'exclude') ?? [] };
  }
  return null;
}

function declaredMember(decl: WorkspaceDecl, relFromRoot: string): boolean {
  const hit = (patterns: readonly string[]): boolean =>
    patterns.some((p) => workspaceGlob(p)?.test(relFromRoot) ?? false);
  return hit(decl.include) && !hit(decl.exclude);
}

/**
 * Assess whether Trivy's fs-scan output covers every dependency manifest in
 * the project (review I1). Every manifest the walk finds
 * ({@link walkManifests}) is judged in its own DIRECTORY: covered when a
 * Result of its ecosystem's Types has its `Target` in that directory, or in
 * an ancestor whose workspace declares it a member (see "workspaces"
 * above). Never by `Type` alone: a root `package-lock.json` said nothing
 * about a `web/package.json` that has no lock of its own, and that is the
 * gap this used to hide — Trivy 0.69.3 skips such a manifest in silence
 * (no `Results` key, exit 0), and the check used to read the root only.
 */
export function assessManifestCoverage(
  projectPath: string,
  rawTrivyOutput: unknown,
  opts: ManifestWalkOptions = {},
): ManifestCoverageAssessment {
  const walked = walkManifests(projectPath, opts);
  if (walked === null) return { gaps: [], sawAnyResults: false };

  const root = parseInputAsJson(rawTrivyOutput);
  const results = asArray(getProp(root, 'Results'));
  /** Type → the directories its Results name. */
  const dirsByType = new Map<string, Set<string>>();
  for (const result of results) {
    const type = getString(result, 'Type');
    const target = getString(result, 'Target');
    if (type === undefined || target === undefined) continue;
    const set = dirsByType.get(type) ?? new Set<string>();
    set.add(dirOf(target));
    dirsByType.set(type, set);
  }
  const resultDirs = (eco: EcosystemManifest): Set<string> => {
    const out = new Set<string>();
    for (const t of eco.trivyTypes) for (const d of dirsByType.get(t) ?? []) out.add(d);
    return out;
  };

  const covered = (eco: EcosystemManifest, dir: string, dirs: Set<string>): boolean => {
    if (dirs.has(dir)) return true;
    // Ancestors, nearest first: a workspace root with a Result that declares this directory.
    const segments = dir === '' ? [] : dir.split('/');
    for (let n = segments.length - 1; n >= 0; n--) {
      const ancestor = segments.slice(0, n).join('/');
      if (!dirs.has(ancestor)) continue;
      const decl = workspaceOf(ancestor === '' ? projectPath : join(projectPath, ...ancestor.split('/')), eco.ecosystem);
      if (decl !== null && declaredMember(decl, segments.slice(n).join('/'))) return true;
    }
    return false;
  };

  const gapFiles = new Map<string, string[]>();
  const dirsOf = new Map<string, Set<string>>();
  for (const m of walked.found) {
    if (m.eco.declaresNothing?.(m.abs) ?? false) continue;
    let dirs = dirsOf.get(m.eco.ecosystem);
    if (dirs === undefined) {
      dirs = resultDirs(m.eco);
      dirsOf.set(m.eco.ecosystem, dirs);
    }
    if (covered(m.eco, m.dir, dirs)) continue;
    gapFiles.set(m.eco.ecosystem, [...(gapFiles.get(m.eco.ecosystem) ?? []), m.rel]);
  }

  const gaps: ManifestCoverageGap[] = [];
  for (const eco of ECOSYSTEM_MANIFESTS) {
    const files = gapFiles.get(eco.ecosystem);
    if (files !== undefined) gaps.push({ ecosystem: eco.ecosystem, files: [...files].sort() });
  }
  const out: ManifestCoverageAssessment = { gaps, sawAnyResults: results.length > 0 };
  if (walked.incomplete !== undefined) out.walkIncomplete = walked.incomplete;
  return out;
}
