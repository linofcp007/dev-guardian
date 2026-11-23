/**
 * The PreToolUse hook's decision for one Bash/PowerShell command: deny,
 * warn, note, or stay silent. Kept here (bundled into `mcp/dist/hooks.js`)
 * rather than in `hooks/guardian-hook.mjs` so it is unit-testable; the hook
 * itself only calls it and emits the answer.
 *
 *   - **deny** a malicious package, always; and a package the public
 *     registry does not have ONLY when the whole command, comments
 *     stripped, is ONE plain install statement with allowlisted flags
 *     (controller ruling, round 2 — `confidentShape` in `parseCommand.ts`;
 *     `InstallCommand.uncertain` is empty then, bar the reasons the confident-shape
 *     filter keeps: a name that ends like an archive, whose manager was not measured
 *     or in a form it was not measured in, and the two readings of a `key@npm:rest`) AND no custom
 *     registry, npmjs auth token (scoped names) or local workspace package
 *     explains the 404 (`privateRegistry.ts`). Blocking a missing name buys
 *     little — the install would 404 anyway — and a false deny blocks real
 *     work. That deny carries an escape hatch ({@link escapeHatch}, named per
 *     tool and shell); a malicious one does not;
 *   - **warn** (additionalContext) on a missing name that was not denied
 *     ("not found on the public registry — if it is private or local,
 *     ignore this"), a version < 72 h old, install scripts, typosquat
 *     suspicion, an unpublished exact version, and known vulnerabilities
 *     only on an EXACT pin (for a range the installed version is unknown);
 *   - **note** — one line — for anything that could not be vetted (offline,
 *     timeout, HTTP error, rate limit). The command runs; the note says it
 *     was NOT verified, never that it was;
 *   - **silent** when every package came back `ok`, and for every command
 *     that installs nothing — which never touches the network.
 *
 * **A manifest install** — `npm install`, `npm ci`, `pnpm install`, `yarn`,
 * `bun install`, `pip install -r`, and an install that names a package inside
 * a project (`npm install <pkg>`, `pnpm add`, `yarn add`, `bun add`: the
 * manager installs the manifest beside the names; not `-g`, not a launcher of another package — a launcher that runs a
 * package manager, `npx pnpm add <pkg>`, reads it as that manager does, as a command of its own in the list) —
 * reads a manifest, the nearest `package.json` from where the command runs up
 * to the project or repository root. Its direct dependencies (`manifest.ts`)
 * join the same lookups, under the same cap and budget, and answer by a rule
 * of their own ({@link decideManifestOne}), because a manifest is installed
 * again and again and a missing name in one is usually a private package:
 *
 *   - **deny** a malicious package, naming the file — nothing else denies;
 *   - **warn** on a typosquat suspicion and on a name the public registry
 *     does not have (never a deny);
 *   - nothing about a fresh version, install scripts or known
 *     vulnerabilities, which would be repeated at every install;
 *   - **one line** for what was not verified, with the count and the file,
 *     and one for a manifest that is there and was not read. A manifest that
 *     is not there is silence: the install has nothing to read either.
 *
 * A scoped name whose scope has a registry of its own is not sent to the
 * public one (`npmScopeRegistry`): in silence when the user's configuration
 * says so, in one line when a file of the project does — a project file may
 * not take a check away unseen.
 *
 * **The lockfile** of an npm-family manifest install (`lockfile.ts`) is what
 * the package manager installs, and the hook asks OSV about every pair it pins
 * (`pins.ts`), at the exact version, beside the registry path of the manifest's
 * own dependencies and under the same budget and deadline. Only a `MAL-`
 * advisory denies — with the manifest's sentence, naming the lockfile.
 * Everything not read, not recognised, not asked or not answered is counted and
 * said in one line, never given as verified. A direct dependency the lockfile
 * records at the manifest's range, with a pinned version, is not asked of the
 * registry (the manager does not resolve it again): its typosquat check stays.
 *
 * Only validated text reaches the answer: the lockfile's file name, package
 * names and exact versions, a host `lockfile.ts` validated.
 *
 * All network work shares one budget ({@link HOOK_BUDGET_MS}, 3 s): the
 * install commands of a compound line are vetted in parallel under it.
 */

import { lstatSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { isNetworkPath, readSmallText, walkLinksUnder } from '../hooks/configFile.js';
import { diskSpelling, diskStep, homeBarrier, rootBarred, systemDisk, type SpellingMemo } from './folderSpelling.js';
import { LOCKFILES, lockFormat, readLock, type LockRead, type Pin, type Source } from './lockfile.js';
import { label as manifestLabel, readInlineScript, readNpmManifest, readRequirements, UNKNOWN_DIRECTORY, type ManifestRead } from './manifest.js';
import { MAX_CANDIDATES_PER_COMMAND, parseInstallCommands, type CommandShell, type InstallCommand } from './parseCommand.js';
import { choosePins, MAX_PINS, vetPins, type PinVerdict } from './pins.js';
import { loadPopularIndex } from './popular.js';
import {
  gitRepositoryRoot,
  npmEnvNamesDefaultRegistry,
  npmProjectDefaultRegistry,
  npmScopeRegistryOf,
  npmUserRegistries,
  registryCache,
  type RegistryCommand,
  type RegistryContext,
} from './privateRegistry.js';
import { buildPopularIndex, normalizePackageName, type PopularIndex } from './typosquat.js';
import type { PackageChecks, PackageSpec, PackageVetResult, PkgEcosystem } from './types.js';
import { HOOK_BUDGET_MS, registryHost, vetPackages, vetTyposquatOnly } from './vet.js';
import { isExactVersion } from './versions.js';

/** The part of `fs.Stats` the decision reads: `lstat` of a word of `dotnet new install`, which a test replaces. */
export type LstatLike = (path: string) => { isDirectory(): boolean; isFile(): boolean; isSymbolicLink(): boolean };

export interface HookVetOptions {
  /** The project directory (the hook payload's `cwd`). */
  cwd: string;
  /**
   * The hook's project root. A manifest install's lockfile is looked for in the
   * directory the command runs in and, when there is none, in the nearest
   * directory above it up to this one — never beyond. Without it, or with the
   * command's directory outside it, only the command's own directory is read.
   */
  projectDir?: string;
  homeDir?: string;
  env?: Readonly<Record<string, string | undefined>>;
  fetchImpl?: typeof fetch;
  /** How an entry of the command's folder is looked up (`dotnet new install`): by default `lstatSync`, which follows no link. */
  lstatImpl?: LstatLike;
  /**
   * How a folder's spelling is asked of the disk (`install-vet-path-forms`): by default `lstatSync` and `realpathSync.native`; a test gives
   * counting ones. Beside `lstatImpl`, which is the disk of `dotnet new install` and which this does not replace.
   */
  diskImpl?: { lstat: LstatLike; realpath: (p: string) => string };
  budgetMs?: number;
  now?: number;
  /** `configs/popular-packages`, located by the hook from the plugin root. */
  popularDir?: string;
  /** Test override of the lists. */
  popular?: Partial<Record<PkgEcosystem, readonly string[] | null>>;
  /** Registry-context overrides for tests (see `RegistryContext`). */
  etcDir?: string;
  platform?: NodeJS.Platform;
  nodeExecPath?: string;
  systemLibraryDir?: string;
  /**
   * The shell that will run the command — the hook's `tool_name`. The
   * PowerShell tool's commands are also read the way PowerShell reads them
   * (`parseInstallCommands`), and its escape hatch is spelled for it.
   */
  shell?: CommandShell;
  /**
   * The scripts the command hands a shell, as the shell guard read them
   * (`BashAssessment.scripts`): their installs are vetted too
   * (`parseInstallCommands`'s `nested`).
   */
  nested?: ReadonlyArray<{ text: string; shell: CommandShell }>;
  /** When the hook call started (epoch ms); the deadline counts from here. Default: now. */
  startedAt?: number;
  /** The deadline itself (epoch ms), overriding `startedAt` + {@link vetDeadlineMs} (tests). */
  deadlineAt?: number;
}

/** The vetting deadline's default: well under Claude Code's 15 s hook timeout. */
export const DEFAULT_DEADLINE_MS = 8000;
/**
 * The most `GUARDIAN_PKG_VET_DEADLINE_MS` may raise it to: past the hook's
 * 15 s, the command runs with no verdict. It leaves room for what follows the
 * deadline (review 8, item 4) — the answer's write, the hook's 250 ms exit
 * grace for a connect still pending, and the process's own exit — with a
 * margin for a loaded machine: 14 s plus the old 5 s backstop could lose a deny.
 */
export const MAX_DEADLINE_MS = 12_000;

/**
 * The one deadline on a hook call's vetting (review I4), in ms from the start
 * of the call: `GUARDIAN_PKG_VET_DEADLINE_MS` (3000-12000), else 8000. Local
 * work — reading registry configuration, walking a workspace — used to run
 * unbounded before the 3 s network budget: 17 packages in a 3000-directory
 * monorepo took 16.5 s, and Claude Code kills a hook at 15 s. Never below the
 * network budget ({@link HOOK_BUDGET_MS}): `1` left no time to look a package
 * up, and the deny of a malicious one became a "not verified" note (review of
 * 3.4.0, finding 4).
 */
export function vetDeadlineMs(env: Readonly<Record<string, string | undefined>>): number {
  const raw = env['GUARDIAN_PKG_VET_DEADLINE_MS']?.trim();
  if (raw === undefined || !/^\d+$/.test(raw)) return DEFAULT_DEADLINE_MS;
  return Math.min(Math.max(Number(raw), HOOK_BUDGET_MS), MAX_DEADLINE_MS);
}

export interface HookDecision {
  /** Set only when the command must be denied. */
  deny?: string;
  /** Warnings and notes for the model, when there is anything to say. */
  context?: string;
  /**
   * The reason of a question to the user, without the `dev-guardian: ` prefix and the final full stop (the
   * dispatcher adds them): a ceiling was passed or the command was cut, so some packages were not vetted. Never set
   * with `deny`; it does not depend on the network or the deadline.
   */
  ask?: string;
}

function label(r: PackageVetResult): string {
  return r.version !== undefined ? `${r.name}@${r.version}` : r.name;
}

function firstLine(r: PackageVetResult): string {
  return r.reasons[0] ?? 'no reason recorded';
}

/** The most packages NAMED ON THE COMMAND LINE one hook call looks up; the rest are named as not vetted. */
export const MAX_VETTED_PACKAGES = MAX_CANDIDATES_PER_COMMAND;
/**
 * The most packages of MANIFESTS one hook call looks up, beside those the
 * command names. Nobody types fifty names, but real applications declare more
 * direct dependencies than that: of 16 manifests measured (2026-11-15: 15
 * open-source LLM applications and this repository's), 11 had from 57 to 97,
 * and under a cap of 50 each of their installs would have said "N more
 * packages were not vetted". The lookups run in parallel under one budget,
 * so the wider cap cost nothing measurable — 0.9 to 3.5 s over the 16, against
 * 0.9 to 3.3 s — and all 16 were vetted whole, in silence.
 */
export const MAX_MANIFEST_PACKAGES = 150;
/**
 * The two checks {@link decideManifestOne} never reads: said once at `npm
 * install <name>`, they would be said at every install of a manifest. Named
 * to the vetting so that it does not fetch for them either — the full
 * registry document and the version document were half of what a manifest
 * install read (3.10.0, measured), and in two of 15 real manifests ran into
 * the 3 s budget.
 */
const MANIFEST_UNREPORTED: ReadonlySet<'publish_age' | 'install_scripts'> = new Set(['publish_age', 'install_scripts'] as const);
/** How much of a command is read for installs — the shell guard reads the same 512 KB. */
const MAX_PARSED_LENGTH = 512 * 1024;

/**
 * The install commands to vet, bounded (fix round 2): every package that
 * repeats one already seen (same ecosystem, name and range) is dropped, and
 * past {@link MAX_VETTED_PACKAGES} the rest are counted, not looked up — 60 KB
 * of `npm i x; ` once took ~57 s through the hook, past its 15 s timeout. A
 * command over 512 KB is read from its start only, and then no command may be
 * denied for a missing name: its last word may have been cut in half.
 *
 * The packages a manifest names have a cap of their own,
 * {@link MAX_MANIFEST_PACKAGES}, counted apart: a package the command names
 * and the manifest repeats is the command's.
 */
function boundedInstalls(
  command: string,
  shell: CommandShell,
  isPopular: (pkg: PackageSpec) => boolean,
  runsLocally: (pkg: PackageSpec, c: InstallCommand) => boolean,
  nested: ReadonlyArray<{ text: string; shell: CommandShell }> = [],
  cdpath = false,
  withManifests: (parsed: readonly InstallCommand[]) => VetCommand[] = (parsed) => [...parsed],
  pastDeadline: () => boolean = () => false,
  onDisk: (c: InstallCommand) => InstallCommand = (c) => c,
  noCopyLookup: (pkg: PackageSpec, c: InstallCommand) => boolean = () => false,
): { commands: VetCommand[]; notVetted: number; manifestNotVetted: number; cut: boolean; unassessed: number } {
  const cut = command.length > MAX_PARSED_LENGTH;
  // The safety net of the budget (review round 2): past the deadline a launcher is no longer asked whether the project
  // has a copy of its package — its packages go to the vetting as if fetched, which says "time budget" when it cannot
  // look them up either. More is vetted, never less; `unassessed` is said.
  let unassessed = 0;
  const parsed = withManifests(
    parseInstallCommands(cut ? command.slice(0, MAX_PARSED_LENGTH) : command, { shell, nested, cdpath }).map((c) => {
      // `dotnet new install` reads a word as a path when an entry of that name is in the command's folder: it fetches nothing then.
      if (c.localPathFirst === true) return onDisk(c);
      // `npx`, `npm exec` and `bunx` run a bin the project has installed, and
      // fetch nothing: there is nothing to vet (review P1).
      if (c.localFirst !== true) return c;
      // Where no installed copy is looked for, a missing name is told why it is not denied.
      // Only when every name is one whose copy would have been looked for: a version, an alias or `--prefix` never was (EC-4).
      const noCopy = c.packages.length > 0 && c.packages.every((p) => noCopyLookup(p, c));
      const withWhy = noCopy ? { ...c, uncertain: [...c.uncertain, NETWORK_COPY_REASON] } : c;
      if (pastDeadline()) {
        unassessed += 1;
        return withWhy;
      }
      return { ...withWhy, packages: c.packages.filter((p) => !runsLocally(p, c)) };
    }),
  );
  const key = (pkg: PackageSpec): string => `${pkg.ecosystem}\0${pkg.name.toLowerCase()}\0${pkg.range ?? ''}`;
  const seen = new Set<string>();
  const named: PackageSpec[] = [];
  const ofManifests: PackageSpec[] = [];
  // A name is certain when some occurrence of it is not only a candidate (the word after a flag the parse does not know).
  const certainKeys = new Set<string>();
  for (const c of parsed) {
    const candidates = new Set(c.candidates);
    for (const pkg of c.packages) {
      if (c.fromManifest === undefined && !candidates.has(pkg)) certainKeys.add(key(pkg));
      if (seen.has(key(pkg))) continue;
      seen.add(key(pkg));
      (c.fromManifest === undefined ? named : ofManifests).push(pkg);
    }
  }
  // The names NOT on the popular list first (fix round 3): 50 popular names
  // in front of a malicious one must not push it past the cap.
  const firstOf = (unique: readonly PackageSpec[], cap: number): string[] =>
    [...unique.filter((p) => !isPopular(p)), ...unique.filter(isPopular)].slice(0, cap).map(key);
  // Under the ceiling the packages the command surely names come first; the candidates take what is left, in line order.
  const certain = firstOf(
    named.filter((p) => certainKeys.has(key(p))),
    MAX_VETTED_PACKAGES,
  );
  const candidateKeys = named.filter((p) => !certainKeys.has(key(p))).map(key).slice(0, MAX_VETTED_PACKAGES - certain.length);
  const chosen = new Set([...certain, ...candidateKeys, ...firstOf(ofManifests, MAX_MANIFEST_PACKAGES)]);
  // Each name goes to ONE command of the line. A name that an update and an install both give is the install's, wherever
  // each stands: an update says less of it (no fresh version, no install scripts, its own reason for a missing name), and
  // `npm update -g x; npm install x` must not take the install's answer away. So the other commands choose first.
  const taken = new Map<VetCommand, PackageSpec[]>();
  for (const updates of [false, true]) {
    for (const c of parsed) {
      if ((c.fromUpdate === true) === updates) taken.set(c, c.packages.filter((pkg) => chosen.delete(key(pkg))));
    }
  }
  const commands: VetCommand[] = [];
  for (const c of parsed) {
    const packages = taken.get(c) ?? [];
    if (packages.length === 0) continue;
    const uncertain = cut ? [...c.uncertain, 'the command is over 512 KB and only its start was read'] : c.uncertain;
    commands.push({ ...c, packages, uncertain });
  }
  return {
    commands,
    // The candidates the parse left out past its own ceiling count as packages not vetted.
    notVetted: Math.max(0, named.length - MAX_VETTED_PACKAGES) + parsed.reduce((n, c) => n + (c.candidatesDropped ?? 0), 0),
    manifestNotVetted: Math.max(0, ofManifests.length - MAX_MANIFEST_PACKAGES),
    cut,
    unassessed,
  };
}

/**
 * An install command as it is vetted: the packages a manifest names carry the file that names them, and the names an update
 * verb is given ({@link InstallCommand.updateNames}) are marked `fromUpdate`; the words `pipx run` takes as the name of a local file
 * are looked up for malware only (`fromLocalScript`), and so are the words the pipx reads as a file whether or not one is there
 * (`fromArchiveFile`: {@link archiveFileCommand}).
 */
type VetCommand = InstallCommand & { fromManifest?: string; fromUpdate?: true; fromLocalScript?: true; fromArchiveFile?: true };

/** The line said in place of the project's registry files, which are not read in a folder on the network. */
const REGISTRY_FILES_NOT_READ =
  "dev-guardian: the project's registry settings were not read (on a network path) — if they set the default registry, what it serves was not vetted.";
/** Why a missing name of `npx`, `bunx` or `npm exec` is not denied in a folder on the network: the installed copy that would explain it was not looked for. */
const NETWORK_COPY_REASON = 'it runs in a folder on a network path, where an installed copy was not looked for';
/** Why the name given to an update is never denied as missing (measured 2026-11-20: an update fetches only what is installed already). */
const NAMED_TO_UPDATE = 'not denied: a package named to an update is fetched only when it is already installed';

/** Said for a global update that names nothing: the managers update every globally installed package (measured 2026-11-20). */
const UPDATES_EVERY_GLOBAL = 'dev-guardian: this command updates every globally installed package — none of them was vetted.';

/** Said for `pipx upgrade-all` and `uv tool upgrade --all`: every tool the manager installed is updated, and none is on the command line. */
const UPDATES_EVERY_TOOL = 'dev-guardian: this command updates every tool pipx or uv installed — none of them was vetted.';

/**
 * The names an update verb is given, as one more command to vet (`fromUpdate`): those that no manifest read for the command
 * has, and those with a version or a range (the manifest's own check is not that version); all of them when no manifest was
 * read. `undefined` when there is nothing to vet.
 */
function updateCommand(c: InstallCommand, inManifest: ReadonlySet<string>): VetCommand | undefined {
  const packages = (c.updateNames ?? []).filter((n) => n.range !== undefined || !inManifest.has(n.name));
  if (packages.length === 0) return undefined;
  const { manifest: _manifest, update: _update, updateNames: _names, ...rest } = c;
  return { ...rest, packages, skipped: [], fromUpdate: true };
}

/** Why a package a manifest names is never denied as missing. */
const NAMED_BY_MANIFEST = 'it is named by a manifest, where a missing name is usually a private or a workspace package';

const plural = (n: number): string => (n === 1 ? '1 package' : `${String(n)} packages`);

/**
 * The most "not found on the public registry" warnings of manifests ONE ANSWER lists; the rest are counted in one
 * line ({@link missingCountLine}). A project whose private packages have no scope configured gets one such warning a
 * dependency at every install — 150 of them were 151 lines and 33 000 characters. Per answer, not per file, so the
 * size has a known maximum whatever the line installs. A missing name that comes with a "Did you mean" is never
 * counted: that one is the sign of a mistyped dependency.
 */
const MAX_MANIFEST_MISSING_LINES = 5;
/** The most manifest files the count line names; the others are counted too. */
const MAX_COUNTED_FILES = 3;

/**
 * The one line for the missing names of manifests past {@link MAX_MANIFEST_MISSING_LINES}: how many, and of which
 * files (as the warnings call them). They were asked of the registry and of the malware check like the listed ones —
 * only their lines are left out.
 */
function missingCountLine(counted: ReadonlyMap<string, number>): string {
  const files = [...counted.keys()];
  const total = [...counted.values()].reduce((sum, n) => sum + n, 0);
  const shown = files.slice(0, MAX_COUNTED_FILES);
  const rest = files.length - shown.length;
  const named =
    rest > 0
      ? `${shown.join(', ')} and ${String(rest)} more file${rest === 1 ? '' : 's'}`
      : shown.length > 1
        ? `${shown.slice(0, -1).join(', ')} and ${shown[shown.length - 1] ?? ''}`
        : (shown[0] ?? '');
  return (
    `dev-guardian: ${String(total)} more package${total === 1 ? '' : 's'} of ${named} ${total === 1 ? 'is' : 'are'} ` +
    'not on the public registry either (in a manifest that is usually a private or a workspace package) — not listed.'
  );
}

/**
 * The commands to vet, with what each manifest install reads beside what it
 * names: one more command per manifest, holding the packages the file names
 * (`fromManifest`), after the command itself. `notes` gets a line for every
 * manifest that is there and was not read, and for the packages a project
 * file keeps from the lookup.
 *
 * A manifest is read for a command the parser marked as installing one: a
 * bare install, and a by-name install that is not global for certain (the
 * manager installs the `package.json` beside the names). A package.json is the
 * nearest one from where the command runs ({@link commandDir}) up to the project
 * root ({@link readNearestManifest}); a directory flag (`--prefix`, `-C`,
 * `--dir`, `--cwd`) or a `cd` that may not have run leaves that unknown, and
 * the manifest unread — said, not guessed.
 */
function withManifestPackages(
  parsed: readonly InstallCommand[],
  opts: HookVetOptions,
  registry: RegistryContext,
  notes: string[],
  locked: LockedProject[],
  scriptOut: { asks: string[]; withDeny: string[] },
  pastDeadline: () => boolean,
  memo: SpellingMemo,
): VetCommand[] {
  const out: VetCommand[] = [];
  // The root a manifest or a lockfile is looked for up to: the project directory, or the root of the git repository it is in.
  // A project directory on the network is never asked for a `.git`: each lstat of a share that stopped answering costs the SMB timeout,
  // and the deadline would be gone before the first request (install-vet-network-project-dir-probe). The limit is then `projectDir` itself.
  const top = opts.projectDir === undefined || isNetworkPath(opts.projectDir) ? undefined : gitRepositoryRoot({ ...registry, projectDir: opts.projectDir });
  const lineAsked = new Map<string, string[]>();
  const world: ScriptWorld = {
    opts,
    // The root the links of a script are walked from: the repository root, else the project directory the hook was given.
    top: top ?? opts.projectDir,
    pastDeadline,
    notes,
    asks: scriptOut.asks,
    withDeny: scriptOut.withDeny,
    folders: new Map<string, Folder>(),
    probes: new Map<string, Probe>(),
    reads: new Map<string, ManifestRead>(),
    overflow: new Set<string>(),
    asked: new Set<string>(),
  };
  let userRegistries: string[] | undefined;
  const user = (): readonly string[] => (userRegistries ??= npmUserRegistries(registry));
  for (const c of parsed) {
    // The scripts the command runs come first: a `pipx run` word that is a local file leaves its packages, and says so.
    const scripted = scriptCommands(c, world);
    out.push(...archiveFileCommand(scripted.command), ...scripted.extra);
    // The names of an update are vetted whatever happens to the manifest below: every early `continue` comes after this.
    const pushUpdate = (inManifest: ReadonlySet<string>): void => {
      const more = updateCommand(c, inManifest);
      if (more !== undefined) out.push(more);
    };
    if (c.global === true && c.updateNames?.length === 0 && c.skipped.length === 0) notes.push(UPDATES_EVERY_GLOBAL);
    // `pipx upgrade-all` and `uv tool upgrade --all` (also with names beside `--all`): said before any request is made.
    if (c.updatesEveryTool === true) notes.push(UPDATES_EVERY_TOOL);
    // A line of thousands of commands asks once per manager and directory: the answer is the same.
    const key = `${c.manager}\u0000${JSON.stringify(c.workdir)}\u0000${String(c.prefixed)}\u0000${String(c.registries.length > 0)}\u0000${String(c.global === true)}\u0000${String(c.envFileFlag === true)}\u0000${String(c.bunLauncher === true)}`;
    if (!lineAsked.has(key)) lineAsked.set(key, projectDefaultRegistryLines(c, opts, registry, user, memo));
    notes.push(...(lineAsked.get(key) ?? []));
    const manifest = c.manifest;
    if (manifest === undefined) {
      pushUpdate(new Set());
      continue;
    }
    // `uv run --directory D --with-requirements F`, and the same after a `cd`: the file is looked for where the uv runs, in every
    // folder it may be (`tools/..` after a link is two), the way the scripts of the command are. Any other file stays where `commandDir` says.
    const uvRequirements = c.manager === 'uv' && manifest.kind === 'requirements';
    const moved =
      c.scriptDir !== undefined || c.scriptDirUnknown === true || (uvRequirements && c.workdir !== undefined)
        ? pastDeadline()
          ? ({ kind: 'deadline' } as const)
          : folderOf(c, world)
        : undefined;
    let dirs: string[] = [];
    let unread: string = UNKNOWN_DIRECTORY;
    if (c.prefixed !== true) {
      if (moved === undefined) {
        const here = commandDir(c, opts, memo);
        if (here !== null) dirs = [here];
      } else if (moved.kind === 'dirs') dirs = moved.dirs;
      else if (moved.kind === 'refused') unread = moved.reason;
      else if (moved.kind === 'deadline') unread = DEADLINE_REASON;
    }
    const dir = dirs[0];
    if (dir === undefined) {
      const what = manifest.kind === 'package-json' ? 'package.json' : 'the requirements file';
      notes.push(`dev-guardian: ${what} was not read (${unread}) — its packages were not vetted.`);
      pushUpdate(new Set());
      continue;
    }
    let reads: ManifestRead[];
    // Where the project is: the directory of the manifest the manager installs — the nearest above the command's — and,
    // for a requirements file (its path is on the command line), the command's own.
    let base = dir;
    try {
      if (manifest.kind === 'package-json') {
        const nearest = readNearestManifest(c.manager, dir, opts.projectDir, top, opts, memo);
        base = nearest.dir;
        reads = [nearest.read];
      } else {
        reads = readRequirements(moved === undefined ? dir : dirs, manifest.files, c.manager, pastDeadline);
      }
    } catch {
      // Fail-open, and said: nothing of the manifest was vetted.
      notes.push('dev-guardian: the manifest was not read (could not be read) — its packages were not vetted.');
      pushUpdate(new Set());
      continue;
    }
    // The file as the message names it: as written, and from the session's folder when it was read in more than one.
    const fileOf = (read: ManifestRead): string =>
      dirs.length > 1 && read.dir !== undefined ? manifestLabel(relative(resolve(opts.cwd), resolve(read.dir, read.file)).split(sep).join('/')) : read.file;
    pushUpdate(new Set(reads.flatMap((r) => (r.status === 'ok' ? r.names : []))));
    for (const read of reads) {
      if (read.status === 'absent') continue;
      // The lockfile is what the manager installs, whether or not the manifest could be read.
      const lock = c.ecosystem === 'npm' && manifest.kind === 'package-json' ? lockedProject(c, base, read, opts, top, registry, notes, memo) : undefined;
      if (lock !== undefined) locked.push(lock);
      if (read.status === 'unreadable') {
        notes.push(`dev-guardian: ${fileOf(read)} was not read (${read.reason ?? 'could not be read'}) — its packages were not vetted.`);
        continue;
      }
      if (read.incomplete !== undefined) {
        notes.push(`dev-guardian: a file ${fileOf(read)} includes was not read (${read.incomplete}) — its packages were not vetted.`);
      }
      const inScope = c.ecosystem === 'npm' ? withoutOwnRegistryScopes(read, { ...registry, projectDir: base, command: registryCommand(c) }, notes) : read.packages;
      // A direct dependency the lockfile records for this project leaves the registry path: its typosquat check stays.
      // Not for an update verb: it moves them past the pins, so every direct dependency is vetted by name (the pins still go to OSV).
      const packages = lock === undefined || c.update === true ? inScope : withoutCovered(inScope, lock);
      if (packages.length === 0) continue;
      const registries = [...c.registries, ...read.registries];
      const custom = c.customRegistry ?? read.registries[0];
      out.push({
        ...c,
        packages,
        skipped: [],
        uncertain: [NAMED_BY_MANIFEST],
        registries,
        ...(custom !== undefined ? { customRegistry: custom } : {}),
        fromManifest: fileOf(read),
      });
    }
  }
  overflowScripts(world);
  return out;
}

/**
 * What the lookups of the registry files need to know of a command: its manager, the form it was written in when it is one of the
 * measured eight, whether it is global for certain, and the two things that stop the bun reading its `.env` files. Without it a lookup
 * reads every file as it did before the commands were told apart.
 */
function registryCommand(c: InstallCommand): RegistryCommand {
  return {
    manager: c.manager,
    registryForm: c.registryForm,
    global: c.global === true,
    envFileFlag: c.envFileFlag === true,
    bunLauncher: c.bunLauncher === true,
  };
}

/** Whether a note is one of the lines of {@link projectDefaultRegistryLines}: a file of the project sets the default registry. */
function isDefaultRegistryLine(note: string): boolean {
  return (
    /^dev-guardian: the project's \S+ sets the default registry(?: \([^)]*\))? — /.test(note) ||
    /^dev-guardian: \d+ more files? of the project sets? the default registry\.$/.test(note) ||
    note === REGISTRY_FILES_NOT_READ
  );
}

/** The most lines said for the project files that set the default registry: the rest is counted. */
const MAX_REGISTRY_LINES = 3;

/**
 * The lines for a command whose project sets the default registry ({@link npmProjectDefaultRegistry}): one per file
 * that gives a registry which is not one of the USER's, nearest first — the file by its base name and the registry by
 * `scheme://host` ({@link registryHost}), nothing else of either — at most {@link MAX_REGISTRY_LINES}, and a last line
 * that counts the files left out. The managers do not agree on which file wins, so each is said. `[]` (no line) when
 * the command line or the environment names a registry (the manager obeys those first), for a global install (the
 * manager does not obey the project's file), when the command's directory is not known, when every registry is one the
 * user's own configuration names (a file of the project never silences a line), and on any error. The notes are
 * de-duplicated per call, so a line is said once.
 */
function projectDefaultRegistryLines(
  c: InstallCommand,
  opts: HookVetOptions,
  registry: RegistryContext,
  userRegistries: () => readonly string[],
  memo: SpellingMemo,
): string[] {
  try {
    if (c.ecosystem !== 'npm' || c.registries.length > 0 || c.prefixed === true || c.global === true || npmEnvNamesDefaultRegistry(registry)) return [];
    const dir = commandDir(c, opts, memo);
    if (dir === null) return [];
    // The project's registry files are not read on the network (same cost as above): the line says so instead of staying silent.
    if (isNetworkPath(dir)) return [REGISTRY_FILES_NOT_READ];
    const found = npmProjectDefaultRegistry(c.manager, { ...registry, projectDir: dir, command: registryCommand(c) }).filter((f) => !fromUserRegistry(f.url, userRegistries()));
    const lines = found.slice(0, MAX_REGISTRY_LINES).map((f) => {
      const host = registryHost('npm', f.url);
      return `dev-guardian: the project's ${basename(f.source)} sets the default registry${host === undefined ? '' : ` (${host})`} — packages are fetched from it, and what it serves was not vetted.`;
    });
    const rest = found.length - lines.length;
    if (rest > 0) lines.push(rest === 1 ? 'dev-guardian: 1 more file of the project sets the default registry.' : `dev-guardian: ${rest} more files of the project set the default registry.`);
    return lines;
  } catch {
    return []; // fail-open: no line
  }
}

/**
 * A manifest's packages less those of a scope with a registry of its own
 * ({@link npmScopeRegistry}): the package manager fetches them there and never
 * asks the public registry, so their names are not sent to it. When the
 * user's configuration says so, nothing is said. When a file of the PROJECT
 * does, one line says how many were not vetted: a project file may only make
 * the hooks stricter, never take a check away unseen.
 */
function withoutOwnRegistryScopes(read: ManifestRead, registry: RegistryContext, notes: string[]): PackageSpec[] {
  const kept: PackageSpec[] = [];
  const scopeRegistry = npmScopeRegistryOf(registry);
  const byProject = new Set<string>();
  let held = 0;
  let source = '';
  for (const pkg of read.packages) {
    const own = pkg.name.startsWith('@') ? scopeRegistry(pkg.name) : null;
    if (own === null) {
      kept.push(pkg);
      continue;
    }
    if (own.from !== 'project') continue;
    held += 1;
    byProject.add(`@${own.scope}`);
    if (source === '') source = basename(own.source);
  }
  if (held > 0) notes.push(ownScopeLine(held, read.file, byProject, source));
  return kept;
}

/** The line for packages of a scope a file of the project gives a registry of its own: counted and said, never dropped unseen. */
function ownScopeLine(held: number, file: string, scopes: ReadonlySet<string>, source: string): string {
  // Three scopes are named, the rest counted: a hostile lockfile may hold hundreds.
  const named = [...scopes].slice(0, MAX_NAMED_HOSTS).join(', ');
  const more = scopes.size > MAX_NAMED_HOSTS ? ` and ${scopes.size - MAX_NAMED_HOSTS} more` : '';
  return `dev-guardian: ${plural(held)} of ${file} ${held === 1 ? 'is' : 'are'} in a scope (${named}${more}) the project's ${source} gives a registry of its own — not vetted.`;
}

// ───────────────────────────────────────────────────────────────────── lockfiles

/** The largest lockfile read: the biggest real one measured is a few MiB, and a hostile one is not given more. */
const MAX_LOCKFILE_BYTES = 16 * 1024 * 1024;
/** The most distinct hosts a line names. */
const MAX_NAMED_HOSTS = 3;
/** The most advisory ids named for one pair, and the most pairs a deny names: the deny is read by the model, and a lockfile can hold thousands of malicious pairs. */
const MAX_NAMED_IDS = 5;
const MAX_NAMED_DENIES = 20;
/** The most of a reason repeated in a line. */
const MAX_REASON_LENGTH = 120;

/** A lockfile read for one manifest install, with what was decided of it before the network. */
interface LockedProject {
  /** The lockfile's file name: the only part of its path an answer repeats. */
  file: string;
  /** The manifest that names the project's own dependencies, as the command names it. */
  manifestFile: string;
  read: LockRead;
  /** The command's directory relative to the lockfile's, with `/` — what `resolutionOf` is asked about. */
  rel: string;
  /** The names the manifest declares: their pairs are asked first. */
  direct: string[];
  /** The direct dependencies the lockfile records for this project: the typosquat check alone. */
  covered: PackageSpec[];
  /** The pairs to ask OSV about, each once, in file order — the scope rule applied. */
  asked: Pin[];
}

const pairKey = (p: Pin): string => `${p.name}@${p.version}`;

/** Text that may stand in a line: no control character, no line break, bounded. */
function said(text: string): string {
  const clean = text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, ' ').trim();
  return clean === '' ? 'no reason recorded' : clean.length > MAX_REASON_LENGTH ? `${clean.slice(0, MAX_REASON_LENGTH)}…` : clean;
}

/**
 * Why a pair has no answer, as a fixed phrase per class of failure: `PinVerdict.unknown`
 * can hold an error's own message, and a JSON parse error quotes the answer it
 * could not read — text of the network, which the model must not be given.
 */
function pinReason(unknown: string | undefined): string {
  const text = unknown ?? '';
  // `pins.ts` and `queryOsv` give a string, not a kind: the classes they write are matched exactly, and what
  // they never write (an error's own message) can only pick the class of its failure, never reach the line.
  if (/^(?:network disabled \(GUARDIAN_OFFLINE=1\)|no fetch implementation available|vetting time budget exhausted|network budget exhausted before OSV answered)$/.test(text)) return text;
  const http = /^osv http (\d{3})$/.exec(text);
  if (http !== null) return `OSV answered HTTP ${http[1] ?? ''}`;
  if (/^osv (?:answered|left) \d+ /.test(text) || /^osv answer over /.test(text)) return 'OSV gave an incomplete answer';
  // `JSON.parse` of an answer that is no JSON: its message names JSON and quotes the answer — only the class is kept.
  if (/JSON/.test(text)) return 'OSV gave an answer that is not JSON';
  return 'OSV lookup failed';
}

const notReadLine = (file: string, why: string): string => `dev-guardian: ${file} was not read (${said(why)}) — its packages were not vetted.`;

/** Whether `dir` is `root` or below it. */
function isWithin(root: string, dir: string): boolean {
  const rel = relative(resolve(root), resolve(dir));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

type LockFound =
  | { status: 'absent' }
  | { status: 'unread'; file: string; why: string }
  | { status: 'ok'; file: string; dir: string; text: string; start: string };

/**
 * The lockfile of the manager that runs `manager`: in `dir` and, when there is
 * none, in the nearest directory above up to `projectDir` — never beyond it.
 * With no `projectDir`, or a `dir` outside it, only `dir`. Read only through
 * the hooks' bounded reader, below the project root (a link to a network path
 * is refused), so a FIFO, a device or a share in its place cannot hold the hook.
 */
function findLockfile(manager: string, dir: string, projectDir: string | undefined, top: string | undefined, opts: HookVetOptions, memo: SpellingMemo): LockFound {
  const names = manager === 'npm' || manager === 'pnpm' || manager === 'yarn' || manager === 'bun' ? LOCKFILES[manager] : [];
  if (names.length === 0) return { status: 'absent' };
  const { root, dirs } = climb(dir, projectDir, top, opts, memo);
  // The manifest read already says that a directory on the network was not read.
  if (isNetworkPath(dir) || isNetworkPath(root)) return { status: 'absent' };
  const candidates = manager === 'bun' ? [...names, 'bun.lockb'] : names;
  for (const at of dirs) {
    for (const file of candidates) {
      const path = join(at, file);
      if (file === 'bun.lockb') {
        // The binary lockfile of bun < 1.2: nothing here reads it, and it is not read as text.
        if (presentBelow(root, path)) return { status: 'unread', file, why: "it is bun's binary lockfile" };
        continue;
      }
      const read = readSmallText(path, MAX_LOCKFILE_BYTES, root);
      if (read.status === 'ok') return { status: 'ok', file, dir: at, text: read.text, start: dirs[0] ?? resolve(dir) };
      if (read.status === 'refused') return { status: 'unread', file, why: refusedWhy(read.reason) };
    }
  }
  return { status: 'absent' };
}

/**
 * `dir` and each directory above it up to the project root, nearest first — the one bound of what a command's
 * directory may read upward, for the lockfile and the manifest alike. The root is `top` — the root of the git
 * repository the project directory is in ({@link gitRepositoryRoot}) — or else `projectDir`. With no `projectDir`, or
 * a `dir` outside that root, only `dir`: nothing above that root is ever read.
 */
function climb(dir: string, projectDir: string | undefined, top: string | undefined, opts: HookVetOptions, memo: SpellingMemo): { root: string; dirs: string[] } {
  // Inside the project is inside the repository root when there is one: a sibling folder of the session's is the project's.
  const bound = top ?? projectDir;
  let root = resolve(dir);
  let at = resolve(dir);
  if (bound !== undefined && projectDir !== undefined) {
    if (isWithin(bound, dir)) root = resolve(bound);
    else {
      // The text says "outside": it may be the same folder spelled another way (a short 8.3 name), which only the disk can say.
      const real = realClimb(dir, bound, opts, memo);
      if (real !== null) ({ root, start: at } = real);
    }
  }
  const dirs: string[] = [];
  for (let i = 0; i < 64; i += 1) {
    dirs.push(at);
    const parent = dirname(at);
    if (relative(root, at) === '' || parent === at) break;
    at = parent;
  }
  return { root, dirs };
}

/**
 * The climb in real space: the real paths of the folder and of the root, when {@link diskSpelling} gives both, the folder
 * is within the root, and the root is no home directory nor above one. `null` otherwise: the climb is the folder alone, as it was.
 */
function realClimb(dir: string, bound: string, opts: HookVetOptions, memo: SpellingMemo): { root: string; start: string } | null {
  const deps = opts.diskImpl ?? systemDisk;
  const platform = opts.platform ?? process.platform;
  const root = diskSpelling(bound, memo, deps, platform);
  if (root === null) return null;
  const start = diskSpelling(dir, memo, deps, platform);
  if (start === null || !isWithin(root, start)) return null;
  if (rootBarred(root, homeBarrier([opts.homeDir, homedir()], memo, deps))) return null;
  return { root, start };
}

/**
 * The `package.json` a manager installs from `dir`: the nearest one from `dir` up to the project root, as the
 * managers find theirs — the first found is the manifest, several are never merged. One that cannot be read is
 * the answer too (a manager would stop there). None at all: the `absent` of `dir`. A manifest above `dir` is named
 * by its path from `dir`, in POSIX form (`../package.json`); `dir` of the answer is the directory it was read in.
 */
function readNearestManifest(
  manager: string,
  dir: string,
  projectDir: string | undefined,
  top: string | undefined,
  opts: HookVetOptions,
  memo: SpellingMemo,
): { read: ManifestRead; dir: string } {
  // The climb's first step is where the names start: the folder as the disk spells it when the climb went by the real paths.
  const { dirs } = climb(dir, projectDir, top, opts, memo);
  const here = dirs[0] ?? resolve(dir);
  const absent = readNpmManifest(here, manager);
  if (absent.status !== 'absent') return { read: absent, dir: here };
  for (const at of dirs.slice(1)) {
    const read = readNpmManifest(at, manager);
    if (read.status === 'absent') continue;
    return { read: { ...read, file: `${relative(here, at).split(sep).join('/')}/${read.file}` }, dir: at };
  }
  return { read: absent, dir: here };
}

function refusedWhy(reason: 'not-a-regular-file' | 'too-large' | 'unreadable' | 'remote-link'): string {
  switch (reason) {
    case 'not-a-regular-file':
      return 'not a regular file';
    case 'too-large':
      return 'over 16 MiB';
    case 'remote-link':
      return 'on a network path';
    default:
      return 'could not be read';
  }
}

/** Whether `url` starts — on a path-segment boundary — with a registry URL the user's own npm configuration names. */
function fromUserRegistry(url: string, registries: readonly string[]): boolean {
  let normal: string;
  try {
    const u = new URL(url);
    normal = `${u.origin}${u.pathname.endsWith('/') ? u.pathname : `${u.pathname}/`}`;
  } catch {
    return false;
  }
  return registries.some((registry) => normal.startsWith(registry));
}

/** Where the entries of a lockfile are fetched from, if not the public registry: how many, and from which hosts the lockfile names. */
function otherSources(read: LockRead, userRegistries: () => readonly string[]): { count: number; named: string[]; distinct: number } {
  // A Set, not a list searched at every entry: a hostile lockfile can name a host per entry.
  const hosts = new Set<string>();
  const named: string[] = [];
  let count = 0;
  for (const { source } of read.entries) {
    if (!isOtherSource(source, userRegistries)) continue;
    count += 1;
    if ('host' in source && source.host !== '' && !hosts.has(source.host)) {
      hosts.add(source.host);
      if (named.length < MAX_NAMED_HOSTS) named.push(source.host);
    }
  }
  return { count, named, distinct: hosts.size };
}

function isOtherSource(source: Source, userRegistries: () => readonly string[]): boolean {
  if (source.kind === 'git') return true;
  // Only the USER's registries silence the line: a file of the project never does.
  return source.kind === 'elsewhere' && !fromUserRegistry(source.url, userRegistries());
}

function otherSourceLine(count: number, file: string, named: readonly string[], distinct: number): string {
  const hosts = named.length === 0 ? '' : ` (${named.join(', ')}${distinct > named.length ? ` and ${distinct - named.length} more` : ''})`;
  return `dev-guardian: ${plural(count)} of ${file} ${count === 1 ? 'comes' : 'come'} from another source${hosts} — what it serves was not vetted.`;
}

/**
 * The pairs of a lockfile to ask OSV about: every pin and every pair a URL
 * names, but not those of a git source, and not those of a scope the npm
 * configuration gives a registry of its own — their names stay where the manager
 * fetches them — unless the lockfile itself gives the public registry's URL for
 * the entry. What a PROJECT file keeps out is counted for a line.
 */
function pairsToAsk(
  read: LockRead,
  registry: RegistryContext,
): { asked: Pin[]; heldByProject: number; scopes: Set<string>; source: string } {
  const asked: Pin[] = [];
  const askedKeys = new Set<string>();
  const heldKeys = new Set<string>();
  const scopes = new Set<string>();
  let source = '';
  // One prepared lookup: the configuration is read once, however many scopes the lockfile names.
  const ownRegistry = npmScopeRegistryOf(registry);
  for (const entry of read.entries) {
    if (entry.source.kind === 'git') continue;
    for (const pin of [entry.pin, entry.fetched]) {
      if (pin === undefined) continue;
      const key = pairKey(pin);
      const own = entry.source.kind === 'public' ? null : ownRegistry(pin.name);
      if (own !== null) {
        if (own.from === 'project') {
          heldKeys.add(key);
          scopes.add(`@${own.scope}`);
          if (source === '') source = basename(own.source);
        }
        continue;
      }
      if (askedKeys.has(key)) continue;
      askedKeys.add(key);
      asked.push(pin);
    }
  }
  return { asked, heldByProject: [...heldKeys].filter((key) => !askedKeys.has(key)).length, scopes, source };
}

/**
 * The lockfile of a manifest install, read and planned — or `undefined`, with
 * the line that says why it was not read. Nothing here throws: a lockfile that
 * cannot be handled is one more "was not read", and the manifest is vetted as
 * it is with no lockfile.
 */
function lockedProject(
  c: InstallCommand,
  dir: string,
  manifest: ManifestRead,
  opts: HookVetOptions,
  top: string | undefined,
  registry: RegistryContext,
  notes: string[],
  memo: SpellingMemo,
): LockedProject | undefined {
  try {
    const found = findLockfile(c.manager, dir, opts.projectDir, top, opts, memo);
    if (found.status === 'absent') return undefined;
    if (found.status === 'unread') {
      notes.push(notReadLine(found.file, found.why));
      return undefined;
    }
    const format = lockFormat(found.file);
    const read = format === null ? { unread: 'its format is not known' } : readLock(format, found.text);
    if ('unread' in read) {
      notes.push(notReadLine(found.file, read.unread));
      return undefined;
    }
    const ctx: RegistryContext = { ...registry, projectDir: dir, command: registryCommand(c) };
    let userRegistries: string[] | undefined;
    const user = (): readonly string[] => (userRegistries ??= npmUserRegistries(ctx));
    const plan = pairsToAsk(read, ctx);
    const lines: string[] = [];
    if (plan.heldByProject > 0) lines.push(ownScopeLine(plan.heldByProject, found.file, plan.scopes, plan.source));
    const other = otherSources(read, user);
    if (other.count > 0) lines.push(otherSourceLine(other.count, found.file, other.named, other.distinct));
    const divergent = read.entries.filter((e) => e.fetched !== undefined).length;
    if (divergent > 0) {
      lines.push(
        `dev-guardian: ${divergent === 1 ? '1 entry' : `${divergent} entries`} of ${found.file} ${divergent === 1 ? 'names' : 'name'} one package and ${divergent === 1 ? 'fetches' : 'fetch'} another — both were looked up; check the lockfile.`,
      );
    }
    if (read.unrecognised > 0) {
      lines.push(`dev-guardian: ${read.unrecognised === 1 ? '1 entry' : `${read.unrecognised} entries`} of ${found.file} ${read.unrecognised === 1 ? 'was' : 'were'} not recognised — not vetted.`);
    }
    notes.push(...lines);
    return {
      file: found.file,
      manifestFile: manifest.file,
      read,
      rel: relative(found.dir, found.start).split(sep).join('/'),
      direct: manifest.packages.map((p) => p.name),
      covered: [],
      asked: plan.asked,
    };
  } catch {
    notes.push('dev-guardian: the lockfile was not read (could not be read) — its packages were not vetted.');
    return undefined;
  }
}

/**
 * The packages the lockfile does NOT cover: a direct dependency leaves the
 * registry path only when the lockfile records, for this project, the very
 * range the manifest has, with a pinned version that satisfies it — the case
 * where the manager installs the pin and resolves nothing again. The covered
 * ones are kept in `lock.covered`, for the typosquat check alone.
 */
function withoutCovered(packages: readonly PackageSpec[], lock: LockedProject): PackageSpec[] {
  const rest: PackageSpec[] = [];
  for (const pkg of packages) {
    const pinned = pkg.range === undefined ? null : lock.read.resolutionOf(lock.rel, pkg.name, pkg.range);
    if (pinned === null) rest.push(pkg);
    else lock.covered.push(pkg);
  }
  return rest;
}

/** The advisory ids of a verdict as a line may repeat them: ids of the shape OSV writes, nothing else. */
function advisoryIds(ids: readonly string[]): string {
  const clean = ids.map((id) => id.trim()).filter((id) => /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(id));
  if (clean.length === 0) return 'a MAL- advisory';
  // A pair of a hostile lockfile may carry hundreds of advisories: five are named, the rest counted.
  return clean.length > MAX_NAMED_IDS ? `${clean.slice(0, MAX_NAMED_IDS).join(', ')} and ${clean.length - MAX_NAMED_IDS} more` : clean.join(', ');
}

/** What the answers of OSV say of one lockfile: the denials, and the lines for what was left or not answered. */
function lockOutcome(
  lock: LockedProject,
  verdicts: ReadonlyMap<string, PinVerdict>,
  counted: Set<string>,
): { denies: string[]; lines: string[] } {
  const denies = new Set<string>();
  const lines: string[] = [];
  const askedKeys = new Set(lock.asked.map(pairKey));
  const advisory = (v: PinVerdict): string => `OSV malicious-package advisory for ${v.pin.version}: ${advisoryIds(v.malicious ?? [])}`;
  const found = (pin: Pin | undefined): PinVerdict | undefined => {
    const v = pin !== undefined && askedKeys.has(pairKey(pin)) ? verdicts.get(pairKey(pin)) : undefined;
    return v !== undefined && v.malicious !== null && v.malicious.length > 0 ? v : undefined;
  };
  for (const entry of lock.read.entries) {
    const own = found(entry.pin);
    if (own !== undefined) denies.add(`${lock.file} pins '${pairKey(own.pin)}': ${sentence(advisory(own))}`);
    const fetched = found(entry.fetched);
    if (fetched !== undefined) {
      const names = entry.pin === undefined ? `${lock.file} fetches` : `${lock.file} names '${pairKey(entry.pin)}' and fetches`;
      denies.add(`${names} '${pairKey(fetched.pin)}': ${sentence(advisory(fetched))}`);
    }
  }
  let unanswered = 0;
  let why = '';
  let left = 0;
  for (const pin of lock.asked) {
    const key = pairKey(pin);
    const v = verdicts.get(key);
    if (v === undefined) {
      // Not asked: past the cap of the whole call. A pair two lockfiles hold is left once.
      if (!counted.has(key)) left += 1;
      counted.add(key);
    } else if (v.malicious === null) {
      unanswered += 1;
      if (why === '') why = v.unknown ?? '';
    }
  }
  if (unanswered > 0) lines.push(`${COULD_NOT_VET}${plural(unanswered)} of ${lock.file} (${pinReason(why)})${NOT_VERIFIED}`);
  if (left > 0) {
    lines.push(
      `dev-guardian: ${left} more ${left === 1 ? 'package' : 'packages'} of ${lock.file} ${left === 1 ? 'was' : 'were'} not vetted (only the first ${MAX_PINS} are) — not verified.`,
    );
  }
  return { denies: [...denies], lines };
}

/** Whether a package is on its ecosystem's popular list — the lists `vet_packages` itself uses. */
function popularTest(opts: HookVetOptions): (pkg: PackageSpec) => boolean {
  const indexes = new Map<PkgEcosystem, PopularIndex | null>();
  return (pkg) => {
    let index = indexes.get(pkg.ecosystem);
    if (index === undefined) {
      const override = opts.popular?.[pkg.ecosystem];
      index =
        override === null
          ? null
          : override !== undefined
            ? buildPopularIndex(pkg.ecosystem, override)
            : opts.popularDir === undefined
              ? loadPopularIndex(pkg.ecosystem)
              : loadPopularIndex(pkg.ecosystem, opts.popularDir);
      indexes.set(pkg.ecosystem, index);
    }
    return index !== null && index.set.has(normalizePackageName(pkg.ecosystem, pkg.name));
  };
}

/** Whether `path` exists — `lstat`, never following a link at it — below `under`, with no link on the way to a network or device path. */
function presentBelow(under: string, path: string): boolean {
  if (!walkLinksUnder(under, path).ok) return false;
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Whether `path` is a regular FILE below `under` — `stat`, so a local link is
 * followed to what it names (npm's own `.bin` entries are links on POSIX) —
 * with no link on the way to a network or device path.
 */
function fileBelow(under: string, path: string): boolean {
  if (!walkLinksUnder(under, path).ok) return false;
  return isRegularFile(path);
}

/** Whether `path` is a regular file, a local link followed to what it names (`stat`: it opens nothing). */
function isRegularFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/** The largest `package.json` read to see which package a `node_modules` folder holds. */
const MAX_PACKAGE_JSON_BYTES = 1024 * 1024;

/**
 * npm's prefix for a command run in `cwd`: the nearest directory, from `cwd`
 * up, that holds a `package.json` or a `node_modules` (`lstat`, behind the
 * link walk), else `cwd` itself — what `npx` / `npm exec` load the project's
 * tree from.
 */
function npmPrefix(cwd: string): string {
  let dir = resolve(cwd);
  for (let i = 0; i < 64; i += 1) {
    if (presentBelow(dir, join(dir, 'package.json')) || presentBelow(dir, join(dir, 'node_modules'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return resolve(cwd);
}

/** Whether `<dir>/node_modules/<name>/package.json` is a regular file whose `name` is `name` — npm's own test of an installed package. */
function packageNamed(dir: string, name: string): boolean {
  const r = readSmallText(join(dir, 'node_modules', name, 'package.json'), MAX_PACKAGE_JSON_BYTES, dir);
  if (r.status !== 'ok') return false;
  try {
    const manifest: unknown = JSON.parse(r.text.charCodeAt(0) === 0xfeff ? r.text.slice(1) : r.text);
    return manifest !== null && typeof manifest === 'object' && (manifest as Record<string, unknown>)['name'] === name;
  } catch {
    return false;
  }
}

/**
 * Whether `npx` / `npm exec` / `bunx` would run `name` from the project
 * rather than fetch it (review P1), as npm resolves it: a
 * `node_modules/.bin/<name>` FILE in npm's prefix or a directory above it —
 * for the unscoped program name a launcher runs, not a `-p` package
 * (`byPackageFlag`), bun's `.exe` too, walked up to the repository root — or
 * the package itself in the prefix's own tree: `<prefix>/node_modules/<name>/
 * package.json`, whose `name` is `name` (review of 3.4.0, finding 5: one that
 * was `{}`, named another package or was no JSON at all skipped the vetting
 * while npm fetched; so did one in a parent of a directory with its own
 * `package.json`, which is npm's prefix). Not found, or behind a link to a
 * network path, means it would be fetched, and is vetted.
 */
function installedLocally(name: string, cwd: string, byPackageFlag = false, manager = ''): boolean {
  const prefix = npmPrefix(cwd);
  if (packageNamed(prefix, name)) return true;
  if (name.startsWith('@') || byPackageFlag) return false;
  let dir = prefix;
  for (let i = 0; i < 32; i += 1) {
    const bin = join(dir, 'node_modules', '.bin');
    for (const candidate of manager === 'bun' ? [join(bin, name), join(bin, `${name}.exe`)] : [join(bin, name)]) {
      if (fileBelow(dir, candidate)) return true;
    }
    if (presentBelow(dir, join(dir, '.git'))) return false;
    const parent = dirname(dir);
    if (parent === dir) return false;
    dir = parent;
  }
  return false;
}

/** The words of one `dotnet new install` the hook asks the disk about: no more, whatever the length of the line. */
const MAX_DISK_WORDS = 50;

/** The reason a word of `dotnet new install` was not asked of the disk, said as the command's own: the word is vetted as an identifier all the same. */
const diskReason = (why: string): string => `whether a file or folder of that name is in the command's folder was not looked for (${why})`;

/**
 * `dotnet new install <word>`: with an entry of that name in the command's folder (a folder, a file, empty or not, a link itself: `lstat`
 * follows none) the installer takes the word as a path and fetches nothing (measured 2026-11-20, table-id-or-path-windows-2026-11-20.txt), so
 * the word is no identifier and is left out, without a line. A word that is not there (`ENOENT`, `ENOTDIR`) is an identifier. A word with
 * `::` is always one (the separator of the SDK's version; on NTFS it would be a stream) and never asked. Where the disk cannot say — a
 * folder on the network (never asked: `cwd` as it arrives, before it is resolved, or the path of the word), one a `cd` moved to that is not
 * known, an `lstat` that fails for another reason, the deadline, a word past the first {@link MAX_DISK_WORDS} — the word is vetted and the command
 * says why it may not deny. At most {@link MAX_DISK_WORDS} distinct words are asked.
 */
function withoutDiskEntries(c: InstallCommand, opts: HookVetOptions, pastDeadline: () => boolean, said: Set<string>, spelling: SpellingMemo): InstallCommand {
  const why = new Set<string>();
  const lstat: LstatLike = opts.lstatImpl ?? ((path) => lstatSync(path));
  const dir = isNetworkPath(opts.cwd) ? undefined : commandDir(c, opts, spelling);
  const asked = new Map<string, boolean>();
  const packages: PackageSpec[] = [];
  for (const pkg of c.packages) {
    const word = pkg.raw;
    if (word.includes('::')) {
      packages.push(pkg);
      continue;
    }
    const known = asked.get(word);
    if (known !== undefined) {
      if (!known) packages.push(pkg);
      continue;
    }
    if (pastDeadline()) why.add('vetting time budget exhausted');
    else if (dir === undefined) why.add('the folder is on the network');
    else if (dir === null) why.add('the folder is not known');
    else if (asked.size >= MAX_DISK_WORDS) why.add(`past the first ${String(MAX_DISK_WORDS)} words`);
    else {
      const path = resolve(dir, word);
      if (isNetworkPath(path)) why.add('the folder is on the network');
      else {
        try {
          lstat(path);
          asked.set(word, true);
          continue;
        } catch (error) {
          const code = (error as { code?: unknown } | null)?.code;
          asked.set(word, false);
          if (code !== 'ENOENT' && code !== 'ENOTDIR') why.add(`lstat failed: ${typeof code === 'string' ? code : 'unknown'}`);
        }
      }
    }
    packages.push(pkg);
  }
  // The reason is also a line of the answer of its own: a name that the registry configuration explains is told that reason instead of this one.
  for (const each of why) said.add(`dev-guardian: ${diskReason(each)} — its words were vetted as package names.`);
  return { ...c, packages, uncertain: [...c.uncertain, ...[...why].map(diskReason)] };
}

/** Whether `pkg` is a name whose copy {@link runsInstalledCopy} did not look for because the launcher runs in a folder on the network, with no `cd`. */
function copyNotLookedFor(pkg: PackageSpec, c: InstallCommand, opts: HookVetOptions): boolean {
  return c.localFirst === true && copyMayBeLocal(pkg, c) && c.workdir === undefined && isNetworkPath(resolve(opts.cwd));
}

/** The names whose installed copy {@link runsInstalledCopy} looks for: no range, no alias, no `--prefix` (review of 3.4.0, finding 5). */
function copyMayBeLocal(pkg: PackageSpec, c: InstallCommand): boolean {
  return pkg.range === undefined && pkg.raw === pkg.name && c.prefixed !== true;
}

/**
 * Whether a launcher would run `pkg` from the project (review 8, extra item):
 * an unversioned name — `npx vitest`, never `npx -y vitest@5.0.4` or
 * `vitest@latest`, which npx fetches unless the installed copy matches — found
 * installed ({@link installedLocally}) in the directory the command runs in. That
 * is the hook's working directory moved by the `cd`s before the command
 * ({@link commandDir}): `cd mcp && npx vitest run` from the repository root ran
 * `mcp`'s own vitest, and the hook warned about the registry's newest one.
 */
function runsInstalledCopy(pkg: PackageSpec, c: InstallCommand, opts: HookVetOptions, memo: Map<string, boolean>, spelling: SpellingMemo): boolean {
  // `--prefix` (`-C`) points npm at another project: where is not read here (review of 3.4.0, finding 5).
  if (!copyMayBeLocal(pkg, c)) return false;
  const dir = commandDir(c, opts, spelling);
  // On the network no installed copy is looked for (each lstat may cost the SMB timeout): see {@link NETWORK_COPY_REASON}.
  if (dir === null || isNetworkPath(dir)) return false;
  const key = `${dir}\0${pkg.name}\0${String(c.byPackageFlag === true)}\0${c.manager}`;
  const known = memo.get(key);
  if (known !== undefined) return known;
  const found = installedLocally(pkg.name, dir, c.byPackageFlag === true, c.manager);
  memo.set(key, found);
  return found;
}

/**
 * The directory an install command runs in: the hook's `cwd`, moved by every
 * `cd` before it on the line ({@link InstallCommand.workdir}) — a `~` read as the
 * home directory and, on Windows, an MSYS `/c/…` as `C:/…`. Each move only
 * when its directory is there (`lstat` behind the link walk, never on the
 * network): a `cd` to one that is not there failed and moved nothing, and
 * `cd web/node_modules/.bin/x; cd ../../..; npx x` ran `x` three levels above
 * the line's start, not in `web` (review of 3.4.0, finding 5). A move through
 * a link is not followed either ({@link plainMove}). `null` when a move cannot
 * be read or did not surely happen: nothing is then taken as installed.
 */
function commandDir(c: InstallCommand, opts: HookVetOptions, memo: SpellingMemo): string | null {
  if (c.workdir === undefined) return resolve(opts.cwd);
  if (c.workdir === null) return null;
  const home = opts.homeDir ?? homedir();
  const windows = (opts.platform ?? process.platform) === 'win32';
  let dir = resolve(opts.cwd);
  if (isNetworkPath(dir)) return null;
  let real = realDir(dir);
  for (const step of c.workdir) {
    const target = cdTarget(step, home, windows);
    if (target === null || real === null) return null;
    const moved = plainMove(dir, real, target, windows, opts, memo);
    if (moved === null) return null;
    [dir, real] = moved;
  }
  return dir;
}

/** The target of a `cd` as the hook walks it: a `~` read as the home directory and, on Windows, an MSYS `/c/…` as `C:/…`; `null` for `~user`. */
function cdTarget(step: string, home: string, windows: boolean): string | null {
  if (step === '~' || /^~[\\/]/.test(step)) return join(home, step.slice(1));
  if (step.startsWith('~')) return null;
  return windows ? step.replace(/^\/(?:cygdrive\/)?([A-Za-z])(?=\/|$)/, (_, drive: string) => `${drive.toUpperCase()}:/`) : step;
}

/** The real path of a directory (`realpathSync.native`), or `null` when it cannot be had. Never asked of a network path. */
function realDir(path: string): string | null {
  try {
    return realpathSync.native(path);
  } catch {
    return null;
  }
}

/**
 * Where `cd target` from `dir` (whose real path is `real`) goes, and its real
 * path — when it goes to a directory that is there through no link. The shell
 * keeps the path as typed, while npx looks for its project from the directory
 * it runs in, the link's target: a `cd` through a symlink or a junction made
 * the walk up for an installed bin answer for another directory than npx's
 * (review 12, finding 4). So each component the `cd` names is `lstat`ed (a
 * link, or one that is not a directory or not there: `null`), and the real
 * path of where it lands must be the real path of `dir` plus the step — any
 * other reparse point, or a `realpath` that fails, is `null` too. A drive
 * with no slash after it (`C:`, `C:x`), whose meaning depends on the shell,
 * is `null`. Never on the network.
 */
function plainMove(dir: string, real: string, target: string, windows: boolean, opts: HookVetOptions, memo: SpellingMemo): [string, string] | null {
  if (windows && /^[A-Za-z]:(?![\\/])/.test(target)) return null;
  const next = resolve(dir, target);
  if (isNetworkPath(next)) return null;
  const root = isAbsolute(target) ? parse(target).root : '';
  let at = root === '' ? dir : resolve(dir, root);
  for (const part of target.slice(root.length).split(windows ? /[\\/]+/ : /\/+/)) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      at = dirname(at);
      continue;
    }
    at = join(at, part);
    try {
      const kind = lstatSync(at);
      if (kind.isSymbolicLink() || !kind.isDirectory()) return null;
    } catch {
      return null;
    }
  }
  const landed = realDir(next);
  if (landed === null) return null;
  const expected = resolve(real, target);
  if (windows ? landed.toLowerCase() === expected.toLowerCase() : landed === expected) return [next, landed];
  // The text says "elsewhere": it may be the same folder spelled another way (a short 8.3 name). Only on Windows, and only
  // when the folder it starts from and each component are the same folder through no link (install-vet-path-forms).
  return windows && spelledAs(dir, real, target, landed, opts, memo) ? [landed, landed] : null;
}

/** Whether `cd target` from `dir` (real path `real`) lands on `landed` by the closed grammar of {@link diskStep}, component by component. */
function spelledAs(dir: string, real: string, target: string, landed: string, opts: HookVetOptions, memo: SpellingMemo): boolean {
  const deps = opts.diskImpl ?? systemDisk;
  const platform = opts.platform ?? process.platform;
  const root = isAbsolute(target) ? parse(target).root : '';
  // A relative `cd` starts from a folder that is behind no link; an absolute one from its drive root.
  let at = diskSpelling(root === '' ? dir : resolve(dir, root), memo, deps, platform);
  if (at === null || (root === '' && at.toLowerCase() !== real.toLowerCase())) return false;
  for (const part of target.slice(root.length).split(/[\\/]+/)) {
    if (part === '' || part === '.') continue;
    at = part === '..' ? dirname(at) : diskStep(at, join(at, part), part, memo, deps);
    if (at === null) return false;
  }
  return at.toLowerCase() === landed.toLowerCase();
}

// ───────────────────────────────────────────────────── inline scripts (PEP 723)

/** The most script files one call reads, each once; the others are counted and the user is asked. */
const MAX_SCRIPT_FILES = 8;
/** The reasons a script was not read that come from the line or the session, never from a file of the repository: only the line is said. */
const DEADLINE_REASON = 'vetting time budget exhausted';
const NOT_LITERAL_REASON = 'not a literal file name';
/** The two reasons the link walk and the read give ({@link ManifestRead.reason}). */
const NETWORK_REASON = 'on a network path';
const UNREADABLE_REASON = 'could not be read';
/** How many directories one line may hold in doubt (`cd tools && cd ..` after a link: the logical one and the physical one). */
const MAX_DIR_STATES = 8;

/** Where the scripts of a command are looked for: the directories (more than one when a `..` follows a link), or why none is known. */
type Folder = { kind: 'dirs'; dirs: string[] } | { kind: 'unknown' } | { kind: 'deadline' } | { kind: 'refused'; reason: string };

/** What the disk says of a word `pipx run` may take as its app. */
type Probe = { kind: 'file' } | { kind: 'none' } | { kind: 'refused'; reason: string };

/** What one call knows of the scripts of its line: asked once, whatever the number of commands that name them. */
interface ScriptWorld {
  opts: HookVetOptions;
  /** The root the links of a script are walked from when it is below it. */
  top: string | undefined;
  pastDeadline: () => boolean;
  notes: string[];
  asks: string[];
  /** The lines said with a deny as well as without one. */
  withDeny: string[];
  folders: Map<string, Folder>;
  probes: Map<string, Probe>;
  reads: Map<string, ManifestRead>;
  /** The files past {@link MAX_SCRIPT_FILES}, each once. */
  overflow: Set<string>;
  /** The words of `pipx run` asked of the disk: at most {@link MAX_VETTED_PACKAGES} a call. */
  asked: Set<string>;
}

const hasDotDot = (path: string): boolean => path.split(/[\\/]+/).includes('..');
const samePath = (a: string, b: string): boolean => (process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b);

/** Whether a link stands on the way from `under` to `path` (`lstat` of each component below `under`). */
function linkOnPath(under: string, path: string): boolean {
  const rel = relative(resolve(under), resolve(path));
  if (rel === '' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return false;
  let at = resolve(under);
  for (const part of rel.split(/[\\/]+/)) {
    if (part === '' || part === '.') continue;
    at = join(at, part);
    try {
      if (lstatSync(at).isSymbolicLink()) return true;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Where `target` leads from the real directory `real` when the kernel resolves it (POSIX): each link on the way is followed to its real
 * path and a `..` goes up from there — `tools/..` with `tools` a link to `sub/inner` is `sub`, where the shell, resolving the `..` in the
 * text, says the directory above `tools`. The last component of a word that names a file (`lastIsFile`) is not resolved: the open follows
 * it. `null` when a link on the way cannot be resolved, or leads off the local disk (that one is refused by the reading itself).
 */
function physicalPath(real: string, target: string, lastIsFile: boolean): string | null {
  let at = real;
  const parts = target.split(/[\\/]+/);
  for (const [k, part] of parts.entries()) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      at = dirname(at);
      continue;
    }
    const next = join(at, part);
    let link = false;
    try {
      link = lstatSync(next).isSymbolicLink();
    } catch {
      link = false;
    }
    if (link && !(lastIsFile && k === parts.length - 1)) {
      // `realpath` of a link to the network waits for it: the walk looks at the link's own target first.
      if (!walkLinksUnder(at, next).ok) return null;
      const resolved = realDir(next);
      if (resolved === null) return null;
      at = resolved;
    } else at = next;
  }
  return at;
}

type Moved = { ok: true; states: Array<[logical: string, real: string]> } | { ok: false; folder: Folder };

/**
 * One `cd` (or `--directory`, or `UV_WORKING_DIR`) of a script's line, from the directory `logical` (whose real path is `real`): the
 * links on the way are walked first, from the project root when the target is below it ({@link walkLinksUnder}: a link to the network
 * is refused, and so is a chain of more than 32); then the real path of where it lands. A link that was followed and leads nowhere is
 * "could not be read" — the repository put the link there — and a plain directory that is not there is a directory not known. With a
 * `..` after a link the logical and the physical directory can differ: both are kept.
 */
function moveScriptDir(logical: string, real: string, target: string, windows: boolean, top: string | undefined): Moved {
  const unknown: Moved = { ok: false, folder: { kind: 'unknown' } };
  // A drive with no slash after it (`C:`, `C:x`) depends on the shell, as it does for `commandDir`.
  if (windows && /^[A-Za-z]:(?![\\/])/.test(target)) return unknown;
  const next = resolve(logical, target);
  if (isNetworkPath(next)) return { ok: false, folder: { kind: 'refused', reason: NETWORK_REASON } };
  const under = top !== undefined && isWithin(top, next) ? top : logical;
  const walked = walkLinksUnder(under, next);
  if (!walked.ok) return { ok: false, folder: { kind: 'refused', reason: walked.reason === 'remote-link' ? NETWORK_REASON : UNREADABLE_REASON } };
  const landed = realDir(next);
  if (landed === null) return linkOnPath(under, next) ? { ok: false, folder: { kind: 'refused', reason: UNREADABLE_REASON } } : unknown;
  const states: Array<[string, string]> = [[next, landed]];
  if (!isAbsolute(target) && hasDotDot(target)) {
    const physical = physicalPath(real, target, false);
    const physicalReal = physical === null ? null : realDir(physical);
    if (physical !== null && physicalReal !== null && !samePath(physical, next)) states.push([physical, physicalReal]);
  }
  return { ok: true, states };
}

/**
 * The directories the uv or the pipx look for the scripts of `c` in: where the line runs ({@link InstallCommand.workdir}, the `cd`s
 * before it), moved by `--directory` / `UV_WORKING_DIR` ({@link InstallCommand.scriptDir}). Unlike {@link commandDir} a `cd` through a
 * link is followed — the process opens the script from the link's target — one step after another, the shell's own path (the logical
 * one) kept for the next `cd` (P9 and P10 of install-vet-inline-script-deps). Nothing is asked of the disk past the deadline.
 */
function scriptFolder(c: InstallCommand, w: ScriptWorld): Folder {
  if (c.workdir === null || c.scriptDirUnknown === true) return { kind: 'unknown' };
  const start = resolve(w.opts.cwd);
  if (isNetworkPath(start)) return { kind: 'unknown' };
  const steps = [...(c.workdir ?? []), ...(c.scriptDir === undefined ? [] : [c.scriptDir])];
  if (steps.length === 0) return { kind: 'dirs', dirs: [start] };
  const home = w.opts.homeDir ?? homedir();
  const windows = (w.opts.platform ?? process.platform) === 'win32';
  const startReal = realDir(start);
  if (startReal === null) return { kind: 'unknown' };
  let states: Array<[string, string]> = [[start, startReal]];
  for (const step of steps) {
    if (w.pastDeadline()) return { kind: 'deadline' };
    const target = cdTarget(step, home, windows);
    if (target === null) return { kind: 'unknown' };
    const next: Array<[string, string]> = [];
    for (const [logical, real] of states) {
      const moved = moveScriptDir(logical, real, target, windows, w.top);
      if (!moved.ok) return moved.folder;
      for (const state of moved.states) if (!next.some(([seen]) => samePath(seen, state[0]))) next.push(state);
    }
    states = next.slice(0, MAX_DIR_STATES);
  }
  return { kind: 'dirs', dirs: states.map(([logical]) => logical) };
}

function folderOf(c: InstallCommand, w: ScriptWorld): Folder {
  const key = JSON.stringify([c.workdir === undefined ? 'none' : c.workdir, c.scriptDir ?? null, c.scriptDirUnknown ?? null]);
  let folder = w.folders.get(key);
  if (folder === undefined) {
    try {
      folder = scriptFolder(c, w);
    } catch {
      // Fail-open: a directory that cannot be worked out is a directory not known.
      folder = { kind: 'unknown' };
    }
    w.folders.set(key, folder);
  }
  return folder;
}

/** A path a script may be at, and the directory of the command it was reached from. */
interface ScriptPath {
  path: string;
  dir: string;
  physical: boolean;
}

/** The paths the word `written` names from each of `dirs`: the logical one and, with a `..` after a link, the physical one. */
function scriptPaths(dirs: readonly string[], written: string): ScriptPath[] {
  const out: ScriptPath[] = [];
  const add = (path: string, dir: string, physical: boolean): void => {
    if (!out.some((p) => samePath(p.path, path))) out.push({ path, dir, physical });
  };
  for (const dir of dirs) {
    add(resolve(dir, written), dir, false);
    if (isAbsolute(written) || !hasDotDot(written)) continue;
    const real = realDir(dir);
    const physical = real === null ? null : physicalPath(real, written, true);
    if (physical !== null) add(physical, dir, true);
  }
  return out;
}

/** The root a script's links are walked from: the project root when it is below it, the command's directory otherwise. */
const scriptUnder = (w: ScriptWorld, path: string, dir: string): string => (w.top !== undefined && isWithin(w.top, path) ? w.top : dir);

/** Whether `word` is a regular file below `under`: `walkLinksUnder` first, and the reason when it refuses. */
function probeFile(under: string, path: string): Probe {
  const walked = walkLinksUnder(under, path);
  if (!walked.ok) return { kind: 'refused', reason: walked.reason === 'remote-link' ? NETWORK_REASON : UNREADABLE_REASON };
  return isRegularFile(path) ? { kind: 'file' } : { kind: 'none' };
}

/** The read of a script, once per call: `undefined` when it is past the eighth file. Never throws. */
function readScript(w: ScriptWorld, cand: ScriptPath, written: string): ManifestRead | undefined {
  const key = process.platform === 'win32' ? cand.path.toLowerCase() : cand.path;
  const known = w.reads.get(key);
  if (known !== undefined) return known;
  if (w.reads.size >= MAX_SCRIPT_FILES) {
    w.overflow.add(key);
    return undefined;
  }
  const under = scriptUnder(w, cand.path, cand.dir);
  let read: ManifestRead;
  try {
    read = cand.physical
      ? { ...readInlineScript(dirname(cand.path), basename(cand.path), 'uv', under), file: said(written) }
      : readInlineScript(cand.dir, written, 'uv', under);
  } catch {
    read = { file: said(written), status: 'unreadable', packages: [], names: [], registries: [], reason: UNREADABLE_REASON };
  }
  w.reads.set(key, read);
  return read;
}

/** The question for a script the hook did not read, whose packages the uv or the pipx install unvetted. */
const unreadAsk = (file: string, why: string): string =>
  `the inline dependencies of ${file} could not be read (${why}) — uv or pipx installs them unvetted; allow it only if you trust this script`;

/**
 * The words the pipx reads as a file (`malwareOnly`, a mark of the parse) that are still packages of the command — a `pipx install <word>`,
 * or a `pipx run <word>` whose folder has no such file or is not known — as a command of their own (`fromArchiveFile`): they are asked of the
 * registry and of OSV only to find a malicious package of that name, and nothing else is said of them. What is left is the command without them.
 */
function archiveFileCommand(c: VetCommand): VetCommand[] {
  const words = c.packages.filter((p) => p.malwareOnly === true);
  if (words.length === 0) return [c];
  const rest: VetCommand = { ...c, packages: c.packages.filter((p) => p.malwareOnly !== true) };
  return [rest, { ...withoutCandidates(c), packages: words, skipped: [], uncertain: [], fromArchiveFile: true }];
}

/** The line said for the word `pipx run` reads as a file when the hook could not ask the disk whether it is there (the folder is not known, or time or the 50 words ran out). */
const runsAsFileLine = (word: string): string =>
  `dev-guardian: pipx run reads ${word} as a file, not a package — if the file is there, pipx runs it as a script and installs the packages its \`# /// script\` block names; they were not vetted.`;

/** A command stripped of what only its own packages need, as the base of the commands made of its scripts. */
function withoutCandidates(c: InstallCommand): VetCommand {
  const { candidates: _candidates, candidatesDropped: _dropped, inlineScripts: _scripts, ...rest } = c;
  return rest;
}

/**
 * The scripts a command runs, vetted: each is read (once per call, at most eight files) and what its `# /// script` block names becomes
 * one more command to vet, as a manifest's packages do (`fromManifest`); what could not be read is a line, and — when the repository can
 * choose it — a question to the user. A word `pipx run` may take as its app (`ifFile`) is asked of the disk: when it is a file the
 * pipx runs it, so the word is looked up for malware only (`fromLocalScript`) and its block is read; when it is not there nothing
 * changes. A word that could not be asked keeps its place as a package and says it may be a local script — but the word `pipx run`
 * reads as a file for certain (`runsAsScript`) says {@link runsAsFileLine} instead, and is no doubt about the command.
 */
function scriptCommands(c: InstallCommand, w: ScriptWorld): { command: VetCommand; extra: VetCommand[] } {
  const scripts = c.inlineScripts;
  if (scripts === undefined) return { command: c, extra: [] };
  const extra: VetCommand[] = [];
  const base = withoutCandidates(c);
  /** The words of `pipx run` that are files (or entries the walk refused): looked up for malware only. */
  const local = new Set<string>();
  const maybeLocal: string[] = [];
  let ran = false;
  const unread = (file: string, why: string, ask: boolean): void => {
    w.notes.push(notReadLine(file, why));
    if (ask) w.asks.push(unreadAsk(file, why));
  };
  const askable = (why: string): boolean => why !== DEADLINE_REASON && why !== UNKNOWN_DIRECTORY && why !== NOT_LITERAL_REASON;
  for (const s of scripts) {
    const file = said(s.file);
    const asked = s.ifFile === true;
    if (!asked) ran = true;
    if (s.literal === false) {
      w.notes.push(notReadLine(file, NOT_LITERAL_REASON));
      continue;
    }
    if (isNetworkPath(s.file)) {
      unread(file, NETWORK_REASON, true);
      if (asked) local.add(s.file);
      continue;
    }
    const folder = w.pastDeadline() ? ({ kind: 'deadline' } as const) : folderOf(c, w);
    if (folder.kind === 'refused') {
      unread(file, folder.reason, true);
      if (asked) local.add(s.file);
      continue;
    }
    if (folder.kind !== 'dirs') {
      if (asked) maybeLocal.push(s.file);
      else w.notes.push(notReadLine(file, folder.kind === 'deadline' ? DEADLINE_REASON : UNKNOWN_DIRECTORY));
      continue;
    }
    if (asked) {
      const key = `${folder.dirs.join('|')}|${s.file}`;
      if (!w.asked.has(key)) {
        if (w.asked.size >= MAX_VETTED_PACKAGES) {
          maybeLocal.push(s.file);
          continue;
        }
        w.asked.add(key);
      }
    }
    for (const cand of scriptPaths(folder.dirs, s.file)) {
      if (asked) {
        const under = scriptUnder(w, cand.path, cand.dir);
        const probeKey = `${under}|${cand.path}`;
        let probe = w.probes.get(probeKey);
        if (probe === undefined) {
          probe = probeFile(under, cand.path);
          w.probes.set(probeKey, probe);
        }
        if (probe.kind === 'none') continue;
        local.add(s.file);
        ran = true;
        if (probe.kind === 'refused') {
          unread(file, probe.reason, true);
          continue;
        }
      }
      const read = readScript(w, cand, s.file);
      if (read === undefined || read.status === 'absent') continue;
      if (read.status === 'unreadable') {
        const why = read.reason ?? UNREADABLE_REASON;
        unread(read.file, why, askable(why));
        continue;
      }
      if (read.incomplete !== undefined) unread(read.file, read.incomplete, true);
      if (read.toolUv === true) {
        w.notes.push(`dev-guardian: ${read.file} may name its own index or sources ([tool.uv]) — what they serve was not verified.`);
        w.asks.push(`the inline dependencies of ${read.file} may come from its own index or sources ([tool.uv]) — what they serve was not vetted; allow it only if you trust this script`);
      }
      if (read.otherSource === true) {
        w.notes.push(`dev-guardian: ${read.file} names packages from a URL, a path or a VCS — they were not vetted.`);
        w.asks.push(`${read.file} names packages from a URL, a path or a VCS — they were not vetted; allow it only if you trust this script`);
      }
      if (read.packages.length === 0) continue;
      const custom = c.customRegistry ?? undefined;
      extra.push({
        ...base,
        packages: read.packages,
        skipped: [],
        uncertain: [NAMED_BY_MANIFEST],
        registries: c.registries,
        ...(custom !== undefined ? { customRegistry: custom } : {}),
        fromManifest: read.file,
      });
    }
  }
  if (c.sourced !== undefined && ran) {
    const line = `dev-guardian: ${said(c.sourced)} was run with source before the script and may have changed the directory or the environment — not checked.`;
    w.notes.push(line);
    w.withDeny.push(line);
  }
  if (local.size === 0 && maybeLocal.length === 0) return { command: c, extra };
  const here = c.packages.filter((p) => local.has(p.raw));
  const reasons: string[] = [];
  for (const word of maybeLocal) {
    if (word === c.runsAsScript) w.notes.push(runsAsFileLine(said(word)));
    else reasons.push(`\`${said(word)}\` may be a local script that pipx runs instead — not checked`);
  }
  const command: VetCommand = { ...c, packages: c.packages.filter((p) => !local.has(p.raw)), uncertain: [...c.uncertain, ...reasons] };
  if (here.length > 0) extra.unshift({ ...base, packages: here, skipped: [], uncertain: [], fromLocalScript: true });
  return { command, extra };
}

/** The lines and the question for the files past the eighth a call reads. */
function overflowScripts(w: ScriptWorld): void {
  const n = w.overflow.size;
  if (n === 0) return;
  w.notes.push(`dev-guardian: ${String(n)} more script file${n === 1 ? '' : 's'} of this command ${n === 1 ? 'was' : 'were'} not read (only the first ${String(MAX_SCRIPT_FILES)} are) — their packages were not vetted.`);
  w.asks.push(`this command runs more scripts than the hook reads — ${String(n)} ${n === 1 ? 'was' : 'were'} not read (only the first ${String(MAX_SCRIPT_FILES)} are); allow it only if you expected that`);
}

/**
 * The words of the hook's "could not vet … — not verified." line, which the
 * selftest (`selftest/hookChecks.ts`) recognises by these very constants: were
 * the line worded otherwise, the recognition would follow.
 */
export const COULD_NOT_VET = 'dev-guardian could not vet ';
export const NOT_VERIFIED = ' — not verified.';

/**
 * The reasons to ask the user, one per signal of {@link boundedInstalls} — the names of the commands past the
 * ceiling, the dependencies of the manifests past theirs, the cut at 512 KB — in that order, joined by `; `.
 * `undefined` when none holds. Fixed sentences with two integers and the ceilings: nothing of the project is in them.
 */
function askReason(signals: { notVetted: number; manifestNotVetted: number; cut: boolean }, scripts: readonly string[] = []): string | undefined {
  const verb = (n: number): string => (n === 1 ? '1 was' : `${String(n)} were`);
  const reasons: string[] = [];
  if (signals.notVetted > 0) {
    reasons.push(
      `this command names more packages than the hook vets — ${verb(signals.notVetted)} not vetted (only the first ${String(MAX_VETTED_PACKAGES)} are); allow it only if you expected a command this long`,
    );
  }
  if (signals.manifestNotVetted > 0) {
    reasons.push(
      `the manifests this command installs name more dependencies than the hook vets — ${verb(signals.manifestNotVetted)} not vetted (only the first ${String(MAX_MANIFEST_PACKAGES)} are); allow it only if you expected that`,
    );
  }
  if (signals.cut) {
    reasons.push('this command is longer than the hook reads — installs past the first 512 KB were not looked for; allow it only if you expected a command this long');
  }
  // The questions about the scripts, once each, in the order the line met them.
  reasons.push(...new Set(scripts));
  return reasons.length > 0 ? reasons.join('; ') : undefined;
}

/** The note for a command read only to its first 512 KB. */
const CUT_NOTE ='dev-guardian: installs past the first 512 KB of this command were not looked for — not verified.';

/**
 * `null` when there is nothing to say: no install command, or every package
 * vetted clean.
 */
export async function decideInstallCommand(command: string, opts: HookVetOptions): Promise<HookDecision | null> {
  const shell = opts.shell ?? 'bash';
  // A `CDPATH` in the environment: a bare `cd name` may go elsewhere.
  const env = opts.env ?? process.env;
  const cdpath = (env['CDPATH'] ?? '').trim() !== '';
  // One cache, shared by every command of the line and by the manifests'
  // scope lookups (review I4): each configuration file is read once.
  const registry: RegistryContext = {
    projectDir: opts.cwd,
    homeDir: opts.homeDir,
    env,
    etcDir: opts.etcDir,
    platform: opts.platform,
    nodeExecPath: opts.nodeExecPath,
    systemLibraryDir: opts.systemLibraryDir,
    cache: registryCache(),
  };
  // What a manifest could not tell: one line each, said whatever else happens.
  const manifestNotes: string[] = [];
  /** What the scripts of the line ask the user: a script that was not read, an index of its own, a source that is not the registry. */
  const scriptAsks: string[] = [];
  /** The lines of the scripts a deny carries too. */
  const scriptDenyLines: string[] = [];
  /** The lockfiles of the manifest installs of the line, read. */
  const locked: LockedProject[] = [];
  const isPopular = popularTest(opts);
  // One deadline for the whole call (review I4).
  const deadlineAt = opts.deadlineAt ?? (opts.startedAt ?? Date.now()) + vetDeadlineMs(env);
  // One lookup per directory and name, however many statements of the line name them (review round 2: 8 000 x `npx lodash;`).
  const localCopies = new Map<string, boolean>();
  // What the disk said of the spelling of a folder: asked once per folder in this call, whatever the commands (install-vet-path-forms).
  const spelling: SpellingMemo = new Map();
  /** What the disk could not say about the words of `dotnet new install`: one line each, said whatever else happens. */
  const diskNotes = new Set<string>();
  const { commands, notVetted, manifestNotVetted, cut, unassessed } = boundedInstalls(
    command,
    shell,
    isPopular,
    (pkg, c) => runsInstalledCopy(pkg, c, opts, localCopies, spelling),
    opts.nested,
    cdpath,
    (parsed) => withManifestPackages(parsed, opts, registry, manifestNotes, locked, { asks: scriptAsks, withDeny: scriptDenyLines }, () => Date.now() > deadlineAt, spelling),
    () => Date.now() > deadlineAt,
    (c) => withoutDiskEntries(c, opts, () => Date.now() > deadlineAt, diskNotes, spelling),
    (pkg, c) => copyNotLookedFor(pkg, c, opts),
  );
  // A cut command whose start installs nothing still says what was not read — and so does a manifest that was not.
  if (commands.length === 0 && locked.length === 0) {
    const said = [...manifestNotes, ...(cut ? [CUT_NOTE] : [])];
    if (said.length === 0) return null;
    const question = askReason({ notVetted, manifestNotVetted, cut }, scriptAsks);
    return question === undefined ? { context: said.join('\n') } : { context: said.join('\n'), ask: question };
  }

  const offline = env['GUARDIAN_OFFLINE'] === '1';
  const budgetMs = opts.budgetMs ?? HOOK_BUDGET_MS;
  const now = opts.now ?? Date.now();
  // The pairs the lockfiles pin, asked at once and beside the registry path: both share the budget and the deadline.
  const pairs = choosePins(
    locked.flatMap((l) => l.asked),
    {
      direct: new Set(locked.flatMap((l) => l.direct)),
      popular: (name) => isPopular({ ecosystem: 'npm', name, raw: name }),
    },
  );
  const pinned = vetPins(pairs.chosen, {
    budgetMs,
    offline,
    deadlineAt,
    now,
    ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
  });
  const [batches, verdicts] = await Promise.all([
    Promise.all(
      commands.map((c) =>
        vetPackages(c.packages, {
          budgetMs,
          offline,
          deadlineAt,
          now,
          registry: { ...registry, command: registryCommand(c) },
          commandRegistries: c.registries,
          // A manifest's packages are told neither of a fresh version nor of install scripts (`decideManifestOne`):
          // what only those two checks need is not asked of the registry.
          // The names given to an update are told neither of them: an update repeats them at every run.
          ...(c.fromManifest !== undefined || c.fromUpdate === true ? { unreported: MANIFEST_UNREPORTED } : {}),
          ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
          ...(opts.popularDir !== undefined ? { popularDir: opts.popularDir } : {}),
          ...(opts.popular !== undefined ? { popular: opts.popular } : {}),
        }),
      ),
    ),
    pinned,
  ]);
  const denies: string[] = [];
  const manifestDenies: string[] = [];
  const warnings: string[] = [];
  const unverified: string[] = [];
  /** Per manifest file: how many of its packages could not be vetted, and the first reason. */
  const unverifiedIn = new Map<string, { count: number; why: string }>();
  const lockLines: string[] = [];
  /** What the lockfiles left unvetted (counts, one sentence each): said with a deny too. */
  const lockCounts: string[] = [];
  const lockDenies = new Set<string>();
  let malicious = false;
  let missingIn: InstallCommand | undefined;
  // What the lockfiles say. An exception here is one more lockfile not read — the hook stays fail-open.
  const verdictOf = new Map(verdicts.map((v) => [pairKey(v.pin), v] as const));
  const counted = new Set<string>();
  const warnedCovered = new Set<string>();
  // The plain missing-name warnings of manifests: the first of the answer are listed, the others counted per file.
  let missingListed = 0;
  const missingCounted = new Map<string, number>();
  const warnOfManifest = (d: { warn?: string; plainMissing?: true }, file: string): void => {
    if (d.warn === undefined) return;
    if (d.plainMissing === true) {
      if (missingListed >= MAX_MANIFEST_MISSING_LINES) {
        missingCounted.set(file, (missingCounted.get(file) ?? 0) + 1);
        return;
      }
      missingListed += 1;
    }
    warnings.push(d.warn);
  };
  for (const lock of locked) {
    try {
      // Two installs of one line may read one manifest twice: a covered dependency is judged once.
      const covered = lock.covered.filter((pkg) => !warnedCovered.has(`${lock.manifestFile}\0${pkg.name}\0${pkg.range ?? ''}`));
      for (const pkg of covered) warnedCovered.add(`${lock.manifestFile}\0${pkg.name}\0${pkg.range ?? ''}`);
      for (const r of vetTyposquatOnly(covered, {
        ...(opts.popularDir !== undefined ? { popularDir: opts.popularDir } : {}),
        ...(opts.popular !== undefined ? { popular: opts.popular } : {}),
      })) {
        warnOfManifest(decideManifestOne(r, lock.manifestFile), lock.manifestFile);
      }
      const outcome = lockOutcome(lock, verdictOf, counted);
      for (const text of outcome.denies) lockDenies.add(text);
      lockLines.push(...outcome.lines);
      lockCounts.push(...outcome.lines);
    } catch {
      lockLines.push(notReadLine(lock.file, 'could not be read'));
    }
  }
  if (lockDenies.size > 0) {
    manifestDenies.push(...[...lockDenies].slice(0, MAX_NAMED_DENIES));
    const more = lockDenies.size - MAX_NAMED_DENIES;
    if (more > 0) manifestDenies.push(`and ${more} more pair${more === 1 ? '' : 's'} of the lockfiles have a malicious-package advisory.`);
  }
  commands.forEach((cmd, i) => {
    for (const r of batches[i] ?? []) {
      if (cmd.fromManifest !== undefined) {
        const d = decideManifestOne(r, cmd.fromManifest);
        if (d.deny !== undefined) manifestDenies.push(d.deny);
        warnOfManifest(d, cmd.fromManifest);
        if (d.unverified !== undefined) {
          const sofar = unverifiedIn.get(cmd.fromManifest);
          unverifiedIn.set(cmd.fromManifest, { count: (sofar?.count ?? 0) + 1, why: sofar?.why ?? d.unverified });
        }
        continue;
      }
      // The word of `pipx run` that is a file the pipx runs, or a word the pipx reads as a file: only a package of that name that is malicious is said.
      if (cmd.fromLocalScript === true || cmd.fromArchiveFile === true) {
        if (r.checks.malicious.status === 'fail') {
          denies.push(cmd.fromLocalScript === true ? localScriptDeny(r) : archiveFileDeny(r));
          malicious = true;
        }
        continue;
      }
      const d = cmd.fromUpdate === true ? decideUpdateOne(r) : decideOne(r, cmd.uncertain);
      if (d.deny !== undefined) denies.push(d.deny);
      if (d.malicious === true) malicious = true;
      else if (d.deny !== undefined) missingIn = missingIn ?? cmd;
      if (d.warn !== undefined) warnings.push(d.warn);
      if (d.unverified !== undefined) unverified.push(d.unverified);
    }
  });

  if (denies.length > 0 || manifestDenies.length > 0) {
    const parts: string[] = [];
    if (denies.length > 0) {
      parts.push(
        `${denies.join(' ')} ` +
          'Check the package name against the project documentation or the registry before installing anything. ' +
          // Controller ruling (round 2): a missing-name deny carries its own
          // escape hatch — a registry flag, or an inline prefix, takes the
          // command out of the confident shape, so the agent can always
          // proceed. A MALICIOUS package gets no such hint.
          (malicious ? 'If this package is genuinely intended, ask the user to install it themselves.' : escapeHatch(missingIn?.manager ?? '', shell, missingIn?.sourceFlag)),
      );
    }
    if (manifestDenies.length > 0) {
      // A manifest names it, so the command names nothing to correct: no hint
      // of a way round, and the decision is handed to the user with the file.
      parts.push(
        `${manifestDenies.join(' ')} ` +
          "Installing it or removing the dependency is the user's decision: tell them which file names it, and install nothing from that manifest until they have decided.",
      );
    }
    // The counts of what was not vetted come after the sentences — the advisory received stands even when a batch failed.
    // The other lines (another source, not recognised, …) stay out of a deny: they do not change it, and the deny stays short.
    const counts = [...new Set([...lockCounts, ...scriptDenyLines])];
    // The one note that rides in the refusal of a missing name: a file of the project sets the default registry and was said, though it
    // did not explain the name (a value the reader cannot judge, a workspace root it cannot tell). It is in the text because the dispatcher
    // answers a deny with its reason alone. The deny of a malicious name stays short.
    const registryLines = malicious ? [] : [...new Set(manifestNotes.filter(isDefaultRegistryLine))];
    const tail = [...counts, ...registryLines];
    const deny = `dev-guardian blocked this install: ${parts.join(' ')}${tail.length > 0 ? `\n${tail.join('\n')}` : ''}`;
    // The lines of what was not read stay beside the refusal (the dispatcher answers a deny with its reason alone): a file of one folder that
    // could not be read says so even when the file of the other folder is what is refused.
    const unreadLines = [...new Set(manifestNotes.filter((n) => n.includes(' was not read (')))];
    return unreadLines.length === 0 ? { deny } : { deny, context: unreadLines.join('\n') };
  }
  const lines: string[] = [];
  if (warnings.length > 0) {
    lines.push('⚠️ dev-guardian package vetting — review before relying on these:');
    for (const w of warnings) lines.push(`  • ${w}`);
  }
  if (missingCounted.size > 0) lines.push(missingCountLine(missingCounted));
  if (unverified.length > 0) lines.push(`${COULD_NOT_VET}${unverified.join(', ')}${NOT_VERIFIED}`);
  for (const [file, { count, why }] of unverifiedIn) {
    lines.push(`${COULD_NOT_VET}${plural(count)} of ${file} (${why})${NOT_VERIFIED}`);
  }
  // Two installs of one line may read one lockfile twice: a line is said once.
  lines.push(...new Set([...lockLines, ...manifestNotes, ...diskNotes]));
  if (unassessed > 0) {
    lines.push(
      `dev-guardian: ${unassessed} launcher commands of this line were not checked for a copy in the project (vetting time budget exhausted) — their packages were vetted as if fetched.`,
    );
  }
  if (notVetted > 0) {
    lines.push(
      `dev-guardian: ${notVetted} more packages in this command were not vetted (only the first ${MAX_VETTED_PACKAGES} are) — not verified.`,
    );
  }
  if (manifestNotVetted > 0) {
    lines.push(
      `dev-guardian: ${manifestNotVetted} more packages of the manifest were not vetted (only the first ${MAX_MANIFEST_PACKAGES} are) — not verified.`,
    );
  }
  if (cut) lines.push(CUT_NOTE);
  if (lines.length === 0) return null;
  const question = askReason({ notVetted, manifestNotVetted, cut }, scriptAsks);
  return question === undefined ? { context: lines.join('\n') } : { context: lines.join('\n'), ask: question };
}

const NOT_FOUND = 'not found on the public registry — if it is private or local, ignore this.';

/** The flag that names a registry, per package manager (`InstallCommand.manager`). */
const REGISTRY_FLAG: Readonly<Record<string, string>> = {
  npm: '`--registry <url>`',
  npx: '`--registry <url>`',
  pipx: '`--index-url <url>`',
  pnpm: '`--registry <url>`',
  bun: '`--registry <url>`',
  pip: '`--index-url <url>`',
  'uv-pip': '`--index-url <url>`',
  uv: '`--index <url>`',
  poetry: '`--source <name>`',
  dotnet: '`--source <url>`',
};

/** Tools with no registry flag to name one with (Yarn classic has one, Berry has not; neither form can be told apart here). */
const NO_REGISTRY_FLAG: Readonly<Record<string, string>> = {
  yarn: 'Yarn Berry has no registry flag',
  composer: 'composer has no registry flag',
};

/**
 * The missing-name deny's own escape hatch (controller ruling, round 2): a way
 * to re-run the install that takes it out of the plain shape, so the agent can
 * always proceed. It names what the tool really has — a registry flag, or
 * (composer, Yarn Berry) none — and an inline `GUARDIAN_PKG_VET=0`, spelled
 * for the shell: a `VAR=x` prefix for bash, `$env:` for PowerShell. Neither
 * touches the hook's own switch; a malicious version is still denied.
 */
export function escapeHatch(manager: string, shell: CommandShell = 'bash', sourceFlag?: string): string {
  const prefix =
    shell === 'powershell'
      ? "run `$env:GUARDIAN_PKG_VET = '0'` before it, in the same command"
      : 'prefix the command with `GUARDIAN_PKG_VET=0`';
  // The flag the refused command's own form has comes first: `dotnet new install` has `--add-source`, not `--source`.
  const flag = sourceFlag ?? REGISTRY_FLAG[manager];
  if (flag !== undefined) return `If this package is private or local, re-run the install with an explicit ${flag}, or ${prefix}.`;
  const none = NO_REGISTRY_FLAG[manager];
  return `If this package is private or local, ${prefix}${none !== undefined ? ` (${none})` : ''}.`;
}

const CHECK_KEYS: ReadonlyArray<keyof PackageChecks> = [
  'exists',
  'malicious',
  'vulnerabilities',
  'publish_age',
  'install_scripts',
  'typosquat',
];

/** The checks of "the version that installs": with no such version there is nothing for them to look at. */
const VERSION_CHECKS: ReadonlySet<keyof PackageChecks> = new Set<keyof PackageChecks>(['vulnerabilities', 'publish_age', 'install_scripts']);

function sentence(text: string): string {
  return /[.?!]$/.test(text) ? text : `${text}.`;
}

/**
 * One package a MANIFEST names, in the hook's answer — a narrower rule than
 * {@link decideOne}'s, because a manifest is installed at every `npm
 * install` and what it names was not typed by anyone just now:
 *
 *   - malicious (OSV `MAL-` on the version its range resolves to, npm's
 *     takedown placeholder) → deny, with the file that names it;
 *   - missing from the public registry → a warning, never a deny: a missing
 *     name in a manifest is usually a private or a workspace package, and a
 *     deny would stop every install of the project. `plainMissing` says the
 *     warning is that one and carries no "Did you mean": the caller lists the
 *     first {@link MAX_MANIFEST_MISSING_LINES} of an answer and counts the rest;
 *   - a typosquat suspicion → a warning;
 *   - a fresh version, install scripts, known vulnerabilities, an exact
 *     version nobody published → nothing: said once at `npm install <name>`,
 *     they would be said at every install here (`deps_audit` reads the
 *     manifest and the lockfile for vulnerabilities);
 *   - the lookup or the malware check could not run → counted, for the one
 *     line that says how many packages of the file were not verified.
 *
 * Nothing of the manifest is in the text but the file's name, the package's
 * name and a version: `manifest.ts` lets nothing else through.
 */
function decideManifestOne(
  r: PackageVetResult,
  file: string,
): { deny?: string; warn?: string; plainMissing?: true; unverified?: string } {
  if (r.checks.malicious.status === 'fail') {
    const why = Object.values(r.checks)
      .filter((c) => c.status === 'fail' && c.detail !== undefined)
      .map((c) => c.detail ?? '')
      .join('; ');
    return { deny: `${file} names '${label(r)}': ${sentence(why)}` };
  }
  if (r.not_on_public_registry === true) {
    const didYouMean = r.similar_to !== undefined ? ` Did you mean '${r.similar_to}'?` : '';
    const why = r.verdict === 'block' ? `not denied: ${NAMED_BY_MANIFEST}` : (r.checks.exists.detail ?? '');
    return {
      warn: `${file}: '${label(r)}': ${NOT_FOUND}${didYouMean} (${why})`,
      ...(r.similar_to === undefined ? { plainMissing: true as const } : {}),
    };
  }
  const out: { warn?: string; unverified?: string } = {};
  const typo = r.checks.typosquat;
  if (typo.status === 'warn' && typo.detail !== undefined) out.warn = `${file}: ${label(r)}: ${typo.detail}`;
  const unknown = [r.checks.exists, r.checks.malicious].find((c) => c.status === 'unknown' && c.detail !== undefined);
  if (unknown !== undefined) out.unverified = unknown.detail ?? '';
  return out;
}

/** The sentence for a malicious package whose name is a word the pipx takes for a file: `lead` says which file and why, and nothing else of the word is said. */
function maliciousFileDeny(lead: string, r: PackageVetResult): string {
  const why = Object.values(r.checks)
    .filter((c) => c.status === 'fail' && c.detail !== undefined)
    .map((c) => c.detail ?? '')
    .join('; ');
  return `${lead} a package of that name is malicious: '${label(r)}': ${sentence(why)}`;
}

/** The sentence for a malicious package whose name is a local file `pipx run` runs: the hook saw the file. */
const localScriptDeny = (r: PackageVetResult): string => maliciousFileDeny(`pipx runs the local file '${r.name}' here, and`, r);

/** The sentence for a malicious package whose name is a word the pipx reads as a file (`pipx install <word>`, `pipx run <word>`): the hook did not see one. */
const archiveFileDeny = (r: PackageVetResult): string => maliciousFileDeny(`pipx reads '${r.name}' as a file here, not as a package, and`, r);

/**
 * One name given to an update verb, in the hook's answer. It is typed on the command line, so a malicious package is denied
 * as {@link decideOne} does; but an update fetches a package only when it is installed already, so a name the registry does not
 * have is never a deny — it is a warning that says why. A typosquat suspicion is a warning too; a fresh version, install scripts
 * and known vulnerabilities are not said (an update repeats them at every run); a lookup that could not run is the "could not vet" line.
 */
function decideUpdateOne(r: PackageVetResult): { deny?: string; malicious?: boolean; warn?: string; unverified?: string } {
  if (r.checks.malicious.status === 'fail') {
    const why = Object.values(r.checks)
      .filter((c) => c.status === 'fail' && c.detail !== undefined)
      .map((c) => c.detail ?? '')
      .join('; ');
    return { deny: `'${label(r)}': ${sentence(why)}`, malicious: true };
  }
  if (r.not_on_public_registry === true) {
    const didYouMean = r.similar_to !== undefined ? ` Did you mean '${r.similar_to}'?` : '';
    return { warn: `'${label(r)}': ${NOT_FOUND}${didYouMean} (${NAMED_TO_UPDATE})` };
  }
  const out: { warn?: string; unverified?: string } = {};
  const typo = r.checks.typosquat;
  if (typo.status === 'warn' && typo.detail !== undefined) out.warn = `${label(r)}: ${typo.detail}`;
  const unknown = [r.checks.exists, r.checks.malicious].find((c) => c.status === 'unknown' && c.detail !== undefined);
  if (unknown !== undefined) out.unverified = `${label(r)} (${unknown.detail ?? ''})`;
  return out;
}

/**
 * One package's contribution to the hook's answer.
 *
 *   - malicious (OSV `MAL-` on the version, npm takedown placeholder) → deny, always;
 *   - missing from the public registry → deny ONLY when the vetting found
 *     nothing to explain it (it is `block`, not `unknown`) AND the command
 *     has the confident shape (`uncertain` is empty, bar the reasons the confident-shape
 *     filter keeps: an archive-like name of an unmeasured manager, or of the pipx
 *     and the composer outside the form measured, and the two readings of a
 *     `key@npm:rest`); otherwise the ruling's
 *     "not found … ignore this" warning, with the reason;
 *   - every other `warn` check, except known vulnerabilities on a version
 *     the user did not pin exactly (M4: for a range or a bare name the
 *     installed version is not known here — the tool still reports them);
 *   - checks that could not run → the one-line "not verified" note — also
 *     beside a warning: a package with a typosquat suspicion whose registry
 *     did not answer is told both ways, as {@link decideManifestOne} does.
 *     Not for the three checks ({@link VERSION_CHECKS}) an unpublished exact
 *     version leaves without a version to look at: its warning says that.
 */
function decideOne(
  r: PackageVetResult,
  uncertain: readonly string[],
): { deny?: string; malicious?: boolean; warn?: string; unverified?: string } {
  if (r.checks.malicious.status === 'fail') {
    const why = Object.values(r.checks)
      .filter((c) => c.status === 'fail' && c.detail !== undefined)
      .map((c) => c.detail ?? '')
      .join('; ');
    return { deny: `'${label(r)}': ${sentence(why)}`, malicious: true };
  }
  if (r.not_on_public_registry === true) {
    if (r.verdict === 'block' && uncertain.length === 0) {
      return { deny: `'${label(r)}': ${sentence(r.checks.exists.detail ?? firstLine(r))}` };
    }
    const didYouMean = r.similar_to !== undefined ? ` Did you mean '${r.similar_to}'?` : '';
    const why = r.verdict === 'block' ? `not denied: ${uncertain.join('; ')}` : (r.checks.exists.detail ?? '');
    return { warn: `'${label(r)}': ${NOT_FOUND}${didYouMean} (${why})` };
  }

  const pinned = isExactVersion(r.ecosystem, r.requested);
  const warns = CHECK_KEYS.filter((key) => key !== 'vulnerabilities' || pinned)
    .map((key) => r.checks[key])
    .filter((c) => c.status === 'warn' && c.detail !== undefined)
    .map((c) => c.detail ?? '');
  if (r.requested_version_unpublished === true) {
    warns.push(`requested version ${r.requested ?? ''} is not published — possibly a hallucinated version`);
  }
  const out: { warn?: string; unverified?: string } = {};
  if (warns.length > 0) out.warn = `${label(r)}: ${warns.slice(0, 3).join('; ')}`;
  // A warning does not hide a check that could not run: the note says the rest was not verified. An exact version
  // nobody published is the exception its own warning states — the checks of "the version that installs" have no
  // version to look at, which is not a lookup that failed. Every other check still counts: the malware lookup
  // (asked by name), the typosquat check.
  const couldRun =
    r.requested_version_unpublished === true ? CHECK_KEYS.filter((key) => !VERSION_CHECKS.has(key)).map((key) => r.checks[key]) : Object.values(r.checks);
  const unknownCheck = couldRun.find((c) => c.status === 'unknown' && c.detail !== undefined);
  if (unknownCheck !== undefined) out.unverified = `${label(r)} (${unknownCheck.detail ?? ''})`;
  return out;
}
