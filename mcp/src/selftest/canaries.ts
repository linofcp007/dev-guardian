// @ts-nocheck -- Phase 4 scaffold (dev-spec-driven): the failing tests come first; the implementation replaces these bodies.
/**
 * The selftest's temporary project: made, seeded with the canaries, removed.
 *
 * The canaries ship with the plugin in `configs/selftest/`, every one under a
 * name that ends in `.canary` — no file there has a code extension or a
 * manifest's name, so neither the repository's own scanners nor a host that
 * indexes it reads them as code (`project/deps/package-lock.json.canary` is
 * not a lockfile to anything). Seeding copies `project/**` into the temporary
 * project with the suffix dropped; the probe rule goes beside it, outside the
 * scanned tree.
 *
 * The secret canary is not a file: it is put together here, at run time, from
 * two halves, so that neither the repository nor the bundle holds the whole
 * string, and it is written only into the temporary project. It has the
 * format of an AWS access key id and is no key anyone was issued.
 *
 * The directory is made by `mkdtemp` — an unpredictable name that fails if it
 * exists, private to the user where the system has modes — and is removed
 * without following a link out of it, after checking that the path still is
 * the directory this run made.
 */

import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative, sep } from 'node:path';

/** What every temporary directory of a selftest is named after: recognisable when one is left behind. */
export const WORKSPACE_PREFIX = 'dev-guardian-selftest-';
/** The suffix every shipped canary carries, dropped when it is seeded. */
export const CANARY_SUFFIX = '.canary';
/** Where the secret canary goes in a seeded file. */
export const TOKEN_PLACEHOLDER = '@@SELFTEST_TOKEN@@';
/** The probe rule as shipped, and as the probe run is given it. */
export const PROBE_RULE_SOURCE = 'probe.yml.canary';
export const PROBE_RULE_FILE = 'probe.yml';
/** The marker every Semgrep canary carries in a comment, which the probe rule matches. */
export const CANARY_MARKER = 'dev-guardian-selftest-canary';
/** A directory of an earlier selftest counts as left behind once it is this old. */
const LEFTOVER_AFTER_MS = 60 * 60 * 1000;

// The two halves of the secret canary. Joined only by `canaryToken()`.
const TOKEN_HALVES: readonly string[] = ['@@TOKEN_HEAD@@', '@@TOKEN_TAIL@@'];

/** The synthetic secret: valid for the rules that look for an AWS access key id, issued to no one. */
export function canaryToken(): string {
  throw new Error('selftest: not implemented');
}

export interface Workspace {
  /** The directory this run made; everything else is below it. */
  dir: string;
  /** The seeded project: what every scanner is pointed at. */
  project: string;
  /** Where the scanners write their reports: inside the project, as a real scan's are. */
  reports: string;
  /** The probe rule's directory, outside the scanned tree. */
  rules: string;
  /** The directory's identity when it was made, checked before it is removed. */
  ino: number;
}

/** A new, empty, private directory under `tmpRoot`. Throws when it cannot be made. */
export function createWorkspace(tmpRoot: string = tmpdir()): Workspace {
  throw new Error('selftest: not implemented');
}

/** Every file below `dir`, relative, with forward slashes. Links are listed, never followed. */
function filesBelow(dir: string, base: string = dir): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...filesBelow(path, base));
    else out.push(relative(base, path).split(sep).join('/'));
  }
  return out.sort();
}

/**
 * Copy the shipped canaries into the workspace: `project/**` with the suffix
 * dropped and the secret put where its placeholder is, and the probe rule
 * beside the project. Returns the seeded paths, relative to the project, with
 * forward slashes. Throws when the canaries are not there: an install without
 * them cannot be tested, and that is not a verdict of any control.
 */
export function seedCanaries(canariesDir: string, ws: Workspace): string[] {
  throw new Error('selftest: not implemented');
}

/** Whether `rel` (relative to the project, forward slashes) is a file in the seeded project now. */
export function canaryPresent(ws: Workspace, rel: string): boolean {
  throw new Error('selftest: not implemented');
}

/**
 * Remove the workspace and everything in it. A link inside it is removed as a
 * link: what it points at stays. Refuses a path that is no longer the
 * directory this run made. Throws when anything is left.
 */
export function removeWorkspace(ws: Workspace): void {
  throw new Error('selftest: not implemented');
}

/** Directories of earlier selftests still under `tmpRoot`, old enough not to be a run in progress. Never removed here. */
export function leftoverWorkspaces(tmpRoot: string, own: string, now: number = Date.now()): string[] {
  throw new Error('selftest: not implemented');
}
