/**
 * The pack registry: which rule pack is ablated against which corpora.
 *
 * Axis 3 (does the clause raise the finding count on code nobody wrote as a
 * fixture?) needs a real-code corpus in a language the pack matches. That is
 * a property of the INVOCATION, recorded here per pack and overridable from
 * the command line, not a special case buried inside the harness: `mcp/src`
 * is the only large body of not-written-as-a-fixture code IN this repo, and
 * it is TypeScript, so the JS/TS pack is the only one whose corpus can be a
 * committed path.
 *
 * The Rust pack's corpus is the one exception, and it is opt-in rather than
 * absent. Rust's standard library source is ~1400 `.rs` files nobody wrote as
 * a fixture, it is free (`rustup component add rust-src`, or copied out of
 * `<toolchain>/lib/rustlib/src/rust/library` in the `rust:1.79-alpine`
 * image after adding the component), and in the Rust probe it is what turned
 * "three rules ship" into "one": `mem-forget` scored 43 findings and zero
 * true positives on it, and `unwrap-in-drop` was found accusing the canonical
 * mitigation it is supposed to prescribe. Both had clean fixtures and would
 * have shipped under a C#-style round, where axis 3 was permanently N/A.
 *
 * It cannot be a committed path — the standard library does not belong in
 * this tree — so it is read from `GUARDIAN_RUST_SRC`. Unset, axis 3 reports
 * `N/A` for the pack, loudly, the same way it does for every pack with no
 * corpus. Set to a path that does not exist, it THROWS rather than degrading
 * to N/A: a typo'd corpus that silently becomes "not measured" is the exact
 * shape of failure this harness exists to prevent.
 *
 * KNOW WHAT THIS CORPUS IS WEAK AT, because a PASS on it is not the same
 * strength of evidence for every rule. Measured on the 1.79 library tree:
 * 1201 files scanned, and only **14 of them contain the string `async fn`**.
 * So for `blocking-sleep-in-async` — the only rule the pack currently has —
 * axis 3 is close to vacuous: the baseline is 0 findings and every clause
 * passes trivially, because there is barely any async Rust for the rule to be
 * wrong about. The corpus earned its keep against `mem-forget` and
 * `unwrap-in-drop`, which are about ownership and `Drop`, and the standard
 * library is saturated with both. A future async rule wanting real axis-3
 * evidence needs a corpus of async Rust, which this is not.
 *
 * `base.yml` does contain JS/TS rules and would accept `mcp/src` as a corpus;
 * it is left off by default only because nobody has read that baseline yet.
 * Turn it on with `--real-code=../mcp/src` when someone is ready to triage
 * whatever it reports.
 *
 * `routes.yml` is deliberately absent: it is a route-inventory pack with no
 * `hits/` + `misses/` fixture pair, so axes 1 and 2 have nothing to measure
 * against. Give it a fixture corpus and it belongs here like the rest.
 */

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PackSpec, RealCorpus } from './harness.js';

/** `<repo>/mcp/test/ablate/packs.ts` -> `<repo>`. */
export const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));

const config = (name: string): string => resolve(REPO_ROOT, 'configs', 'semgrep', `${name}.yml`);
const fixtures = (name: string): string => resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', name);

/** Real-code corpus for the JS/TS pack: this repo's own server sources. */
export const MCP_SRC = { label: 'mcp/src', dir: resolve(REPO_ROOT, 'mcp', 'src') } as const;

/** Env var naming the Rust standard-library source tree, for axis 3. */
export const RUST_SRC_ENV = 'GUARDIAN_RUST_SRC';

/**
 * Axis-3 corpus for the Rust pack, or `undefined` when the env var is unset —
 * in which case the harness prints axis 3 as `N/A` for the pack, which is a
 * verdict rather than a silent skip. A path that is set but missing is an
 * error, not an N/A: see the file header.
 */
export function rustStdlibCorpus(): RealCorpus | undefined {
  const dir = process.env[RUST_SRC_ENV];
  if (dir === undefined || dir.trim() === '') return undefined;
  const abs = resolve(dir.trim());
  if (!existsSync(abs)) {
    throw new Error(
      `${RUST_SRC_ENV} is set to ${abs}, which does not exist. Unset it to run ` +
        `bugfix-rs with axis 3 as N/A, or point it at a rust-src library tree.`,
    );
  }
  return { label: 'rust-src (standard library)', dir: abs };
}

const RUST_STDLIB = rustStdlibCorpus();

export const PACKS: readonly PackSpec[] = [
  {
    name: 'bugfix-js',
    config: config('bugfix-js'),
    fixtures: fixtures('bugfix-js'),
    hitsSubdir: 'hits',
    realCode: MCP_SRC,
  },
  { name: 'bugfix-py', config: config('bugfix-py'), fixtures: fixtures('bugfix-py'), hitsSubdir: 'hits' },
  { name: 'bugfix-go', config: config('bugfix-go'), fixtures: fixtures('bugfix-go'), hitsSubdir: 'hits' },
  { name: 'bugfix-java', config: config('bugfix-java'), fixtures: fixtures('bugfix-java'), hitsSubdir: 'hits' },
  { name: 'bugfix-cs', config: config('bugfix-cs'), fixtures: fixtures('bugfix-cs'), hitsSubdir: 'hits' },
  {
    name: 'bugfix-rs',
    config: config('bugfix-rs'),
    fixtures: fixtures('bugfix-rs'),
    hitsSubdir: 'hits',
    realCode: RUST_STDLIB,
  },
  { name: 'base', config: config('base'), fixtures: fixtures('base'), hitsSubdir: 'hits' },
];

export function packByName(name: string): PackSpec | undefined {
  return PACKS.find((p) => p.name === name);
}

export function packNames(): string[] {
  return PACKS.map((p) => p.name);
}
