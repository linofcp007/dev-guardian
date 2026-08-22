/**
 * `deriveTestCommand` — which command proves the project's own tests still
 * pass after a fix has been applied (design doc
 *
 * Pure: manifest CONTENTS in, one of four known commands out, or `null`. No
 * git, no process, no filesystem — `create_fix_pr` reads `TEST_MANIFESTS` off
 * disk and hands whichever ones exist to `deriveTestCommand`.
 *
 * The property this module exists to hold: manifest TEXT never becomes argv.
 * `scripts.test`, a `[tool.pytest]` table — these only ever SELECT one of the
 * four fixed commands below; their content is inspected (parsed, matched,
 * measured) but never copied into `command` or `args`. Accepting a
 * `test_command` string parameter instead of deriving it would reopen the
 * hazard the DAST work closed: an agent fills a tool's parameters from a
 * context that includes the repository under analysis, so an injected
 * instruction sitting in a README would have somewhere to point. A malicious
 * `scripts.test` can only ever select `npm test`; it can never become argv.
 */

export interface DerivedTestCommand {
  command: string;
  args: string[];
  /** Where it came from — rendered into the PR body. */
  origin: string;
}

/**
 * npm's own placeholder, written by `npm init`. It exits 1 on every project
 * that has not added real tests — running it would report all of them as a
 * broken build, which is worse than not verifying at all.
 */
const NPM_PLACEHOLDER_TEST_SCRIPT = 'echo "Error: no test specified" && exit 1';

/**
 * A `[tool.pytest]` table header, or a nested one such as
 * `[tool.pytest.ini_options]` — allowing the indentation some formatters add.
 * No `g`/`y` flag: this pattern is reused across calls via `.test()`, and a
 * stateful flag would advance `lastIndex` after a match and silently miss it
 * on a later call against the same input.
 *
 * A pyproject.toml with no such table proves nothing about how the project
 * is tested — it is also the config file for Poetry, Hatch, black, ruff and
 * mypy, none of which imply pytest.
 */
const PYTEST_SECTION = /^[ \t]*\[tool\.pytest(?:\.|\])/m;

type Checker = (content: string) => DerivedTestCommand | null;

// Order is precedence: the first manifest present whose content yields a
// command wins over one that is merely present but unusable (e.g. package.json
// with no real test script) or absent. TEST_MANIFESTS is derived FROM this
// list below, so the two can never drift apart.
const CHECKERS: ReadonlyArray<readonly [string, Checker]> = [
  ['package.json', fromPackageJson],
  ['Cargo.toml', fromCargoToml],
  ['go.mod', fromGoMod],
  ['pyproject.toml', fromPyprojectToml],
];

/** The manifests deriveTestCommand knows how to read. The caller reads exactly these. */
export const TEST_MANIFESTS: readonly string[] = CHECKERS.map(([name]) => name);

export function deriveTestCommand(files: Readonly<Record<string, string>>): DerivedTestCommand | null {
  for (const [name, check] of CHECKERS) {
    const content = files[name];
    // Presence, not truthiness: an empty-but-present Cargo.toml or go.mod
    // still means "this is a cargo/go project" and must not be skipped as if
    // the manifest were missing — the same falsy-vs-absent shape this
    // project has been bitten by before, just at the file level instead of a
    // field inside one.
    if (content === undefined) continue;
    const derived = check(content);
    if (derived !== null) return derived;
  }
  return null;
}

// --------------------------------------------------------------- package.json

function fromPackageJson(content: string): DerivedTestCommand | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }

  const scripts = asRecord(asRecord(parsed)?.['scripts']);
  const test = scripts?.['test'];
  if (typeof test !== 'string') return null;

  // Falsy check, not `??`: an empty or whitespace-only scripts.test is
  // exactly as unusable as a missing one, and `??` only treats null/undefined
  // as "absent" — it would let '' straight through untouched. Trimmed, so a
  // whitespace-only script does not slip past either.
  const trimmed = test.trim();
  if (trimmed.length === 0 || trimmed === NPM_PLACEHOLDER_TEST_SCRIPT) return null;

  // `test` (and `trimmed`) selected this branch; neither appears below.
  // `npm test` runs whatever scripts.test actually says — that is the
  // project's own business — but the string itself never reaches our argv.
  return { command: 'npm', args: ['test', '--silent'], origin: 'package.json scripts.test' };
}

/**
 * A plain, non-null, non-array object — or `undefined` for anything else,
 * including `null`, where the classic `typeof null === 'object'` trap would
 * otherwise let it through and throw on the next property read.
 */
function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

// --------------------------------------------------------------- cargo / go

function fromCargoToml(): DerivedTestCommand {
  return { command: 'cargo', args: ['test'], origin: 'Cargo.toml' };
}

function fromGoMod(): DerivedTestCommand {
  return { command: 'go', args: ['test', './...'], origin: 'go.mod' };
}

// --------------------------------------------------------------- pyproject.toml

function fromPyprojectToml(content: string): DerivedTestCommand | null {
  if (!PYTEST_SECTION.test(content)) return null;
  return { command: 'pytest', args: [], origin: 'pyproject.toml [tool.pytest]' };
}
