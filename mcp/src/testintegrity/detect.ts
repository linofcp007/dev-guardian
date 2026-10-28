/**
 * Tests weakened by a change — what an agent asked to "make the tests pass"
 * does when it cannot: skip the failing test, focus the one that passes,
 * delete the file, drop the assertions, or make the test script exit 0
 * whatever happens. Read on a DIFF, never on a tree: a skip that has always
 * been there is the project's decision, a skip this change adds is a question
 * for its author.
 *
 *   | rule                      | severity | in the change                                 |
 *   | ------------------------- | -------- | --------------------------------------------- |
 *   | test-focused              | high     | an added `.only` / `fit` / `fdescribe` — it   |
 *   |                           |          | silently disables every other test of the run |
 *   | test-skipped              | medium   | an added skip: `.skip`, `xit`, pytest's       |
 *   |                           |          | `skip` / `skipif` / `xfail`, `@unittest.skip`,|
 *   |                           |          | Go's `t.Skip`, JUnit's `@Disabled` /          |
 *   |                           |          | `@Ignore`, xUnit's `Skip =`, NUnit's          |
 *   |                           |          | `[Ignore]`, Rust's `#[ignore]`, PHPUnit's     |
 *   |                           |          | `markTestSkipped`, RSpec's `xit` / `skip` /   |
 *   |                           |          | `pending`                                     |
 *   | test-todo-replaced        | medium   | an added `it.todo` / `test.todo` where the    |
 *   |                           |          | same change removed a test                    |
 *   | test-file-deleted         | medium   | a test file deleted (or renamed to a name no  |
 *   |                           |          | runner picks up)                              |
 *   | test-assertions-removed   | medium   | a test file with fewer assertions than before |
 *   | test-script-always-passes | medium   | a test script in package.json given           |
 *   |                           |          | `--passWithNoTests`, `\|\| true` and the like,|
 *   |                           |          | or replaced by `echo` / `exit 0`              |
 *
 * Every rule but `test-focused` is medium: a skip can be legitimate (a flaky
 * test quarantined with a ticket, a platform the test cannot run on), so the
 * finding asks for the reason rather than calling it a defect. A comment line
 * is never read (`// it.only(` documents, it does not focus).
 *
 * Pure: a change set in, findings out (`gitChanges.ts` builds the change set).
 */

import { parseJsonBounded } from '../platform/boundedJson.js';
import { makeFinding } from '../runners/scannerParsers/index.js';
import type { Finding, Severity } from '../types.js';

/** The `tool` of every finding here, and the pass's `tools_run` name. */
export const TEST_INTEGRITY_TOOL = 'guardian-test-integrity';

/** One line of a diff: an added line's new number, or the new-file line a removed one sat at. */
export interface DiffLine {
  line: number;
  text: string;
}

export interface ChangedFile {
  status: 'added' | 'modified' | 'deleted' | 'renamed';
  /** Project-relative, `/`-separated: the new path (the old one for a deletion). */
  path: string;
  /** A rename's or a copy's previous path. */
  oldPath?: string;
  added: DiffLine[];
  removed: DiffLine[];
  /** The file before and after the change, when read (a test file, a package.json); null when it could not be. */
  before?: string | null;
  after?: string | null;
}

type Lang = 'js' | 'py' | 'go' | 'jvm' | 'cs' | 'rs' | 'php' | 'rb';

/** Folders of test data, not tests: a `.only` in a fixture is the fixture's text. */
const NOT_TESTS = /(?:^|\/)(?:fixtures?|__fixtures__|__snapshots__|testdata|__mocks__|mocks?|snapshots?)\//i;

/** The language of a source file by its extension, or null. */
function languageOf(path: string): Lang | null {
  const ext = /\.([A-Za-z0-9]+)$/.exec(path)?.[1]?.toLowerCase();
  switch (ext) {
    case 'js':
    case 'jsx':
    case 'mjs':
    case 'cjs':
    case 'ts':
    case 'tsx':
    case 'mts':
    case 'cts':
      return 'js';
    case 'py':
      return 'py';
    case 'go':
      return 'go';
    case 'java':
    case 'kt':
    case 'kts':
    case 'groovy':
      return 'jvm';
    case 'cs':
      return 'cs';
    case 'rs':
      return 'rs';
    case 'php':
      return 'php';
    case 'rb':
      return 'rb';
    default:
      return null;
  }
}

/** Whether a path is a test file by the conventions of its language's runners. */
export function isTestFile(path: string): boolean {
  const p = path.replace(/\\/g, '/');
  if (NOT_TESTS.test(p)) return false;
  const lang = languageOf(p);
  if (lang === null) return false;
  const name = p.slice(p.lastIndexOf('/') + 1);
  const inDir = (re: RegExp): boolean => re.test(p);
  switch (lang) {
    case 'js':
      return /\.(?:test|spec|e2e|cy)\.[A-Za-z]+$/.test(name) || inDir(/(?:^|\/)(?:__tests__|tests?|specs?|e2e|cypress)\//);
    case 'py':
      return /^test_.*\.py$/.test(name) || /_tests?\.py$/.test(name) || name === 'conftest.py' || inDir(/(?:^|\/)tests?\//);
    case 'go':
      return name.endsWith('_test.go');
    case 'jvm':
      return /(?:Test|Tests|IT|Spec)\.(?:java|kt|kts|groovy)$/.test(name) || inDir(/(?:^|\/)src\/(?:test|androidTest|integrationTest)\//);
    case 'cs':
      return /Tests?\.cs$/.test(name) || inDir(/(?:^|\/)[^/]*\.?Tests?\//);
    case 'rs':
      return inDir(/(?:^|\/)tests\//);
    case 'php':
      return /Test\.php$/.test(name) || inDir(/(?:^|\/)tests?\//);
    case 'rb':
      return /_(?:spec|test)\.rb$/.test(name) || inDir(/(?:^|\/)(?:spec|test)\//);
  }
}

/**
 * Whether a change to this path is read at all: a test file, a package.json,
 * or a Rust source (a `#[ignore]` marks a test wherever it is written — Rust's
 * unit tests live beside the code).
 */
export function isRelevantPath(path: string): boolean {
  const name = path.slice(path.lastIndexOf('/') + 1);
  return isTestFile(path) || name === 'package.json' || (languageOf(path) === 'rs' && !NOT_TESTS.test(path));
}

interface Marker {
  rule: 'test-focused' | 'test-skipped' | 'test-todo-replaced';
  re: RegExp;
  /** What the line does, for the title. */
  what: string;
}

const JS_CALLEE = String.raw`\b(?:it|test|describe|context|suite|specify|bench)\b(?:\.\w+)*`;

const MARKERS: Readonly<Record<Lang, readonly Marker[]>> = {
  js: [
    { rule: 'test-focused', re: new RegExp(String.raw`${JS_CALLEE}\.only\s*[.(\x60]`), what: 'a focused test (.only)' },
    { rule: 'test-focused', re: /\bf(?:it|describe)\s*\(/, what: 'a focused test (fit / fdescribe)' },
    { rule: 'test-skipped', re: new RegExp(String.raw`${JS_CALLEE}\.skip\s*[.(\x60]`), what: 'a skipped test (.skip)' },
    { rule: 'test-skipped', re: /\bx(?:it|test|describe|context|specify)\s*\(/, what: 'a skipped test (xit / xdescribe / xtest)' },
    { rule: 'test-skipped', re: /\b(?:test|it)\.fixme\s*\(/, what: 'a skipped test (.fixme)' },
    { rule: 'test-todo-replaced', re: /\b(?:it|test)\.todo\s*\(/, what: 'a test turned into a todo (.todo)' },
  ],
  py: [
    { rule: 'test-skipped', re: /@pytest\.mark\.(?:skip|skipif|xfail)\b/, what: 'a skipped test (@pytest.mark.skip / skipif / xfail)' },
    { rule: 'test-skipped', re: /\bpytest\.(?:skip|xfail)\s*\(/, what: 'a skipped test (pytest.skip / pytest.xfail)' },
    { rule: 'test-skipped', re: /@unittest\.(?:skip|skipIf|skipUnless|expectedFailure)\b/, what: 'a skipped test (@unittest.skip)' },
    { rule: 'test-skipped', re: /\bself\.skipTest\s*\(|\braise\s+(?:unittest\.)?SkipTest\b/, what: 'a skipped test (skipTest)' },
  ],
  go: [{ rule: 'test-skipped', re: /\b\w+(?:\(\))?\.Skip(?:f|Now)?\s*\(/, what: 'a skipped test (t.Skip)' }],
  jvm: [{ rule: 'test-skipped', re: /@(?:Disabled|Ignore)\b/, what: 'a disabled test (@Disabled / @Ignore)' }],
  cs: [
    { rule: 'test-skipped', re: /\[\s*(?:Fact|Theory|Test|TestMethod|TestCase)\b[^\]]*\bSkip\s*=/, what: 'a skipped test (Skip =)' },
    { rule: 'test-skipped', re: /\[\s*Ignore\b/, what: 'an ignored test ([Ignore])' },
  ],
  rs: [{ rule: 'test-skipped', re: /#\[\s*ignore\b/, what: 'an ignored test (#[ignore])' }],
  php: [{ rule: 'test-skipped', re: /\bmarkTest(?:Skipped|Incomplete)\s*\(/, what: 'a skipped test (markTestSkipped)' }],
  rb: [
    { rule: 'test-focused', re: /^\s*f(?:it|describe|context|specify)\b/, what: 'a focused example (fit / fdescribe)' },
    { rule: 'test-focused', re: /\bfocus:\s*true\b/, what: 'a focused example (focus: true)' },
    { rule: 'test-skipped', re: /^\s*x(?:it|describe|context|specify|scenario|feature)\b/, what: 'a skipped example (xit)' },
    { rule: 'test-skipped', re: /^\s*(?:skip|pending)\b(?!\s*[=:])/, what: 'a skipped example (skip / pending)' },
    { rule: 'test-skipped', re: /\bskip:\s*true\b/, what: 'a skipped example (skip: true)' },
  ],
};

/** Assertions, by language — counted before and after the change. */
const ASSERTIONS: Readonly<Record<Lang, RegExp>> = {
  js: /\bexpect(?:TypeOf)?\s*\(|\bassert(?:\.\w+)*\s*\(|\.should\b|\bt\.(?:is|not|deepEqual|notDeepEqual|true|false|truthy|falsy|throws|throwsAsync|equal|ok|assert)\s*\(/g,
  py: /\bassert\b|\bself\.assert\w*\s*\(|\bpytest\.raises\s*\(|\bpytest\.approx\s*\(/g,
  go: /\b\w+\.(?:Error|Errorf|Fatal|Fatalf|Fail|FailNow)\s*\(|\b(?:assert|require)\.\w+\s*\(/g,
  jvm: /\bassert\w*\s*\(|\bAssert\w*\.\w+\s*\(|\bverify\s*\(|\bexpect\w*\s*\(/g,
  cs: /\bAssert\.\w+\s*\(|\.Should\w*\s*\(|\bVerify\s*\(/g,
  rs: /\b(?:debug_)?assert(?:_eq|_ne|_matches)?!\s*\(/g,
  php: /(?:\$this->|self::|static::)(?:assert\w*|expect\w*)\s*\(/g,
  rb: /\bexpect\s*[({]|\.should\b|\bassert\w*\b|\brefute\w*\b/g,
};

/** A test declaration, to tell a `.todo` that REPLACES a test from a new one. */
const JS_TEST_DECL = /\b(?:it|test)\s*\(/;

/** A comment line: never read as code. `#[` is Rust's attribute, never a comment. */
function isComment(text: string, lang: Lang): boolean {
  const t = text.trim();
  if (t.startsWith('//') || t.startsWith('/*') || t.startsWith('*')) return true;
  if ((lang === 'py' || lang === 'rb' || lang === 'php') && t.startsWith('#') && !t.startsWith('#[')) return true;
  return false;
}

/** The assertions in `text` — comment lines left out. */
export function countAssertions(text: string, lang: Lang): number {
  let n = 0;
  for (const line of text.split(/\r?\n/)) {
    if (isComment(line, lang)) continue;
    const re = ASSERTIONS[lang];
    re.lastIndex = 0;
    n += [...line.matchAll(re)].length;
  }
  return n;
}

/** A script a test command lives in: `test`, `test:unit`, `unit:test`, `ci`, `check`, `verify`. */
const TEST_SCRIPT = /^(?:tests?|ci|check|verify)(?:[:._-].*)?$|^.*[:._-]tests?(?:[:._-].*)?$/i;
/** What makes a command pass whatever its tests do. */
const ALWAYS_PASSES = /--pass-?with-?no-?tests\b|\|\|\s*(?:true\b|exit\s+0\b|:|echo\b)|;\s*exit\s+0\b/i;
const NO_OP = /^\s*(?:echo\b[^|&;]*|exit\s+0|true|:)\s*$/;

/** A package.json's `scripts`, or null when it is not one. */
function scriptsOf(text: string | null | undefined): Record<string, string> | null {
  if (text === null || text === undefined) return null;
  const parsed = parseJsonBounded(text);
  if (!parsed.ok || typeof parsed.value !== 'object' || parsed.value === null) return null;
  const scripts = (parsed.value as { scripts?: unknown }).scripts;
  if (typeof scripts !== 'object' || scripts === null) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(scripts as Record<string, unknown>)) if (typeof v === 'string') out[k] = v;
  return out;
}

/** The 1-based line of `"name":` in a package.json's text, or undefined. */
function lineOfKey(text: string, name: string): number | undefined {
  const needle = JSON.stringify(name);
  const lines = text.split(/\r?\n/);
  const i = lines.findIndex((l) => new RegExp(`${needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:`).test(l));
  return i < 0 ? undefined : i + 1;
}

const ASK =
  'A test can be skipped for a reason — a quarantined flaky test with a ticket, a platform it cannot run on — so ' +
  'say which in the change (a comment with the ticket, the condition), or restore the test and fix what it caught.';

function make(
  rule: string,
  severity: Severity,
  path: string,
  line: number | undefined,
  title: string,
  message: string,
): Finding {
  return makeFinding({
    tool: TEST_INTEGRITY_TOOL,
    rule_id: rule,
    severity,
    category: 'quality',
    subcategory: 'test-integrity',
    title,
    message,
    file_path: path,
    ...(line !== undefined ? { line_start: line, line_end: line } : {}),
  });
}

/** Every finding of one change set (see the module comment). */
export function detectTestWeakening(changes: readonly ChangedFile[]): Finding[] {
  const findings: Finding[] = [];
  for (const c of changes) {
    const name = c.path.slice(c.path.lastIndexOf('/') + 1);
    if (name === 'package.json') {
      findings.push(...scriptFindings(c));
      continue;
    }
    const wasTest = isTestFile(c.oldPath ?? c.path);
    const isTest = c.status !== 'deleted' && isTestFile(c.path);

    if ((c.status === 'deleted' && wasTest) || (c.status === 'renamed' && wasTest && !isTest)) {
      const oldLang = languageOf(c.oldPath ?? c.path);
      const lost = typeof c.before === 'string' && oldLang !== null ? countAssertions(c.before, oldLang) : null;
      const what = c.status === 'deleted' ? 'deletes' : `renames to ${c.path}, a name no test runner picks up,`;
      findings.push(
        make(
          'test-file-deleted',
          'medium',
          c.oldPath ?? c.path,
          undefined,
          `Test file ${c.status === 'deleted' ? 'deleted' : 'renamed out of the suite'}: ${c.oldPath ?? c.path}`,
          `This change ${what} the test file ${c.oldPath ?? c.path}${lost !== null ? ` and its ${lost} assertion(s)` : ''}: ` +
            'whatever it checked is no longer checked. If the code it tested is gone too, say so in the change; if not, ' +
            'restore it, or move its cases to the file that replaces it.',
        ),
      );
      continue;
    }

    const lang = languageOf(c.path);
    if (lang === null) continue;
    // `#[ignore]` marks a test wherever it is written; every other marker only in a test file.
    if (!isTest && lang !== 'rs') continue;
    const removedTest = c.removed.some((l) => !isComment(l.text, lang) && JS_TEST_DECL.test(l.text));
    for (const added of c.added) {
      if (isComment(added.text, lang)) continue;
      const marker = MARKERS[lang].find((m) => m.re.test(added.text));
      if (marker === undefined) continue;
      if (lang === 'rs' && !isTest && marker.rule !== 'test-skipped') continue;
      if (marker.rule === 'test-todo-replaced' && !removedTest) continue;
      if (marker.rule === 'test-focused') {
        findings.push(
          make(
            'test-focused',
            'high',
            c.path,
            added.line,
            `${c.path}:${added.line} adds ${marker.what}`,
            `This change adds ${marker.what}: the runner then runs only the focused tests and silently skips every ` +
              'other test of the file or the run — the suite goes green without testing the rest. Remove the focus ' +
              'before committing (most runners can fail on it: Jest/Vitest `--forbid-only`/`allowOnly: false`, Mocha ' +
              '`--forbid-only`).',
          ),
        );
      } else if (marker.rule === 'test-todo-replaced') {
        findings.push(
          make(
            'test-todo-replaced',
            'medium',
            c.path,
            added.line,
            `${c.path}:${added.line} turns a test into a todo`,
            `This change removes a test and adds ${marker.what} in its place: the behaviour it checked is no longer ` +
              `checked, and the run stays green. ${ASK}`,
          ),
        );
      } else {
        findings.push(
          make(
            'test-skipped',
            'medium',
            c.path,
            added.line,
            `${c.path}:${added.line} adds ${marker.what}`,
            `This change adds ${marker.what}: the test no longer runs, and the suite passes without it. ${ASK}`,
          ),
        );
      }
    }

    if (isTest && wasTest && (c.status === 'modified' || c.status === 'renamed') && typeof c.before === 'string' && typeof c.after === 'string') {
      const before = countAssertions(c.before, lang);
      const after = countAssertions(c.after, lang);
      if (after < before) {
        const re = ASSERTIONS[lang];
        const first = c.removed.find((l) => {
          re.lastIndex = 0;
          return !isComment(l.text, lang) && re.test(l.text);
        });
        findings.push(
          make(
            'test-assertions-removed',
            'medium',
            c.path,
            first?.line ?? c.removed[0]?.line,
            `${c.path}: assertions dropped from ${before} to ${after}`,
            `This change leaves ${c.path} with ${after} assertion(s) where it had ${before}: the tests still run, ` +
              'and check less. Deleting or loosening an assertion is how a failing test is made to pass without ' +
              'fixing the code; if the checks moved elsewhere or the behaviour is gone, say so in the change.',
          ),
        );
      }
    }
  }
  return findings;
}

function scriptFindings(c: ChangedFile): Finding[] {
  if (c.status === 'deleted') return [];
  const before = scriptsOf(c.before) ?? {};
  const after = scriptsOf(c.after);
  if (after === null || typeof c.after !== 'string') return [];
  const out: Finding[] = [];
  for (const [name, command] of Object.entries(after)) {
    if (!TEST_SCRIPT.test(name)) continue;
    const old = before[name];
    if (old === command) continue;
    const loosened = ALWAYS_PASSES.test(command) && (old === undefined || !ALWAYS_PASSES.test(old));
    const emptied = NO_OP.test(command) && old !== undefined && !NO_OP.test(old);
    if (!loosened && !emptied) continue;
    out.push(
      make(
        'test-script-always-passes',
        'medium',
        c.path,
        lineOfKey(c.after, name),
        `${c.path}: the "${name}" script now passes whatever the tests do`,
        `This change makes the "${name}" script ${emptied ? 'a no-op' : 'pass regardless'} ` +
          `(${emptied ? `it was "${old ?? ''}"` : '`--passWithNoTests`, `|| true`, `|| exit 0` or the like'}): a CI ` +
          'step or a pre-merge check that runs it is green whether or not a single test runs or passes. Restore the ' +
          'command; if no test exists yet, say so instead of hiding it.',
      ),
    );
  }
  return out;
}
