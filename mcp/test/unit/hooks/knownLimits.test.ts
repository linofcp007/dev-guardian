/**
 * The guardrail hooks' known limits, pinned.
 *
 * `docs/hooks.md` used to list 22 known limits as prose. Nothing failed when a
 * guard came to cover one, or when a change made one worse than the text
 * said. Each limit is now a record of `test/fixtures/hooks/known-limits.yml`
 * with examples, and every shell and secret example runs here through the
 * detector the hooks use; the hook examples run through the real dispatcher
 * in `test/e2e/knownLimitsHook.test.ts`.
 *
 * A failure names the limit. When the guard answers MORE strictly than the
 * record, the limit looks closed: its record leaves the list (or its example
 * is corrected) in the same commit, and `npm run build` regenerates
 * `docs/hooks-known-limits.md`. Never loosen a guard to make this file pass.
 *
 * The verdicts are measured, not transcribed: a record states what the
 * detector answers on HEAD, with the platform, the home directory, the working
 * directory and the environment injected, so no verdict depends on the machine
 * running the suite.
 */

import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { assessBashCommand, type AssessOptions } from '../../../src/hooks/bashGuard.js';
import { scanForSecrets } from '../../../src/hooks/secretScan.js';
import {
  buildInput,
  evaluateExample,
  exampleRefs,
  judgeExample,
  KNOWN_LIMITS_FILE,
  LIMIT_AREAS,
  loadKnownLimits,
  parseKnownLimits,
  partitionByPlatform,
  platformOf,
  type Actual,
  type ExampleRef,
  type HookDecision,
  type KnownLimit,
  type LimitExample,
  type SecretExample,
  type ShellExample,
  type ShellLevel,
} from '../../docs/knownLimits.js';

/** What the guard is told about the machine: fixed, so a verdict is the same everywhere. */
function guardOptions(example: ShellExample): AssessOptions {
  const platform = platformOf(example);
  const win = platform === 'win32';
  return {
    shell: example.shell,
    platform,
    homeDir: win ? 'C:\\Users\\dev' : '/home/dev',
    cwd: win ? 'C:\\work\\shop' : '/work/shop',
    projectDir: win ? 'C:\\work\\shop' : '/work/shop',
    dataDir: win ? 'C:\\Users\\dev\\AppData\\Local\\dev-guardian' : '/home/dev/.local/share/dev-guardian',
    claudeConfigDir: '',
    env: win
      ? {
          TEMP: 'C:\\Users\\dev\\AppData\\Local\\Temp',
          TMP: 'C:\\Users\\dev\\AppData\\Local\\Temp',
          LOCALAPPDATA: 'C:\\Users\\dev\\AppData\\Local',
          APPDATA: 'C:\\Users\\dev\\AppData\\Roaming',
        }
      : { TMPDIR: '/tmp' },
    // Wide on purpose: only an example about a size cap may be cut short, never one about load.
    budgetMs: 60_000,
  };
}

function detect(example: ShellExample | SecretExample): Actual {
  if (example.detector === 'secret') {
    return { detector: 'secret', hits: scanForSecrets(buildInput(example)).length };
  }
  const a = assessBashCommand(buildInput(example), guardOptions(example));
  return { detector: 'shell', level: a.level, ask: a.ask !== undefined };
}

const label = (ref: ExampleRef): string => `${ref.limit.id} #${String(ref.index + 1)}`;

/**
 * Read at collection time, so each example is a test of its own. A data file
 * that does not load is T-01's to report, by name; here it only means no cases.
 */
function collected(): ExampleRef[] {
  try {
    return exampleRefs(loadKnownLimits());
  } catch {
    return [];
  }
}

const PURE = collected().filter((r) => r.example.detector !== 'hook');

// ---- an independent oracle for T-05: how severe an answer is ---------------

const SHELL_ANSWERS: ReadonlyArray<{ level: ShellLevel; ask: boolean }> = [
  { level: 'ok', ask: false },
  { level: 'warn', ask: false },
  { level: 'warn', ask: true },
  { level: 'block', ask: false },
];
const HOOK_ANSWERS: readonly HookDecision[] = ['none', 'warn', 'ask', 'deny'];

function recorded(example: LimitExample): Actual {
  if (example.detector === 'shell') {
    return { detector: 'shell', level: example.expect.level, ask: example.expect.ask === true };
  }
  if (example.detector === 'secret') return { detector: 'secret', hits: example.expect.hits };
  return { detector: 'hook', decision: example.expect.decision };
}

function severity(a: Actual): number {
  if (a.detector === 'shell') return SHELL_ANSWERS.findIndex((s) => s.level === a.level && s.ask === a.ask);
  if (a.detector === 'secret') return a.hits;
  return HOOK_ANSWERS.indexOf(a.decision);
}

/** Every answer the detector could give that is not the recorded one. */
function otherAnswers(example: LimitExample): Actual[] {
  const now = recorded(example);
  if (now.detector === 'shell') {
    return SHELL_ANSWERS.filter((s) => s.level !== now.level || s.ask !== now.ask).map((s) => ({ detector: 'shell', ...s }));
  }
  if (now.detector === 'secret') {
    const fewer: Actual[] = now.hits > 0 ? [{ detector: 'secret', hits: now.hits - 1 }] : [];
    return [...fewer, { detector: 'secret', hits: now.hits + 1 }];
  }
  return HOOK_ANSWERS.filter((d) => d !== now.decision).map((decision) => ({ detector: 'hook', decision }));
}

// ---- inline data for the schema tests -------------------------------------

/** One record, with whatever replaces or follows its fields. */
function record(fields: Record<string, string>, extra = ''): string {
  const all = {
    id: 'sample-limit',
    area: 'shell-guard',
    doc: 'A sample limit.',
    examples: '\n    - { detector: shell, shell: bash, command: "python fix.py", expect: { level: ok } }',
    ...fields,
  };
  const lines = Object.entries(all)
    .filter(([, v]) => v !== '')
    .map(([k, v]) => `  ${k}:${v.startsWith('\n') ? v : ` ${v}`}`);
  return `- ${lines.join('\n').trimStart()}\n${extra}`;
}

const ALL_FORMS = `
- id: sample-shell
  area: shell-guard
  doc: A program on disk is never judged.
  examples:
    - detector: shell
      shell: bash
      command: python fix.py
      expect: { level: ok }
    - detector: shell
      shell: powershell
      command: 'Remove-Item * -Recurse'
      platform: win32
      expect: { level: warn, ask: true }
      note: asked, never denied
    - detector: shell
      shell: bash
      build: { repeat: 'x', times: 5, then: '; rm -rf /' }
      expect: { level: block }
- id: sample-secret
  area: secret-scan
  doc: A password below the entropy floor is not reported.
  examples:
    - detector: secret
      text: 'url = "postgres://app:hunter2@db/app"'
      expect: { hits: 0 }
    - detector: secret
      parts: ['AKIA', 'Q7XZ2M9KDP4RWT3B']
      expect: { hits: 1 }
- id: sample-hook
  area: mcp-tools
  doc: A tool whose name holds no file verb is not guarded.
  examples:
    - detector: hook
      event: PreToolUse
      tool: mcp__files__touch
      input: { path: '\${PROJECT}/notes.txt' }
      files: { 'README.md': 'x' }
      only: [linux]
      expect: { decision: none }
- id: sample-prose
  area: write-guard
  doc: A share that leads back to this machine under another name is not resolved.
  not_executable: needs a network share the test cannot mount
`;

describe("the hooks' known limits, as data", () => {
  it('T-01 the data file loads: every record has a kebab-case id, a known area, a text and its examples', () => {
    const limits = loadKnownLimits();
    expect(limits.length).toBeGreaterThan(0);
    for (const l of limits) {
      expect(l.id, l.id).toMatch(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
      expect(LIMIT_AREAS, l.id).toContain(l.area);
      expect(l.doc.trim(), l.id).not.toBe('');
      expect(Array.isArray(l.examples), l.id).toBe(true);
    }
    expect(new Set(limits.map((l) => l.id)).size, 'ids are unique').toBe(limits.length);
  });

  it('T-02 the schema takes the three detectors with their verdicts, and an input is built from command, text, parts or build', () => {
    const limits = parseKnownLimits(ALL_FORMS, 'inline');
    expect(limits.map((l) => l.id)).toEqual(['sample-shell', 'sample-secret', 'sample-hook', 'sample-prose']);
    const refs = exampleRefs(limits);
    expect(refs.map((r) => r.example.detector)).toEqual(['shell', 'shell', 'shell', 'secret', 'secret', 'hook']);

    const inputs = refs.flatMap((r) => (r.example.detector === 'hook' ? [] : [buildInput(r.example)]));
    expect(inputs).toEqual([
      'python fix.py',
      'Remove-Item * -Recurse',
      'xxxxx; rm -rf /',
      'url = "postgres://app:hunter2@db/app"',
      ['AKIA', 'Q7XZ2M9KDP4RWT3B'].join(''),
    ]);

    // Every verdict a detector can give is one a record may state.
    for (const level of ['ok', 'warn', 'block']) {
      for (const ask of ['', ', ask: true']) {
        const text = record({ examples: `\n    - { detector: shell, shell: bash, command: "x", expect: { level: ${level}${ask} } }` });
        expect(() => parseKnownLimits(text, 'inline'), `${level}${ask}`).not.toThrow();
      }
    }
    for (const decision of HOOK_ANSWERS) {
      const text = record({
        examples: `\n    - { detector: hook, event: PostToolUse, tool: Write, input: { file_path: "a" }, expect: { decision: ${decision} } }`,
      });
      expect(() => parseKnownLimits(text, 'inline'), decision).not.toThrow();
    }
  });

  it('T-03 the data file holds shell and secret examples to run', () => {
    expect(PURE.length).toBeGreaterThan(0);
  });

  if (PURE.length > 0) {
    it.each(PURE.map((ref) => [label(ref), ref] as const))('T-03 %s answers as recorded', (_name, ref) => {
      const example = ref.example;
      if (example.detector === 'hook') throw new Error('a hook example is the e2e file\'s');
      const judgement = evaluateExample(ref, () => detect(example));
      expect(judgement, judgement.ok ? '' : judgement.message).toEqual({ ok: true });
    });
  }

  it('T-05 for every example and every other answer, the failure names the limit and says which way the guard moved', () => {
    const refs = exampleRefs(loadKnownLimits());
    expect(refs.length).toBeGreaterThan(0);
    for (const ref of refs) {
      const now = recorded(ref.example);
      expect(judgeExample(ref, now), label(ref)).toEqual({ ok: true });
      for (const other of otherAnswers(ref.example)) {
        const judgement = judgeExample(ref, other);
        const what = `${label(ref)} answering ${JSON.stringify(other)}`;
        expect(judgement.ok, what).toBe(false);
        if (judgement.ok) continue;
        const stricter = severity(other) > severity(now);
        expect(judgement.direction, what).toBe(stricter ? 'stricter' : 'looser');
        expect(judgement.message, what).toContain(ref.limit.id);
        if (stricter) {
          // The limit looks closed: the record leaves the list in the same commit.
          expect(judgement.message, what).toMatch(/closed/i);
          expect(judgement.message, what).toMatch(/same commit/i);
        }
      }
    }
  });

  it('T-06 a record with no example needs a reason, and one with neither is refused by name', () => {
    expect(() => parseKnownLimits(record({ examples: '' }), 'inline')).toThrow(/sample-limit.*(?:examples|not_executable)/s);
    expect(() =>
      parseKnownLimits(record({ examples: '', not_executable: 'needs a network share the test cannot mount' }), 'inline'),
    ).not.toThrow();
    expect(() => parseKnownLimits(record({ not_executable: 'only its second half can be run' }), 'inline')).not.toThrow();
  });

  it('T-07 a bad data file fails naming the record and the field', () => {
    const twice = record({}) + record({});
    expect(() => parseKnownLimits(twice, 'inline'), 'an id used twice').toThrow(/sample-limit.*\bid\b/s);
    expect(() => parseKnownLimits(record({ area: 'kernel' }), 'inline'), 'an unknown area').toThrow(/sample-limit.*area/s);
    expect(
      () => parseKnownLimits(record({ examples: '\n    - { detector: antivirus, text: "x", expect: { hits: 0 } }' }), 'inline'),
      'an unknown detector',
    ).toThrow(/sample-limit.*detector/s);
    expect(
      () =>
        parseKnownLimits(
          record({ examples: '\n    - { detector: shell, shell: bash, command: "x", expect: { level: fatal } }' }),
          'inline',
        ),
      'an unknown verdict',
    ).toThrow(/sample-limit.*level/s);
    expect(() => parseKnownLimits(record({ severity: 'high' }), 'inline'), 'a field the schema does not know').toThrow(
      /sample-limit.*severity/s,
    );
    expect(() => parseKnownLimits(record({ doc: '' }), 'inline'), 'no text').toThrow(/sample-limit.*doc/s);
  });

  it('T-08 a detector that throws fails its example by name: a known limit is an answer, never a crash', () => {
    const [ref] = exampleRefs(parseKnownLimits(record({}), 'inline'));
    if (ref === undefined) throw new Error('the sample record has one example');
    const judgement = evaluateExample(ref, () => {
      throw new Error('boom');
    });
    expect(judgement.ok).toBe(false);
    if (judgement.ok) return;
    expect(judgement.direction).toBe('threw');
    expect(judgement.message).toContain('sample-limit');
    expect(judgement.message).toMatch(/threw/);
    expect(judgement.message).toContain('boom');
  });

  it('T-09 a hook example of another platform is set aside as skipped, and a shell example runs everywhere', () => {
    const refs = exampleRefs(parseKnownLimits(ALL_FORMS, 'inline'));
    const onWindows = partitionByPlatform(refs, 'win32');
    expect(onWindows.skip.map((r) => r.limit.id)).toEqual(['sample-hook']);
    expect(onWindows.run).toHaveLength(refs.length - 1);
    const onLinux = partitionByPlatform(refs, 'linux');
    expect(onLinux.skip).toEqual([]);
    expect(onLinux.run).toHaveLength(refs.length);
    // A shell example carries its platform to the guard instead of waiting for a machine of that kind.
    const shells = refs.flatMap((r) => (r.example.detector === 'shell' ? [r.example] : []));
    expect(shells.map(platformOf)).toEqual(['linux', 'win32', 'linux']);
  });

  it('T-15 the 22 limits docs/hooks.md listed are all records, and at least 18 have an example', () => {
    const limits = loadKnownLimits();
    const ids = new Set(limits.map((l) => l.id));
    // The design's migration map: one id per item of the hand-written list, in its order.
    const migrated = [
      'program-on-disk',
      'config-written-by-other-means',
      'settings-copied-into-place',
      'settings-removed-from-above',
      'guardian-dir-removed',
      'plugin-install-editable',
      'nesting-depth',
      'launchers-not-followed',
      'db-adopt-other-launchers',
      'download-run-unseen',
      'checksum-trust',
      'path-dirs-fixed-list',
      'hard-link-scope',
      'jwt-long-segment',
      'secret-prefilter',
      'secret-from-shell',
      'mcp-tool-verbs',
      'network-share-alias',
      'runtime-named-command',
      'decoder-output',
      'baseline-ask-headless',
      'size-and-time-caps',
    ];
    expect(migrated).toHaveLength(22);
    expect(migrated.filter((id) => !ids.has(id))).toEqual([]);
    expect(limits.filter((l) => l.examples.length > 0).length).toBeGreaterThanOrEqual(18);
    for (const l of limits.filter((x) => x.examples.length === 0)) {
      expect((l.not_executable ?? '').trim(), l.id).not.toBe('');
    }
  });

  it('T-16 the data file itself holds no secret: a token exists only once its parts are joined', () => {
    expect(existsSync(KNOWN_LIMITS_FILE), `${KNOWN_LIMITS_FILE} is missing`).toBe(true);
    expect(scanForSecrets(readFileSync(KNOWN_LIMITS_FILE, 'utf8'))).toEqual([]);
  });

  it('T-17 this file and the module it uses start no process, and the file stays in the fast lane', () => {
    const importsChildProcess = /from\s+['"]node:child_process['"]/;
    const here = fileURLToPath(import.meta.url);
    const helper = fileURLToPath(new URL('../../docs/knownLimits.ts', import.meta.url));
    expect(readFileSync(here, 'utf8')).not.toMatch(importsChildProcess);
    expect(readFileSync(helper, 'utf8')).not.toMatch(importsChildProcess);
    const fastLane = readFileSync(fileURLToPath(new URL('../../../vitest.fast.config.ts', import.meta.url)), 'utf8');
    expect(fastLane).not.toContain('knownLimits.test.ts');
  });
});

// ───────────────── install-vet-manifest-install — what the manifest vetting does not cover is a record

describe('the limits of the manifest vetting, as data', () => {
  const WANTED = [
    'manifest-lockfile-and-transitive',
    'manifest-not-from-a-registry',
    'manifest-other-managers',
    'manifest-private-scope',
    'manifest-quiet-checks',
    'manifest-workspace-members',
  ];

  it('T-25 the install-vetting area has a record for each limit, with an example the hook runs — or the reason none can', () => {
    expect(LIMIT_AREAS as readonly string[]).toContain('install-vetting');
    const records = loadKnownLimits().filter((l) => (l.area as string) === 'install-vetting');
    expect(records.map((l) => l.id).sort()).toEqual(WANTED);
    for (const l of records) {
      const hooks = l.examples.filter((e) => e.detector === 'hook');
      const shown = hooks.length > 0 || (l.not_executable ?? '').trim() !== '';
      expect({ id: l.id, shown }).toEqual({ id: l.id, shown: true });
    }
    // Only the limit that needs a registry's answer goes without an example the suite can run.
    expect(records.filter((l) => l.examples.length === 0).map((l) => l.id)).toEqual(['manifest-quiet-checks']);
  });
});

// ───────────────── install-vet-lockfile-pins — the lockfile's record says what still stays out

describe('install-vet-lockfile-pins', () => {
  const RECORD = 'manifest-lockfile-and-transitive';

  function lockfileRecord(): KnownLimit {
    const limit = loadKnownLimits().find((l) => l.id === RECORD);
    if (limit === undefined) throw new Error(`the data file has no record ${RECORD}`);
    return limit;
  }

  // The lockfile IS read now, and every pair it pins is asked of OSV: the record stops saying otherwise and lists what
  // the vetting by the lockfile leaves out (US-2.AC-1). Each thing is looked for by its own words, in any phrasing.
  it('T-32 the record no longer says the lockfile is not read, and names each thing that stays out', () => {
    const doc = lockfileRecord().doc.replace(/\s+/g, ' ');
    // What the record said while the lockfile was not opened.
    const stillSaid = [/lockfile is not read/i, /every transitive dependency[^.]*installed without a lookup/i]
      .filter((re) => re.test(doc))
      .map(String);

    const STAYS_OUT: Array<[what: string, said: RegExp[]]> = [
      ['what another source serves', [/another source|other source|elsewhere|mirror|another (?:host|origin|registry)/i]],
      ["a default registry set by a configuration file of the project (it is not said)", [/default registry/i, /project|\.npmrc/i]],
      ["the lockfile's `integrity` (the content is not compared with it)", [/integrity/i]],
      ["another package manager's lockfile", [/(?:an)?other (?:package )?manager|manager other than|not the command's/i]],
      ['`bun.lockb`', [/bun\.lockb/]],
      ['a format version the reader does not know', [/version/i, /not know|unknown|other than|newer/i]],
      ['the cap of 8 000 pairs', [/8[\s,.]?000/]],
      [
        'an `npm install` whose lockfile is out of sync (what the manager resolves again is not looked up)',
        [/`npm install`/, /out of sync|out-of-sync|not in sync|resolves?[^.]{0,20}(?:again|anew)|re-?resolv/i],
      ],
    ];
    const notSaid = STAYS_OUT.filter(([, said]) => !said.every((re) => re.test(doc))).map(([what]) => what);
    expect({ stillSaid, notSaid }).toEqual({ stillSaid: [], notSaid: [] });
  });

  // "An example for each case the guard answers without the network": each is recognised by the files it cannot do
  // without, never by its wording. The cap is the one thing with no example asked for here — 8 000 pairs do not fit
  // an example's `files`.
  it('T-32 the record has an example the hook runs for each thing a few files can show', () => {
    const MANAGER_LOCKFILES: Readonly<Record<string, readonly string[]>> = {
      npm: ['npm-shrinkwrap.json', 'package-lock.json'],
      pnpm: ['pnpm-lock.yaml'],
      yarn: ['yarn.lock'],
      bun: ['bun.lock', 'bun.lockb'],
    };
    const ANY_LOCKFILE = Object.values(MANAGER_LOCKFILES).flat();
    const PUBLIC_HOSTS = ['registry.npmjs.org', 'registry.npmjs.com', 'registry.yarnpkg.com'];
    const base = (path: string): string => path.split('/').pop() ?? path;

    interface Shown {
      command: string;
      files: Array<[name: string, text: string]>;
    }
    const shown: Shown[] = lockfileRecord().examples.flatMap((e) =>
      e.detector === 'hook' && typeof e.input['command'] === 'string'
        ? [{ command: e.input['command'], files: Object.entries(e.files ?? {}).map(([path, text]): [string, string] => [base(path), text]) }]
        : [],
    );
    const lockfiles = (s: Shown): Array<[string, string]> => s.files.filter(([name]) => ANY_LOCKFILE.includes(name));
    const has = (s: Shown, name: string): boolean => s.files.some(([n]) => n === name);
    const manager = (s: Shown): string => /^\s*(npm|pnpm|yarn|bun)\b/.exec(s.command)?.[1] ?? '';

    /** Whether a lockfile's text states a format version its reader does not know. */
    const unknownVersion = ([name, text]: [string, string]): boolean => {
      if (name === 'yarn.lock') return !/^# yarn lockfile v1\s*$/m.test(text) && !/^__metadata:/m.test(text);
      const version = /["']?lockfileVersion["']?\s*:\s*["']?(\d+)/.exec(text)?.[1];
      if (version === undefined) return false;
      const known = name === 'pnpm-lock.yaml' ? ['5', '6', '9'] : name === 'bun.lock' ? ['0', '1'] : ['1', '2', '3'];
      return !known.includes(version);
    };

    const CASES: Array<[what: string, shows: (s: Shown) => boolean]> = [
      [
        'a lockfile entry fetched from a host that is not the public registry',
        (s) =>
          lockfiles(s).some(([, text]) =>
            [...text.matchAll(/https?:\/\/([^/\s"'#]+)/g)].some((m) => !PUBLIC_HOSTS.includes((m[1] ?? '').toLowerCase())),
          ),
      ],
      [
        'a configuration file of the project that sets the default registry',
        (s) =>
          s.files.some(
            ([name, text]) =>
              ['.npmrc', '.yarnrc', '.yarnrc.yml', 'bunfig.toml'].includes(name) && /^\s*(?:registry\s*[= "]|npmRegistryServer\s*:)/m.test(text),
          ),
      ],
      ['a lockfile entry with an `integrity`', (s) => lockfiles(s).some(([, text]) => /integrity/.test(text))],
      [
        "another manager's lockfile, and none of the command's own",
        (s) => {
          const own = MANAGER_LOCKFILES[manager(s)];
          return own !== undefined && lockfiles(s).length > 0 && !lockfiles(s).some(([name]) => own.includes(name));
        },
      ],
      ['`bun.lockb`, or a lockfile of a format version the reader does not know', (s) => has(s, 'bun.lockb') || lockfiles(s).some(unknownVersion)],
      [
        '`npm install` — not `npm ci` — beside a package.json and its lockfile',
        (s) =>
          /^\s*npm\s+(?:install|i)(?:\s+--?[\w-]+)*\s*$/.test(s.command) &&
          has(s, 'package.json') &&
          lockfiles(s).some(([name]) => (MANAGER_LOCKFILES['npm'] ?? []).includes(name)),
      ],
    ];
    const notShown = CASES.filter(([, shows]) => !shown.some(shows)).map(([what]) => what);
    expect(notShown).toEqual([]);
  });
});
