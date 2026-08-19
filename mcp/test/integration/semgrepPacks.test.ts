/**
 * CROSS-PACK INVARIANTS for every Semgrep rule file in `configs/semgrep/`.
 *
 * The packs are discovered by reading the directory, never from a list kept
 * here. A pack added later — C#, PHP, Ruby, Rust are queued — is covered by
 * existing on disk, not by somebody remembering to register it. That is the
 * whole point: this file exists because the invariants below were learned on
 * the Java pack, and the next pack to break one will not be the Java pack.
 *
 * ---------------------------------------------------------------------------
 * THE SILENT-RULE-FAILURE FAMILY
 *
 * Four ways a rule file can fail to load have now been found in this repo, and
 * all four share one signature: **fewer rules load than the file declares, and
 * nothing in the findings says so.** A `pattern-either` branch with no positive
 * term, an unquoted `?` in a ternary exclusion, `... <... e ...> ...` written
 * inside a block, and — the reason this file exists — a single character whose
 * UTF-8 encoding the *locale* codec cannot decode.
 *
 * The fourth was caught by assertions written for the first three, by an author
 * who did not know it existed. That is the strongest evidence in this whole
 * round that the machinery was worth building, and it is the argument for
 * having it cover every pack rather than only the one where it was written.
 *
 * ---------------------------------------------------------------------------
 * THE LOCALE-CODEC TRAP, stated exactly
 *
 * Semgrep's config loader reads a rule file with the **locale** codec, not
 * UTF-8. On a Windows cp1252 locale the bytes `0x81`, `0x8D`, `0x8F`, `0x90`
 * and `0x9D` are undefined, so any character whose UTF-8 encoding contains one
 * of them takes the entire pack down. Measured on a deliberately broken file:
 * the scan returns `results: 0`, `paths.scanned: 0` and — the part that makes
 * it dangerous — `errors: 0`. A caller reading only the findings sees a pack
 * that ran cleanly and found nothing.
 *
 * Every rule MESSAGE in this series is written in Portuguese, which is why this
 * is a live risk and not a curiosity.
 *
 * **The rule is narrow, and the narrowness is measured.** The first version of
 * this warning said "no uppercase accented letters", and that is false for ten
 * of the twelve accented capitals Portuguese uses: `Ã À Â É Ê Ó Ô Õ Ú Ç` are
 * all fine, and every lowercase accented letter is fine (`á` is `0xC3 0xA1`,
 * which cp1252 knows). In Portuguese exactly two characters are affected —
 * **A-acute (U+00C1) and I-acute (U+00CD)** — with U+00CF, U+00D0 and U+00DD
 * completing the set for languages that use them. An over-broad rule in a
 * warning comment is exactly as durable as a wrong row in a limitations table,
 * and this round spent three waves proving that, so what is encoded here is
 * what was measured rather than the generalisation drawn from it.
 */

import { afterAll, describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { Buffer } from 'node:buffer';
import { copyFileSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const PACK_DIR = resolve(REPO_ROOT, 'configs', 'semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function semgrepAvailable(): boolean {
  try { execFileSync('semgrep', ['--version'], { stdio: 'ignore' }); return true; }
  catch { return false; }
}
const AVAILABLE = semgrepAvailable();

/**
 * The bytes cp1252 leaves undefined. A rule file containing any of them fails
 * to load with `'charmap' codec can't decode byte 0x…`, and the scan that
 * follows reports nothing rather than reporting an error.
 */
const UNDECODABLE_BYTES: ReadonlySet<number> = new Set([0x81, 0x8d, 0x8f, 0x90, 0x9d]);

/**
 * Packs that do NOT currently pass `--validate`, each pinned to the EXACT rule
 * that breaks it. This is a quarantine, not an exemption, and it is written to
 * be uncomfortable to keep:
 *
 *  - if the pack starts validating cleanly, this test FAILS and tells you to
 *    delete the entry — a quarantine that outlives its defect is how a
 *    permanent exception gets born;
 *  - if the pack breaks for a DIFFERENT reason, this test fails too, because
 *    the entry pins the rule id rather than merely tolerating a non-zero exit.
 *
 * `base.yml` / `wp-unescaped-output`: `pattern: echo $_GET[$X]` does not parse
 * as PHP (`Stdlib.Parsing.Parse_error`), so **the WordPress XSS rule has never
 * been able to match anything.** Measured against a PHP file containing a real
 * `echo $_GET['name'];`: `results: 0`, `errors: 1`, exit 2 — the rule is dead,
 * and the one thing standing between that and total silence is the error entry.
 * Found by this test on its first run.
 *
 * It is NOT fixed here on purpose: `base.yml` is outside the branch this test
 * arrived on, and the five non-Java packs are queued for a sweep of their own.
 * This wave adds the coverage; the sweep does the edits.
 */
const KNOWN_INVALID: ReadonlyMap<string, string> = new Map([
  ['base.yml', 'wp-unescaped-output'],
]);

/** Every rule pack on disk, in name order. Discovered, never listed. */
function packFiles(): string[] {
  return readdirSync(PACK_DIR)
    .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
    .sort();
}

interface Offence {
  readonly file: string;
  readonly line: number;
  readonly character: string;
  readonly codePoint: string;
  readonly byte: string;
}

/**
 * Scans TEXT rather than a path, so the positive control below can poison a
 * copy without touching a real pack. Iterating characters rather than bytes is
 * deliberate: it lets the failure name the character the author actually typed,
 * which is the thing they need to find and delete. A byte offset alone would
 * send them looking at a hex dump.
 */
function scanText(file: string, text: string): Offence[] {
  const found: Offence[] = [];
  let line = 1;
  for (const character of text) {
    if (character === '\n') {
      line += 1;
      continue;
    }
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined || codePoint < 0x80) continue;
    for (const byte of Buffer.from(character, 'utf8')) {
      if (!UNDECODABLE_BYTES.has(byte)) continue;
      found.push({
        file,
        line,
        character,
        codePoint: `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`,
        byte: `0x${byte.toString(16).toUpperCase().padStart(2, '0')}`,
      });
    }
  }
  return found;
}

function scanPack(file: string): Offence[] {
  return scanText(file, readFileSync(resolve(PACK_DIR, file), 'utf8'));
}

/**
 * The failure has to explain itself. The symptom a developer sees otherwise is
 * a pack that finds nothing, which looks exactly like a clean project, so a
 * bare "expected 1 to be 0" would send them to their own rules or their own
 * code rather than to an encoding problem they have no reason to suspect.
 */
function renderOffences(offences: readonly Offence[]): string {
  if (offences.length === 0) return '';
  return [
    'Semgrep loads rule files with the LOCALE codec, not UTF-8. On a cp1252',
    'locale these bytes are undefined, so the pack below fails to load ENTIRELY',
    'and the scan then reports results:0 scanned:0 errors:0 — a clean-looking',
    'run that checked nothing. Replace the character, or use its lowercase form.',
    ...offences.map(
      (o) => `  ${o.file}:${o.line} — '${o.character}' (${o.codePoint}) encodes to byte ${o.byte}`,
    ),
  ].join('\n');
}

describe('every Semgrep rule pack', () => {
  const packs = packFiles();

  // A glob that silently matched nothing would make every assertion below pass
  // by checking zero files — the same failure mode as `paths.scanned` being 0,
  // which is the trap this whole file is about. So the discovery is asserted
  // before anything is asserted about what it discovered.
  it('discovers the packs on disk, and the discovery is not empty', () => {
    expect(packs.length).toBeGreaterThan(0);
    // A SUBSET check, not equality: a new pack must be covered by existing on
    // disk, so this must not need editing when one lands. What it does catch is
    // a pack silently disappearing, or the directory being moved out from under
    // this test.
    expect(packs).toEqual(expect.arrayContaining([
      'bugfix-go.yml',
      'bugfix-java.yml',
      'bugfix-js.yml',
      'bugfix-py.yml',
    ]));
  });

  it('contains no byte the locale codec cannot decode', () => {
    expect(renderOffences(packs.flatMap(scanPack))).toBe('');
  });

  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE).toBe(true);
  });

  it.skipIf(!AVAILABLE)('compiles clean, silently, and exits 0 — or is quarantined', () => {
    // `--quiet` is what makes "both streams empty" a usable assertion at all:
    // without it semgrep writes its `Configuration is valid …` banner to STDERR
    // on SUCCESS, so the empty-stderr half would fail on a healthy file. With
    // it, success is silence and the exit code carries the signal — measured
    // against the three known parse traps, which return 2, 5 and 2.
    // `--disable-version-check` is passed because the upgrade notice is network
    // state, and an empty-stderr assertion hostage to network state is a flake
    // waiting to happen.
    const problems = packs
      .map((file) => {
        const config = resolve(PACK_DIR, file);
        const quarantinedRule = KNOWN_INVALID.get(file);
        if (quarantinedRule === undefined) {
          const run = spawnSync(
            'semgrep',
            ['--validate', '--quiet', '--disable-version-check', '--config', config],
            { encoding: 'utf8' },
          );
          if (run.status === 0 && run.stdout === '' && run.stderr === '') return '';
          return [
            `${file}: does not compile. exit=${String(run.status)}`,
            `  stdout=${JSON.stringify(run.stdout)}`,
            `  stderr=${JSON.stringify(run.stderr)}`,
            '  A pack that fails to load does NOT fail the scan that uses it — it',
            '  returns fewer findings, or none, and can report zero errors while',
            '  doing so. Re-run without --quiet to see the reason.',
          ].join('\n');
        }
        // Quarantined: run WITHOUT --quiet, because the reason has to be read
        // off stderr to confirm it is still the same reason.
        const run = spawnSync(
          'semgrep',
          ['--validate', '--disable-version-check', '--config', config],
          { encoding: 'utf8' },
        );
        if (run.status === 0) {
          return `${file}: now validates CLEAN — delete its KNOWN_INVALID entry (${quarantinedRule}).`;
        }
        if (!run.stderr.includes(quarantinedRule)) {
          return [
            `${file}: is quarantined for ${quarantinedRule}, but now fails for something else.`,
            `  stderr=${JSON.stringify(run.stderr)}`,
          ].join('\n');
        }
        return '';
      })
      .filter((line) => line !== '');
    expect(problems).toEqual([]);
  });
});

/**
 * POSITIVE CONTROL — proof that the two assertions above can still fail.
 *
 * Asserting that every pack is clean proves nothing on its own if the check has
 * quietly stopped working: a scan function that returns `[]` for every input,
 * or a `--validate` invocation that stopped reaching semgrep, would both look
 * exactly like a healthy repo. The same hole was found in the Go round's
 * no-duplication test and was closed the same way.
 *
 * So a REAL pack is copied to a temp directory and one A-acute is injected into
 * a comment there. Nothing under `configs/` is touched: poisoning a tracked file
 * to see a test go red is how a poisoned file gets committed.
 */
describe('the encoding check can actually fail', () => {
  const POISON = String.fromCodePoint(0xc1); // A-acute. Written by codepoint —
  // spelling it literally here would put the offending byte in this file, and
  // while a `.ts` file is always read as UTF-8 and would survive it, the habit
  // is what matters: the rule file's own warning cannot spell it either.

  function poisonedCopy(): string {
    const dir = makeTempDir('guardian-semgrep-poison-');
    const source = resolve(PACK_DIR, 'bugfix-java.yml');
    const target = resolve(dir, 'bugfix-java.yml');
    copyFileSync(source, target);
    const text = readFileSync(target, 'utf8');
    // Injected into the FIRST comment line, so the file stays valid YAML and
    // valid Semgrep in every respect except the encoding. The point is that the
    // pack is otherwise perfect and still fails to load.
    const poisoned = text.replace('#', `# ${POISON}`);
    expect(poisoned).not.toBe(text);
    writeFileSync(target, poisoned, 'utf8');
    return target;
  }

  it('the byte scan reports the injected character, its codepoint and its byte', () => {
    const target = poisonedCopy();
    const offences = scanText(basename(target), readFileSync(target, 'utf8'));
    expect(offences.map((o) => [o.character, o.codePoint, o.byte])).toEqual([
      [POISON, 'U+00C1', '0x81'],
    ]);
    // And the rendered failure names the mechanism, not just the position.
    expect(renderOffences(offences)).toContain('LOCALE codec, not UTF-8');
  });

  it.skipIf(!AVAILABLE)('and semgrep --validate refuses the poisoned pack', () => {
    const target = poisonedCopy();
    const run = spawnSync(
      'semgrep',
      ['--validate', '--quiet', '--disable-version-check', '--config', target],
      { encoding: 'utf8' },
    );
    expect(run.status).not.toBe(0);
  });

  it.skipIf(!AVAILABLE)('and a SCAN with it reports nothing at all, with no error', () => {
    // The measurement that makes this trap worth a test rather than a comment.
    // A broken pack does not fail the scan — it produces a clean-looking result
    // with zero findings, zero files scanned and zero errors. This is the
    // symptom a developer would otherwise have to diagnose from scratch.
    const target = poisonedCopy();
    const dir = makeTempDir('guardian-semgrep-poison-target-');
    writeFileSync(resolve(dir, 'Sample.java'), 'class Sample { void f() {} }\n', 'utf8');
    const run = spawnSync(
      'semgrep',
      ['--config', target, '--json', '--quiet', '--no-git-ignore', dir],
      { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
    );
    expect(run.status).not.toBe(0);
    if (run.stdout !== '') {
      const parsed: unknown = JSON.parse(run.stdout);
      const report = parsed as { results?: unknown[]; errors?: unknown[]; paths?: { scanned?: unknown[] } };
      expect({
        results: report.results?.length ?? 0,
        scanned: report.paths?.scanned?.length ?? 0,
        errors: report.errors?.length ?? 0,
      }).toEqual({ results: 0, scanned: 0, errors: 0 });
    }
  });
});
