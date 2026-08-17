import { describe, expect, it } from 'vitest';
import { deriveTestCommand, TEST_MANIFESTS } from '../../../src/fixpr/testCommand.js';

describe('deriveTestCommand', () => {
  it('reads scripts.test out of package.json', () => {
    const r = deriveTestCommand({
      'package.json': JSON.stringify({ scripts: { test: 'vitest run' } }),
    });
    expect(r).toEqual({ command: 'npm', args: ['test', '--silent'],
      origin: 'package.json scripts.test' });
  });

  it('returns null when package.json declares no test script', () => {
    // npm's default `test` script exits 1 with "no test specified". Running it
    // would report every project without tests as a broken build.
    expect(deriveTestCommand({ 'package.json': JSON.stringify({ scripts: { build: 'tsc' } }) }))
      .toBeNull();
  });

  it('returns null for npm\'s placeholder test script', () => {
    expect(deriveTestCommand({
      'package.json': JSON.stringify({
        scripts: { test: 'echo "Error: no test specified" && exit 1' },
      }),
    })).toBeNull();
  });

  it('derives cargo test from Cargo.toml', () => {
    expect(deriveTestCommand({ 'Cargo.toml': '[package]\nname = "x"' }))
      .toEqual({ command: 'cargo', args: ['test'], origin: 'Cargo.toml' });
  });

  it('derives go test from go.mod', () => {
    expect(deriveTestCommand({ 'go.mod': 'module x' }))
      .toEqual({ command: 'go', args: ['test', './...'], origin: 'go.mod' });
  });

  it('derives pytest from pyproject.toml only when pytest is actually configured', () => {
    expect(deriveTestCommand({ 'pyproject.toml': '[tool.pytest.ini_options]\n' }))
      .toEqual({ command: 'pytest', args: [], origin: 'pyproject.toml [tool.pytest]' });
    // A pyproject with no pytest section proves nothing about how to test it.
    expect(deriveTestCommand({ 'pyproject.toml': '[project]\nname = "x"\n' })).toBeNull();
  });

  it('returns null on unparseable JSON rather than guessing', () => {
    expect(deriveTestCommand({ 'package.json': '{not json' })).toBeNull();
  });

  it('returns null when nothing is recognised', () => {
    expect(deriveTestCommand({})).toBeNull();
    expect(deriveTestCommand({ 'Makefile': 'test:\n\techo hi' })).toBeNull();
  });

  it('lists exactly the manifests it reads, so the caller cannot drift from it', () => {
    expect([...TEST_MANIFESTS].sort())
      .toEqual(['Cargo.toml', 'go.mod', 'package.json', 'pyproject.toml']);
  });

  it('never returns a command assembled from manifest text', () => {
    // The whole reason the command is derived rather than accepted: nothing a
    // repository file CONTAINS may become something we execute. A malicious
    // scripts.test selects `npm test`; it does not become the argv.
    const r = deriveTestCommand({
      'package.json': JSON.stringify({ scripts: { test: 'rm -rf / # pwned' } }),
    });
    expect(r?.command).toBe('npm');
    expect(r?.args).toEqual(['test', '--silent']);
  });

  // --- Additional coverage beyond the brief -------------------------------
  //
  // This project's ledger already records FOUR bugs from `??` treating a
  // falsy-but-present value as "absent" (e.g. candidates.ts's rule_id
  // fallback). scripts.test = '' is exactly that shape: present, a string,
  // and unusable. It gets its own tests rather than trusting the
  // placeholder-string test above to cover it by accident.

  it('returns null for an empty-string scripts.test, not the npm command', () => {
    // A wrong implementation reading `scripts.test ?? null` would leave ''
    // untouched (`??` only falls through on null/undefined) and go on to
    // return the npm command for a script that runs nothing at all.
    expect(deriveTestCommand({ 'package.json': JSON.stringify({ scripts: { test: '' } }) }))
      .toBeNull();
  });

  it('returns null for a whitespace-only scripts.test', () => {
    // Distinguishes a bare `.length === 0` check (would pass this through)
    // from a trimmed one (correctly rejects it) — whitespace is exactly as
    // unusable as empty.
    expect(deriveTestCommand({ 'package.json': JSON.stringify({ scripts: { test: '   ' } }) }))
      .toBeNull();
  });

  it('returns null, not a throw, when package.json scripts is null', () => {
    // `typeof null === 'object'` is the classic JS trap: a guard that checks
    // only `typeof value === 'object'` — without also excluding null — would
    // hand `null` on to a `.test` property read and throw instead of
    // returning null.
    expect(deriveTestCommand({ 'package.json': JSON.stringify({ scripts: null }) }))
      .toBeNull();
  });

  it('returns null, not a throw, when package.json itself parses to null', () => {
    // Same trap one level up: 'null' is valid JSON. JSON.parse('null')
    // returns the value null, not a parse failure and not an absence.
    expect(deriveTestCommand({ 'package.json': 'null' })).toBeNull();
  });

  it('prefers package.json over Cargo.toml when both are present, regardless of key order', () => {
    // Cargo.toml is declared FIRST in this object literal. An implementation
    // that walks Object.entries(files) in input order — instead of the fixed
    // precedence list package.json -> Cargo.toml -> go.mod -> pyproject.toml
    // — would try Cargo.toml first and return `cargo test`.
    const r = deriveTestCommand({
      'Cargo.toml': '[package]\nname = "x"',
      'package.json': JSON.stringify({ scripts: { test: 'vitest run' } }),
    });
    expect(r).toEqual({ command: 'npm', args: ['test', '--silent'],
      origin: 'package.json scripts.test' });
  });

  it('falls through to the next manifest when the higher-precedence one has no usable test', () => {
    // Precedence decides which ANSWER wins when more than one manifest could
    // supply one; it is not a reason to stop at the first manifest merely
    // present. A stray package.json with no real tests must not hide a real
    // Cargo.toml suite sitting right next to it.
    const r = deriveTestCommand({
      'package.json': JSON.stringify({ scripts: { build: 'tsc' } }),
      'Cargo.toml': '[package]\nname = "x"',
    });
    expect(r).toEqual({ command: 'cargo', args: ['test'], origin: 'Cargo.toml' });
  });

  it('derives cargo test from an empty-but-present Cargo.toml', () => {
    // Presence, not truthiness: files['Cargo.toml'] === '' must still count
    // as "found" — the same falsy-vs-absent shape as scripts.test = ''.
    expect(deriveTestCommand({ 'Cargo.toml': '' }))
      .toEqual({ command: 'cargo', args: ['test'], origin: 'Cargo.toml' });
  });

  it('derives go test from an empty-but-present go.mod', () => {
    expect(deriveTestCommand({ 'go.mod': '' }))
      .toEqual({ command: 'go', args: ['test', './...'], origin: 'go.mod' });
  });

  it('matches [tool.pytest] on a second call, not just the first', () => {
    // A regex reused with a `g` or `y` flag advances `lastIndex` after a
    // match, so a second call against the very same input can silently miss
    // what the first call found. vitest runs every `it` in this file inside
    // one module instance, so a stateful regex here would surface as
    // flakiness that depends on test order rather than as a clean failure.
    const files = { 'pyproject.toml': '[tool.pytest.ini_options]\n' };
    expect(deriveTestCommand(files)).not.toBeNull();
    expect(deriveTestCommand(files)).not.toBeNull();
  });

  it('never lets pyproject.toml content leak into the returned command either', () => {
    // The same property the brief's last test pins for package.json, checked
    // for the other manifest whose content actually varies rather than being
    // ignored outright (Cargo.toml, go.mod).
    const r = deriveTestCommand({
      'pyproject.toml': '[tool.pytest.ini_options]\naddopts = "; rm -rf / #"\n',
    });
    expect(r).toEqual({ command: 'pytest', args: [], origin: 'pyproject.toml [tool.pytest]' });
  });
});
