/**
 * Runs `configs/semgrep/mobile.yml` -- the plugin's mobile configuration pack
 * -- against `mcp/test/fixtures/mobile/`:
 *
 *   hits/    an Android manifest, a network security config and an iOS
 *            Info.plist where every rule fires; each finding is listed below
 *            by file and line (XML has no end-of-line comment for the repo's
 *            `BUG:` marker inside a tag), and nothing else may fire;
 *   misses/  the safe shape of every rule: `false` values, a component with a
 *            permission (before or after `exported`), a provider with both
 *            permissions, the user CA under `<debug-overrides>`, local
 *            networking, a manifest placeholder, WebView debugging guarded by
 *            `BuildConfig.DEBUG` (on its line and as a block), a delegating
 *            TrustManager, a HostnameVerifier that compares; nothing fires. Its layout
 *            under `res/layout/` is never read (the network security rules
 *            read `res/xml/` only).
 *
 * `--validate` and the banned characters are `integration/semgrepPacks.test.ts`
 * (it discovers packs from disk); the ablation registry is `test/ablate/packs.ts`.
 *
 * Fixtures are copied to a temp dir before scanning: their in-repo path holds
 * a `test/` segment, which Semgrep's default ignore list skips -- and the
 * scanned files are asserted, so "nothing fired" never means "nothing read".
 *
 * SKIPPED, not silently passed, when Semgrep is absent;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that absence into a hard failure.
 */

import { afterAll, describe, expect, it, vi } from 'vitest';

vi.setConfig({ testTimeout: 180_000 });
import { cpSync, existsSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { semgrepAvailable, semgrepStdout } from '../helpers/semgrep.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const PACK = resolve(REPO_ROOT, 'configs', 'semgrep', 'mobile.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'mobile');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';
const AVAILABLE = semgrepAvailable();

const MANIFEST = 'app/src/main/AndroidManifest.xml';
const NSC = 'app/src/main/res/xml/network_security_config.xml';
const PLIST = 'ios/Fixture/Info.plist';
const JAVA = 'app/src/main/java/com/example/fixture/Web.java';
const KOTLIN = 'app/src/main/kotlin/com/example/fixture/Web.kt';
const SAFE_JAVA = 'app/src/main/java/com/example/fixture/Safe.java';
const SAFE_KOTLIN = 'app/src/main/kotlin/com/example/fixture/Safe.kt';

/** Every finding hits/ must produce: `rule file:line`, sorted. */
const EXPECTED_HITS = [
  `mobile-android-allow-backup ${MANIFEST}:4`,
  `mobile-android-cleartext-traffic ${MANIFEST}:6`,
  `mobile-android-debuggable ${MANIFEST}:5`,
  // The service, the receiver over several lines (its `<` line), the provider
  // in single quotes, and the provider with a read permission alone.
  `mobile-android-exported-component ${MANIFEST}:16`,
  `mobile-android-exported-component ${MANIFEST}:17`,
  `mobile-android-exported-component ${MANIFEST}:24`,
  `mobile-android-exported-component ${MANIFEST}:25`,
  `mobile-android-nsc-cleartext ${NSC}:3`,
  `mobile-android-nsc-cleartext ${NSC}:9`,
  `mobile-android-nsc-user-ca ${NSC}:6`,
  `mobile-ios-ats-arbitrary-loads ${PLIST}:11`,
  `mobile-ios-ats-arbitrary-loads ${PLIST}:9`,
  `mobile-ios-ats-insecure-exception ${PLIST}:17`,
  `mobile-ios-ats-insecure-exception ${PLIST}:19`,
  // Java and Kotlin, the same calls: `setX(true)` and `x = true`.
  `mobile-android-webview-debugging ${JAVA}:12`,
  `mobile-android-webview-debugging ${KOTLIN}:11`,
  `mobile-android-webview-js-interface ${JAVA}:14`,
  `mobile-android-webview-js-interface ${KOTLIN}:13`,
  `mobile-android-webview-file-url-access ${JAVA}:15`,
  `mobile-android-webview-file-url-access ${JAVA}:16`,
  `mobile-android-webview-file-url-access ${KOTLIN}:14`,
  `mobile-android-webview-file-url-access ${KOTLIN}:15`,
  `mobile-android-world-accessible-mode ${JAVA}:17`,
  `mobile-android-world-accessible-mode ${JAVA}:18`,
  `mobile-android-world-accessible-mode ${KOTLIN}:16`,
  `mobile-kotlin-trust-all-certificates ${KOTLIN}:21`,
  // The lambdas only: Java's class forms (lines 24-33) are the registry's.
  `mobile-hostname-verifier-accepts-all ${JAVA}:35`,
  // The lambda handed to the call, the commonest form, and typed parameters (review 3.6.1).
  `mobile-hostname-verifier-accepts-all ${JAVA}:37`,
  `mobile-hostname-verifier-accepts-all ${JAVA}:38`,
  `mobile-hostname-verifier-accepts-all ${KOTLIN}:25`,
  `mobile-hostname-verifier-accepts-all ${KOTLIN}:26`,
].sort();

/** The CWE each rule declares, as `metadata.cwe` begins. */
const CWE: Readonly<Record<string, string>> = {
  'mobile-android-debuggable': 'CWE-489',
  'mobile-android-allow-backup': 'CWE-530',
  'mobile-android-cleartext-traffic': 'CWE-319',
  'mobile-android-exported-component': 'CWE-926',
  'mobile-android-nsc-cleartext': 'CWE-319',
  'mobile-android-nsc-user-ca': 'CWE-295',
  'mobile-ios-ats-arbitrary-loads': 'CWE-319',
  'mobile-ios-ats-insecure-exception': 'CWE-319',
  'mobile-android-webview-debugging': 'CWE-489',
  'mobile-android-webview-file-url-access': 'CWE-200',
  'mobile-android-webview-js-interface': 'CWE-749',
  'mobile-android-world-accessible-mode': 'CWE-276',
  'mobile-kotlin-trust-all-certificates': 'CWE-295',
  'mobile-hostname-verifier-accepts-all': 'CWE-295',
};

interface RawResult {
  readonly check_id?: unknown;
  readonly path?: unknown;
  readonly start?: { readonly line?: unknown };
  readonly extra?: { readonly metadata?: { readonly cwe?: unknown } };
}

interface Scan {
  readonly rows: ReadonlyArray<{ rule: string; at: string; cwe: string[] }>;
  readonly scanned: string[];
  readonly errors: readonly unknown[];
}

/** The path below the scanned root, cut at the temp dir's unique name. */
function relativeTo(root: string, reported: string): string {
  const posix = reported.replace(/\\/g, '/');
  const marker = `/${basename(root)}/`;
  const at = posix.indexOf(marker);
  return at === -1 ? posix : posix.slice(at + marker.length);
}

function scan(dir: string): Scan {
  const work = makeTempDir('guardian-mobile-');
  cpSync(dir, work, { recursive: true });
  const stdout = semgrepStdout([`--config=${PACK}`, '--json', '--quiet', '--no-git-ignore', '--metrics=off', work], { cwd: work });
  const report = JSON.parse(stdout) as { results?: RawResult[]; errors?: unknown[]; paths?: { scanned?: unknown[] } };
  return {
    rows: (report.results ?? []).map((r) => {
      const id = String(r.check_id ?? '');
      const cwe = r.extra?.metadata?.cwe;
      return {
        rule: id.split('.').pop() ?? id,
        at: `${relativeTo(work, String(r.path ?? ''))}:${String(r.start?.line)}`,
        cwe: Array.isArray(cwe) ? cwe.map(String) : [],
      };
    }),
    scanned: (report.paths?.scanned ?? []).map((p) => relativeTo(work, String(p))).sort(),
    errors: report.errors ?? [],
  };
}

describe('configs/semgrep/mobile.yml', () => {
  it('exists', () => {
    expect(existsSync(PACK)).toBe(true);
  });

  it.runIf(!AVAILABLE && REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1: semgrep must be on PATH', () => {
    expect(AVAILABLE, 'semgrep is not on PATH').toBe(true);
  });

  it.skipIf(!AVAILABLE)('hits/: every finding listed, nothing else, every file read, each rule with its CWE', () => {
    const s = scan(resolve(FIXTURES, 'hits'));
    expect(s.errors).toEqual([]);
    expect(s.scanned).toEqual([MANIFEST, NSC, PLIST, JAVA, KOTLIN].sort());
    expect(s.rows.map((r) => `${r.rule} ${r.at}`).sort()).toEqual(EXPECTED_HITS);
    expect(new Set(s.rows.map((r) => r.rule))).toEqual(new Set(Object.keys(CWE)));
    for (const r of s.rows) expect(r.cwe[0] ?? '', r.rule).toMatch(new RegExp(`^${CWE[r.rule] ?? 'none'}:`));
  });

  it.skipIf(!AVAILABLE)('misses/: nothing fires, and the layout outside res/xml/ is never read', () => {
    const s = scan(resolve(FIXTURES, 'misses'));
    expect(s.errors).toEqual([]);
    expect(s.scanned).toEqual([MANIFEST, NSC, PLIST, SAFE_JAVA, SAFE_KOTLIN].sort());
    expect(s.rows).toEqual([]);
  });
});
