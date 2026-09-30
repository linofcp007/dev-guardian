/**
 * Windows: a repository link to a network path is never followed — not to
 * read it, not to `stat` it, not to ask whether it exists (review of 3.0,
 * W2E, round 2, I4).
 *
 * The reviewer measured `existsSync` of a `package.json` linked to
 * `\\192.0.2.1\share\x\package.json` blocking for 157 221 ms while Windows
 * tried to reach the host — and it authenticates to whatever answers. `lstat`
 * of the same link took 1 ms. Every case here plants such a link (or names
 * such a path in a repository file) and requires the code to return in well
 * under the SMB timeout. 192.0.2.1 is RFC 5737 TEST-NET-1: nothing answers,
 * so a follow can only wait. Creating a symbolic link needs the privilege
 * (Developer Mode or an elevated shell); without it the file is skipped,
 * visibly.
 */
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { checkRequirements, describePipRefusal } from '../../src/deps/pipRequirements.js';
import { planDotnetRestore, readPackageReferences } from '../../src/deps/dotnetRestore.js';
import { ensureGuardianIgnored } from '../../src/gitignoreGuard.js';
import { projectPathTest } from '../../src/platform/guardianIgnore.js';
import { entryKindAnywhere, presentInProject, projectPathKind } from '../../src/platform/projectFs.js';
import { honouredHandedFiles } from '../../src/runners/repoConfig.js';
import { assessManifestCoverage } from '../../src/runners/scannerParsers/trivy.js';
import { detectStack } from '../../src/runners/stackDetect.js';
import { ingestTarget } from '../../src/skillaudit/ingest.js';
import { collectPorts } from '../../src/surface/collectors/ports.js';
import { inventoryWordPressSource } from '../../src/wordpress/sourceInventory.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const UNC = '\\\\192.0.2.1\\share\\x';
/** Far below the 157 s a followed link took, far above a loaded machine's lstat walk. */
const BOUND_MS = 10_000;

const CAN_LINK = ((): boolean => {
  if (process.platform !== 'win32') return false;
  const d = mkdtempSync(join(tmpdir(), 'dg-canlink-'));
  try {
    symlinkSync(`${UNC}\\probe`, join(d, 'probe'), 'file');
    return true;
  } catch {
    return false;
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
})();

function fileLink(dir: string, name: string): void {
  symlinkSync(`${UNC}\\${name.replace(/\//g, '\\')}`, join(dir, ...name.split('/')), 'file');
}
function dirLink(dir: string, name: string): void {
  symlinkSync(UNC, join(dir, ...name.split('/')), 'dir');
}
async function timed<T>(f: () => T | Promise<T>): Promise<{ ms: number; value: T }> {
  const t0 = Date.now();
  const value = await f();
  return { ms: Date.now() - t0, value };
}

describe.runIf(CAN_LINK)('Windows — links to \\\\192.0.2.1 (RFC 5737) are never followed', () => {
  it('the primitives: presence, kind, and a path named anywhere', async () => {
    const p = makeTempDir('dg-unc-');
    fileLink(p, 'package.json');
    const { ms, value } = await timed(() => [
      presentInProject(p, 'package.json'),
      projectPathKind(p, 'package.json'),
      entryKindAnywhere(join(p, 'package.json')),
      entryKindAnywhere(`${UNC}\\y.csproj`),
    ]);
    expect(value).toEqual([true, 'outside', 'remote', 'remote']);
    expect(ms).toBeLessThan(BOUND_MS);
  });

  it('detect_stack: a package.json and a pyproject.toml linked to a share are named, not read', async () => {
    const p = makeTempDir('dg-unc-');
    fileLink(p, 'package.json');
    fileLink(p, 'pyproject.toml');
    const { ms, value } = await timed(() => detectStack(p));
    expect(ms).toBeLessThan(BOUND_MS);
    const unread = (value.unread_files ?? []).map((u) => u.path).join('\n');
    expect(unread).toMatch(/package\.json/);
    expect(unread).toMatch(/pyproject\.toml/);
  });

  it("Trivy's coverage: a yarn.lock linked to a share", async () => {
    const p = makeTempDir('dg-unc-');
    writeFileSync(join(p, 'package.json'), '{"name":"x","dependencies":{"a":"1"}}');
    fileLink(p, 'yarn.lock');
    const { ms, value } = await timed(() => assessManifestCoverage(p, '{"Results":[]}'));
    expect(ms).toBeLessThan(BOUND_MS);
    // Round 3 (a): named as what it is — it read "yarn.lock/ (a directory link …)".
    expect(value.walkIncomplete).toBe('did not follow yarn.lock (a link to a network path, never followed)');
  });

  it("the scanner-config naming: a requirements file linked to a share, handed to pip-audit", async () => {
    const p = makeTempDir('dg-unc-');
    fileLink(p, 'requirements.txt');
    const { ms } = await timed(() => honouredHandedFiles(p, 'pip-audit', ['requirements.txt']));
    expect(ms).toBeLessThan(BOUND_MS);
  });

  it('pip: an include through a link to a share, and one naming the share, are refused as network paths', async () => {
    const p = makeTempDir('dg-unc-');
    writeFileSync(join(p, 'requirements.txt'), '-r more.txt\n');
    fileLink(p, 'more.txt');
    const q = makeTempDir('dg-unc-');
    writeFileSync(join(q, 'requirements.txt'), `-r ${UNC}\\more.txt\n`);
    const { ms, value } = await timed(() => [
      checkRequirements(p, ['requirements.txt'], p).refusals.map(describePipRefusal),
      checkRequirements(q, ['requirements.txt'], q).refusals.map(describePipRefusal),
    ]);
    expect(ms).toBeLessThan(BOUND_MS);
    expect(value[0]?.join()).toMatch(/requirements\.txt:1: /);
    expect(value[1]).toEqual(['requirements.txt:1: network path (\\\\192.0.2.1)']);
  });

  it('scan_skill: a skill file linked to a share is listed as a link, never opened', async () => {
    const p = makeTempDir('dg-unc-');
    writeFileSync(join(p, 'SKILL.md'), '# s\n');
    fileLink(p, 'run.sh');
    const { ms, value } = await timed(() => ingestTarget(p));
    expect(ms).toBeLessThan(BOUND_MS);
    expect(value.ok).toBe(true);
  });

  it('startup: a .git linked to a share does not stall the .gitignore upkeep', async () => {
    const p = makeTempDir('dg-unc-');
    dirLink(p, '.git');
    const { ms } = await timed(() => ensureGuardianIgnored(p));
    expect(ms).toBeLessThan(BOUND_MS);
  });

  it('.guardianignore matching: a directory linked to a share', async () => {
    const p = makeTempDir('dg-unc-');
    dirLink(p, 'vendor');
    const { ms } = await timed(() => projectPathTest(p)('vendor/lib/a.js'));
    expect(ms).toBeLessThan(BOUND_MS);
  });

  it('dotnet: a ProjectReference on a share blocks the restore, named, without opening it', async () => {
    const p = makeTempDir('dg-unc-');
    writeFileSync(join(p, 'a.csproj'), `<Project><ItemGroup><ProjectReference Include="${UNC}\\b.csproj" /></ItemGroup></Project>`);
    const { ms, value } = await timed(() => planDotnetRestore(p, join(p, 'a.csproj')));
    expect(ms).toBeLessThan(BOUND_MS);
    expect(value.blocked?.code).toBe('network_path_reference');
    const refs = await timed(() => readPackageReferences([`${UNC}\\b.csproj`]));
    expect(refs.ms).toBeLessThan(BOUND_MS);
  });

  it('the attack surface: a Dockerfile linked to a share', async () => {
    const p = makeTempDir('dg-unc-');
    fileLink(p, 'Dockerfile');
    const { ms, value } = await timed(() => collectPorts(p));
    expect(ms).toBeLessThan(BOUND_MS);
    expect(value).toEqual([]);
  });

  it('WordPress: wp-content/plugins linked to a share is named not inventoried', async () => {
    const p = makeTempDir('dg-unc-');
    mkdirSync(join(p, 'wp-includes'));
    writeFileSync(join(p, 'wp-includes', 'version.php'), "<?php\n$wp_version = '6.5.0';\n");
    mkdirSync(join(p, 'wp-content'));
    dirLink(p, 'wp-content/plugins');
    const { ms, value } = await timed(() => inventoryWordPressSource(p));
    expect(ms).toBeLessThan(BOUND_MS);
    expect(value.not_inventoried.join('\n')).toMatch(/wp-content\/plugins/);
  });
});
