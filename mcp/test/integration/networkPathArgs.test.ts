/**
 * Every tool argument that names a local path is held to the rule
 * `project_path` is (review 11, finding 8): on Windows a network path —
 * `\\host\share`, `//host/share`, `\\?\UNC\…`, a `file://host/…` URL, or a
 * local spelling a link leads to a share — is refused before any file call,
 * because any file call on it authenticates to the host it names over SMB
 * (an NTLM hash to a host the caller chose), and blocks about 21 s on one
 * that does not answer. 192.0.2.1 is RFC 5737 TEST-NET-1: nothing answers.
 *
 * `project_path` itself is covered where `toolProjectPath` is
 * (`vetPackages.test.ts` for the tool that skipped it); these are the other
 * path-shaped arguments the sweep found: `wp_install_path` (wp_vuln_check,
 * wp_plugin_check), `scan_skill`'s `target` and `map_attack_surface`'s
 * `spec_paths`.
 */
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { customRulesMetaKey, inspectCustomSemgrepConfigs } from '../../src/platform/customRules.js';
import { networkPathOf, networkPathProblem } from '../../src/platform/projectPath.js';
import { ingestTarget } from '../../src/skillaudit/ingest.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { TOOLS } from '../../src/tools/index.js';
import { wpInstallPathProblem } from '../../src/wordpress/siteKeys.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { hangBound } from '../helpers/timing.js';

const WIN = process.platform === 'win32';
const UNC = '\\\\192.0.2.1\\share\\x';
const SPELLINGS = [UNC, '//192.0.2.1/share/x', '\\\\?\\UNC\\192.0.2.1\\share\\x'];

beforeAll(async () => {
  await import('../../src/tools/mapAttackSurface.js');
  await import('../../src/tools/wpVulnCheck.js');
  await import('../../src/tools/registerCustomRules.js');
  await import('../../src/tools/importSarif.js');
});
afterAll(cleanupTempDirs);

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: process.cwd(), progressNotifier: { send: () => {} } };
}

/** A directory symbolic link to the share, or null without the privilege to make one. */
function linkToShare(): string | null {
  const dir = makeTempDir('dg-netarg-');
  const link = join(dir, 'share');
  try {
    symlinkSync(UNC, link, 'dir');
    return link;
  } catch {
    return null;
  }
}

describe('networkPathOf', () => {
  it.runIf(WIN)('names every network spelling, and the link a local spelling goes through', () => {
    for (const p of SPELLINGS) expect(networkPathOf(p), p).not.toBeNull();
    const link = linkToShare();
    if (link !== null) expect(networkPathOf(join(link, 'a', 'b'))?.via).toBe(link);
  });

  it('a local path is local, on every platform', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dg-netarg-local-'));
    try {
      expect(networkPathOf(dir)).toBeNull();
      expect(networkPathProblem('x', dir)).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.runIf(!WIN)('POSIX: //x is a local path', () => {
    expect(networkPathOf('//tmp')).toBeNull();
  });
});

describe.runIf(WIN)('Windows: path arguments other than project_path refuse a share', () => {
  it('wp_install_path (wp_vuln_check, wp_plugin_check)', () => {
    for (const p of SPELLINGS) {
      const t0 = Date.now();
      expect(wpInstallPathProblem(p), p).toMatch(/network \(UNC\) path/);
      expect(Date.now() - t0).toBeLessThan(hangBound(1000));
    }
    const link = linkToShare();
    if (link !== null) expect(wpInstallPathProblem(join(link, 'wp'))).toMatch(/through the link/);
  });

  it("wp_vuln_check answers unsupported_target, never existsSync's 21 s", async () => {
    const tool = TOOLS.find((t) => t.name === 'wp_vuln_check');
    if (tool === undefined) throw new Error('wp_vuln_check not registered');
    const t0 = Date.now();
    const r = (await tool.handler({ wp_install_path: UNC }, plugin())) as { ok: boolean; error?: { code: string } };
    expect(Date.now() - t0).toBeLessThan(hangBound(1000));
    expect(r.ok).toBe(false);
    expect(r.error?.code).toBe('unsupported_target');
  });

  it("scan_skill's target: a share, a .git on a share, a file:// URL with a host and a link", async () => {
    const targets = [...SPELLINGS, `${UNC}\\repo.git`, 'file://192.0.2.1/share/repo.git'];
    const link = linkToShare();
    if (link !== null) targets.push(join(link, 'skill'));
    for (const target of targets) {
      const t0 = Date.now();
      const r = await ingestTarget(target);
      expect(Date.now() - t0, target).toBeLessThan(hangBound(1000));
      expect(r.ok, target).toBe(false);
      if (!r.ok) expect(r.code).toBe('unsupported_target');
    }
  });

  it("map_attack_surface's spec_paths: a spec on a share is reported unread, never opened", async () => {
    const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
    if (tool === undefined) throw new Error('map_attack_surface not registered');
    const project = makeTempDir('dg-netarg-surface-');
    const t0 = Date.now();
    const r = (await tool.handler({ project_path: project, spec_paths: [`${UNC}\\openapi.yaml`] }, plugin())) as {
      ok: boolean;
      spec_files?: Array<{ file: string; status: string; reason?: string }>;
    };
    expect(Date.now() - t0).toBeLessThan(hangBound(5000));
    expect(r.ok).toBe(true);
    expect(r.spec_files?.find((f) => f.file.includes('192.0.2.1'))?.reason).toMatch(/network/);
  });

  // Review 12, finding 9: three more path arguments reached SMB.
  it('register_custom_rules: a share, or a link to one, is rejected — and a stored one is never re-read by a scan', async () => {
    const tool = TOOLS.find((t) => t.name === 'register_custom_rules');
    if (tool === undefined) throw new Error('register_custom_rules not registered');
    const project = makeTempDir('dg-netarg-rules-');
    const paths = [`${UNC}\\rules.yml`];
    const link = linkToShare();
    if (link !== null) paths.push(join(link, 'rules.yml'));
    const ctx = plugin();
    const t0 = Date.now();
    const r = (await tool.handler({ project_path: project, paths }, ctx)) as {
      ok: boolean;
      registered?: string[];
      rejected?: Array<{ path: string; reason: string }>;
    };
    expect(Date.now() - t0).toBeLessThan(hangBound(2000));
    expect(r.registered ?? []).toEqual([]);
    expect((r.rejected ?? []).length).toBe(paths.length);
    for (const x of r.rejected ?? []) expect(x.reason).toMatch(/network \(UNC\) path/);
    // A registration stored before the check: read on every scan, never opened.
    ctx.storage.runtimeMeta.setJson(customRulesMetaKey(project), [`${UNC}\\rules.yml`]);
    const t1 = Date.now();
    const inspected = inspectCustomSemgrepConfigs(ctx, project);
    expect(Date.now() - t1).toBeLessThan(hangBound(1000));
    expect(inspected.usable).toEqual([]);
    expect(inspected.unusable[0]?.reason).toMatch(/not read: .*network/);
  });

  it('scan_skill: a file:////host URL, and a local repository whose objects/info/alternates names a share', async () => {
    const repo = join(makeTempDir('dg-netarg-alt-'), 'skill.git');
    mkdirSync(join(repo, 'objects', 'info'), { recursive: true });
    writeFileSync(join(repo, 'objects', 'info', 'alternates'), `${UNC}\\objects\n`);
    const targets = ['file:////192.0.2.1/share/x.git', 'file://192.0.2.1/share/x.git', repo, `file:///${repo.split('\\').join('/')}`];
    for (const target of targets) {
      const t0 = Date.now();
      const r = await ingestTarget(target);
      expect(Date.now() - t0, target).toBeLessThan(hangBound(1000));
      expect(r.ok, target).toBe(false);
      if (!r.ok) {
        expect(r.code).toBe('unsupported_target');
        expect(r.message, target).toMatch(/network/);
      }
    }
  });

  it('import_sarif: a log on a share is refused even with allow_outside_project', async () => {
    const tool = TOOLS.find((t) => t.name === 'import_sarif');
    if (tool === undefined) throw new Error('import_sarif not registered');
    const project = makeTempDir('dg-netarg-sarif-');
    for (const sarif_path of [`${UNC}\\results.sarif`, '//192.0.2.1/share/results.sarif']) {
      const t0 = Date.now();
      const r = (await tool.handler({ project_path: project, sarif_path, allow_outside_project: true }, plugin())) as {
        ok: boolean;
        error?: { code: string; message: string };
      };
      expect(Date.now() - t0, sarif_path).toBeLessThan(hangBound(1000));
      expect(r.ok).toBe(false);
      expect(r.error?.code).toBe('unsupported_target');
      expect(r.error?.message).toMatch(/network/);
    }
  });
});
