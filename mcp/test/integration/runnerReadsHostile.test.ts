/**
 * The last raw reads of the scanned repository — the ten sites
 * `rawRepoFsSites.test.ts` used to list as `repo-deferred` (`runners/`,
 * `skillaudit/`) — now through `platform/projectFs.ts`, against the shapes
 * that broke them (review of 3.0, W2E). Measured on e27a37ae in `node:22`
 * (768 MB): `detectStack` on a `package.json` linked to `/dev/zero` was
 * OOM-killed in 10 s and a FIFO at that name hung it; `assessManifestCoverage`
 * on a `yarn.lock` linked to `/dev/zero`, `ruleIdsInFile` on one, and the
 * WordPress source inventory on a `version.php` linked to it were each
 * OOM-killed; a `.semgrep.yml` FIFO hung `ruleIdsInFile`. Each is now refused
 * at once, and — where what it would have said is something a tool reports on
 * — named.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { PROJECT_FILE_MAX_BYTES } from '../../src/platform/projectFs.js';
import { honouredFiles, honouredHandedFiles } from '../../src/runners/repoConfig.js';
import { assessManifestCoverage } from '../../src/runners/scannerParsers/trivy.js';
import { mayHoldTaintRules, ruleIdsInFile } from '../../src/runners/semgrepRuleIds.js';
import { detectStack } from '../../src/runners/stackDetect.js';
import { iacLookingFiles, judgeTrivyConfig } from '../../src/runners/trivyConfig.js';
import { ingestTarget } from '../../src/skillaudit/ingest.js';
import { openDatabase } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { StackSnapshot } from '../../src/types.js';
import { inventoryWordPressSource } from '../../src/wordpress/sourceInventory.js';
import { CAN_SYMLINK, POSIX } from '../helpers/fsCapabilities.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/detectStack.js');
});

/** Root can read a file whatever its mode: the "cannot be opened" cases need another user. */
const NOT_ROOT = POSIX && typeof process.getuid === 'function' && process.getuid() !== 0;

const fast = <T>(fn: () => T): T => {
  const t0 = Date.now();
  const out = fn();
  expect(Date.now() - t0).toBeLessThan(3000);
  return out;
};

const mkfifo = (path: string): void => {
  expect(spawnSync('mkfifo', [path]).status).toBe(0);
};

/** A file one byte over `cap`, of text that would otherwise parse (comments / whitespace). */
function oversized(path: string, cap: number, line = '# padding\n'): void {
  writeFileSync(path, line.repeat(Math.ceil((cap + 1) / line.length)));
}

describe('detect_stack — a hostile manifest never hangs or crashes the server, and is named', () => {
  it('an oversized package.json still says JavaScript, and is named in unread_files', () => {
    const p = makeTempDir('rrh-stack-');
    oversized(join(p, 'package.json'), PROJECT_FILE_MAX_BYTES, ' '.repeat(1023) + '\n');
    const snap = fast(() => detectStack(p));
    expect(snap.languages).toContain('javascript');
    expect(snap.unread_files).toEqual([
      { path: 'package.json', reason: 'it is larger than the size cap and was not read' },
    ]);
  });

  it.skipIf(!CAN_SYMLINK)('a package.json linked out of the project is not read, and is named', () => {
    const p = makeTempDir('rrh-stack-');
    const outside = makeTempDir('rrh-outside-');
    writeFileSync(join(outside, 'package.json'), '{"dependencies":{"react":"1"}}');
    symlinkSync(join(outside, 'package.json'), join(p, 'package.json'), 'file');
    const snap = detectStack(p);
    expect(snap.frameworks).not.toContain('react');
    expect(snap.unread_files).toEqual([
      { path: 'package.json', reason: 'it resolves outside the project (a link) and was not read' },
    ]);
  });

  it.skipIf(!POSIX)('a package.json linked to /dev/zero returns at once, named (POSIX)', () => {
    const p = makeTempDir('rrh-stack-');
    symlinkSync('/dev/zero', join(p, 'package.json'));
    const snap = fast(() => detectStack(p));
    expect(snap.languages).toContain('javascript');
    expect(snap.unread_files?.map((u) => u.path)).toEqual(['package.json']);
    // Round 3 (a): named by what it leads to — a file link to a device is no "directory link".
    expect(snap.unread_files?.[0]?.reason).not.toMatch(/directory/);
  });

  it.skipIf(!POSIX)('a FIFO package.json, pyproject.toml, requirements-dev.txt and deploy.yaml never wait for a writer, and each is named (POSIX)', () => {
    const p = makeTempDir('rrh-stack-');
    mkfifo(join(p, 'package.json'));
    mkfifo(join(p, 'pyproject.toml'));
    mkfifo(join(p, 'requirements-dev.txt'));
    mkfifo(join(p, 'deploy.yaml'));
    const snap = fast(() => detectStack(p));
    // Round 2 (M2): a FIFO under a candidate's name is read and refused, never dropped as "not a file".
    expect(snap.unread_files?.map((u) => u.path)).toEqual(['deploy.yaml', 'package.json', 'pyproject.toml', 'requirements-dev.txt']);
    for (const u of snap.unread_files ?? []) expect(u.reason).toMatch(/not a regular file/);
  });

  it('the detect_stack tool returns and persists the named file', async () => {
    const p = makeTempDir('rrh-stack-tool-');
    oversized(join(p, 'composer.json'), PROJECT_FILE_MAX_BYTES, ' '.repeat(1023) + '\n');
    const { db } = openDatabase({ inMemory: true, projectPath: tmpdir() });
    const ctx = { storage: new Storage(db) } as unknown as PluginContext;
    const tool = TOOLS.find((t) => t.name === 'detect_stack');
    const r = (await tool?.handler({ project_path: p }, ctx)) as { ok: boolean; snapshot?: StackSnapshot };
    expect(r.ok).toBe(true);
    expect(r.snapshot?.languages).toContain('php');
    expect(r.snapshot?.unread_files?.map((u) => u.path)).toEqual(['composer.json']);
  });
});

describe('Trivy manifest coverage — a refused manifest or lock file keeps its gap', () => {
  it('an oversized requirements.txt of comments only is a gap, not "declares nothing"', () => {
    const p = makeTempDir('rrh-trivy-');
    oversized(join(p, 'requirements.txt'), PROJECT_FILE_MAX_BYTES);
    const a = fast(() => assessManifestCoverage(p, '{"Results":[]}'));
    expect(a.gaps).toEqual([{ ecosystem: 'python', files: ['requirements.txt'] }]);
  });

  it.skipIf(!POSIX)('a yarn.lock linked to /dev/zero returns at once; the manifest stays a gap (POSIX)', () => {
    const p = makeTempDir('rrh-trivy-');
    writeFileSync(join(p, 'package.json'), '{"name":"x"}');
    symlinkSync('/dev/zero', join(p, 'yarn.lock'));
    const a = fast(() => assessManifestCoverage(p, '{"Results":[]}'));
    expect(a.gaps).toEqual([{ ecosystem: 'npm', files: ['package.json'] }]);
  });

  it.skipIf(!POSIX)('a FIFO package-lock.json and pnpm-workspace.yaml never wait for a writer (POSIX)', () => {
    const p = makeTempDir('rrh-trivy-');
    writeFileSync(join(p, 'package.json'), '{"name":"x"}');
    mkfifo(join(p, 'package-lock.json'));
    mkfifo(join(p, 'pnpm-workspace.yaml'));
    mkdirSync(join(p, 'web'));
    writeFileSync(join(p, 'web', 'package.json'), '{"dependencies":{"a":"1"}}');
    const a = fast(() => assessManifestCoverage(p, '{"Results":[{"Type":"npm","Target":"package-lock.json"}]}'));
    expect(a.gaps).toEqual([{ ecosystem: 'npm', files: ['web/package.json'] }]);
  });
});

describe('repoConfig — a `when` file that cannot be read is named, never dropped', () => {
  it('an oversized pyproject.toml is named for radon and ruff, saying it was not checked', async () => {
    const p = makeTempDir('rrh-cfg-');
    oversized(join(p, 'pyproject.toml'), 1024 * 1024);
    const radon = await honouredFiles(p, 'radon');
    expect(radon).toEqual([
      {
        path: 'pyproject.toml',
        decides:
          'its [tool.radon] excludes and ignores decide what is measured, if it applies: ' +
          'present, not checked: it is larger than the size cap and was not read',
      },
    ]);
  });

  it('a handed requirements file too large to check is named too', () => {
    const p = makeTempDir('rrh-cfg-');
    oversized(join(p, 'requirements.txt'), 1024 * 1024);
    const handed = honouredHandedFiles(p, 'pip-audit', ['requirements.txt']);
    expect(handed.map((h) => h.path)).toEqual(['requirements.txt']);
    expect(handed[0]?.decides).toMatch(/present, not checked: it is larger than the size cap/);
  });

  it.skipIf(!POSIX)('a FIFO at a config name is never opened, and is named as present, not checked (POSIX)', async () => {
    const p = makeTempDir('rrh-cfg-');
    mkfifo(join(p, 'pyproject.toml'));
    mkfifo(join(p, 'tox.ini'));
    const t0 = Date.now();
    const named = await honouredFiles(p, 'radon');
    expect(Date.now() - t0).toBeLessThan(3000);
    // Round 2 (I3): a config that could not be checked is never taken for absent.
    expect(named.map((h) => h.path)).toEqual(['pyproject.toml', 'tox.ini']);
    for (const h of named) expect(h.decides).toMatch(/if it applies: present, not checked: not a regular file/);
  });
});

describe('trivyConfig — the IaC-looking walk', () => {
  it.skipIf(!POSIX)('FIFOs named like IaC are never opened, and are named (POSIX)', () => {
    const p = makeTempDir('rrh-iac-');
    mkfifo(join(p, 'deploy.yaml'));
    mkfifo(join(p, 'stack.json'));
    const r = fast(() => iacLookingFiles(p, null));
    expect(r.files).toEqual([]);
    // Round 2 (M2): a refused candidate of any kind is named — a FIFO was dropped by a regular-files filter.
    expect(r.incomplete).toMatch(/could not read 2 YAML\/JSON files to tell whether it is IaC: deploy\.yaml \(.+\); stack\.json \(.+\)$/);
  });

  it.skipIf(!NOT_ROOT)('a candidate that cannot be opened makes the walk incomplete, naming it (POSIX, not root)', () => {
    const p = makeTempDir('rrh-iac-');
    writeFileSync(join(p, 'deploy.yaml'), 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n');
    chmodSync(join(p, 'deploy.yaml'), 0o000);
    try {
      const r = iacLookingFiles(p, null);
      expect(r.files).toEqual([]);
      expect(r.incomplete).toMatch(/could not read 1 YAML\/JSON file to tell whether it is IaC: deploy\.yaml/);
    } finally {
      chmodSync(join(p, 'deploy.yaml'), 0o600);
    }
  });

  it('an incomplete walk is named in the trivy-config reason, as a note', () => {
    const run = { outcome: 'completed', stderr: '', stdout: '', exitCode: 0, honoured: [] } as unknown as Parameters<
      typeof judgeTrivyConfig
    >[0]['run'];
    const j = judgeTrivyConfig({
      name: 'trivy-config',
      run,
      raw: '{"Results":[]}',
      iacFiles: [],
      iacIncomplete: 'the walk stopped after 20000 directories',
    });
    expect(j.missing).toEqual([]);
    expect(j.toolRun.reason).toBe(
      'the check for IaC-looking files Trivy did not read is incomplete: the walk stopped after 20000 directories',
    );
  });
});

describe('semgrepRuleIds — a rule file that cannot be read tells nothing, and says "may"', () => {
  it('an oversized rule file declares no id and may hold a taint rule', () => {
    const p = makeTempDir('rrh-rules-');
    oversized(join(p, '.semgrep.yml'), 8 * 1024 * 1024);
    expect(fast(() => ruleIdsInFile(join(p, '.semgrep.yml')))).toEqual([]);
    expect(mayHoldTaintRules([join(p, '.semgrep.yml')])).toBe(true);
  });

  it.skipIf(!POSIX)('a FIFO and a /dev/zero link return at once (POSIX)', () => {
    const p = makeTempDir('rrh-rules-');
    mkfifo(join(p, 'fifo.yml'));
    symlinkSync('/dev/zero', join(p, 'zero.yml'));
    expect(fast(() => ruleIdsInFile(join(p, 'fifo.yml')))).toEqual([]);
    expect(fast(() => ruleIdsInFile(join(p, 'zero.yml')))).toEqual([]);
    expect(fast(() => mayHoldTaintRules([join(p, 'fifo.yml'), join(p, 'zero.yml')]))).toBe(true);
  });
});

describe('wp_vuln_check_source inventory — a hostile install file is a warning naming it', () => {
  it.skipIf(!POSIX)('a version.php linked to /dev/zero returns at once, the core version unknown and named (POSIX)', () => {
    const p = makeTempDir('rrh-wp-');
    mkdirSync(join(p, 'wp-includes'));
    symlinkSync('/dev/zero', join(p, 'wp-includes', 'version.php'));
    const inv = fast(() => inventoryWordPressSource(p));
    expect(inv.core.version).toBeNull();
    expect(inv.warnings).toContain('wp-includes/version.php: not read — it resolves outside the project (a link) and was not read.');
  });

  it.skipIf(!CAN_SYMLINK)('a plugin main file linked out of the install is named, never read', () => {
    const p = makeTempDir('rrh-wp-');
    const outside = makeTempDir('rrh-outside-');
    mkdirSync(join(p, 'wp-content', 'plugins', 'evil'), { recursive: true });
    writeFileSync(join(outside, 'evil.php'), '<?php\n/* Plugin Name: Evil\nVersion: 1.0 */');
    symlinkSync(join(outside, 'evil.php'), join(p, 'wp-content', 'plugins', 'evil', 'evil.php'), 'file');
    const inv = inventoryWordPressSource(p);
    expect(inv.plugins).toEqual([]);
    expect(inv.warnings).toContain('wp-content/plugins/evil: no file with a "Plugin Name:" header — skipped.');
  });

  it('a plugin whose main file is far longer than its header is still inventoried from the head', () => {
    const p = makeTempDir('rrh-wp-');
    mkdirSync(join(p, 'wp-content', 'plugins', 'big'), { recursive: true });
    writeFileSync(
      join(p, 'wp-content', 'plugins', 'big', 'big.php'),
      `<?php\n/*\n * Plugin Name: Big\n * Version: 2.1.0\n */\n${'// code\n'.repeat(200_000)}`,
    );
    const inv = inventoryWordPressSource(p);
    expect(inv.plugins.map((x) => [x.slug, x.version])).toEqual([['big', '2.1.0']]);
  });
});

describe('scan_skill ingestion — a file in the skill that cannot be read is named', () => {
  it.skipIf(!NOT_ROOT)('an unreadable file is skipped with a warning naming it (POSIX, not root)', async () => {
    const p = makeTempDir('rrh-skill-');
    writeFileSync(join(p, 'SKILL.md'), '# skill\n');
    writeFileSync(join(p, 'locked.sh'), 'echo hi\n');
    chmodSync(join(p, 'locked.sh'), 0o000);
    try {
      const r = await ingestTarget(p);
      expect(r.ok).toBe(true);
      if (!r.ok) return;
      expect(r.files.map((f) => f.relPath)).toEqual(['SKILL.md']);
      expect(r.warnings.some((w) => /^not read: locked\.sh \(it could not be read/.test(w))).toBe(true);
    } finally {
      chmodSync(join(p, 'locked.sh'), 0o600);
    }
  });

  it('a relative directory target is read where it is', async () => {
    const p = makeTempDir('rrh-skill-');
    writeFileSync(join(p, 'SKILL.md'), '# skill\n');
    // Relative to the working directory (the temp dir and the checkout share a drive here).
    const rel = relative(process.cwd(), p);
    expect(isAbsolute(rel)).toBe(false);
    const r = await ingestTarget(rel);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.files.map((f) => f.relPath)).toEqual(['SKILL.md']);
  });
});
