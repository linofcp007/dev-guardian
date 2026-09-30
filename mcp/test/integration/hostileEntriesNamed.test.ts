/**
 * A link, a FIFO or an unlistable directory where a file or directory was
 * expected is followed when it stays inside, and NAMED when it is not read —
 * never taken for absent (review of 3.0, W2E, round 2: I2, I3, M2–M5).
 *
 *   - I2: a linked `wp-content/plugins` made the inventory `plugins: []` —
 *     "nothing installed", checked clean. A link that stays inside the install
 *     is followed; one out of it (or unlistable) is named in `not_inventoried`.
 *   - I3: the config lookup required a regular file, so a symlinked
 *     `.gitleaks.toml` — which gitleaks follows — was named nowhere.
 *   - M2: `detect_stack` named a refused `package.json` but not a refused
 *     `requirements-dev.txt`, root plugin `*.php`, Kubernetes `*.yaml` or
 *     nested manifest — its `kind === 'file'` filter dropped them silently.
 *   - M3: a directory the IaC walk or the nested-config walk could not list.
 *   - M4: `scan_skill` read past a FIFO without saying so.
 *   - M5: a FIFO `.git/shallow` stalled the shallow check; it now reads as
 *     undetermined, and says so.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { shallowBoundary, SHALLOW_UNDETERMINED } from '../../src/runners/git.js';
import { honouredFiles } from '../../src/runners/repoConfig.js';
import { detectStack } from '../../src/runners/stackDetect.js';
import { iacLookingFiles } from '../../src/runners/trivyConfig.js';
import { ingestTarget } from '../../src/skillaudit/ingest.js';
import { inventoryWordPressSource } from '../../src/wordpress/sourceInventory.js';
import { CAN_SYMLINK, POSIX } from '../helpers/fsCapabilities.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const NOT_ROOT = POSIX && typeof process.getuid === 'function' && process.getuid() !== 0;
/** A directory link: a junction on Windows, which needs no privilege. */
const dirLink = (target: string, path: string): void => symlinkSync(target, path, process.platform === 'win32' ? 'junction' : 'dir');
const mkfifo = (path: string): void => {
  expect(spawnSync('mkfifo', [path]).status).toBe(0);
};

function wpInstall(): string {
  const wp = makeTempDir('hen-wp-');
  mkdirSync(join(wp, 'wp-includes'));
  writeFileSync(join(wp, 'wp-includes', 'version.php'), "<?php\n$wp_version = '6.5.0';\n");
  mkdirSync(join(wp, 'wp-content'));
  return wp;
}
function plugin(dir: string, slug: string): void {
  mkdirSync(join(dir, slug), { recursive: true });
  writeFileSync(join(dir, slug, `${slug}.php`), `<?php\n/*\nPlugin Name: ${slug}\nVersion: 1.2.3\n*/\n`);
}

describe('I2 — a linked wp-content/plugins is followed inside the install, named outside it', () => {
  it('a link that stays inside the install is followed: its plugins are inventoried', () => {
    const wp = wpInstall();
    plugin(join(wp, 'wp-content', 'real-plugins'), 'akismet');
    dirLink(join(wp, 'wp-content', 'real-plugins'), join(wp, 'wp-content', 'plugins'));
    const inv = inventoryWordPressSource(wp);
    expect(inv.plugins.map((p) => p.slug)).toEqual(['akismet']);
    expect(inv.not_inventoried).toEqual([]);
  });

  it('a link out of the install is not followed, and is named — never "no plugins"', () => {
    const wp = wpInstall();
    const outside = makeTempDir('hen-out-');
    plugin(outside, 'akismet');
    dirLink(outside, join(wp, 'wp-content', 'plugins'));
    const inv = inventoryWordPressSource(wp);
    expect(inv.plugins).toEqual([]);
    expect(inv.not_inventoried).toEqual(['wp-content/plugins']);
    expect(inv.warnings.join('\n')).toMatch(/wp-content\/plugins: not read — /);
  });

  it.skipIf(!NOT_ROOT)('an unlistable plugins directory is named too (POSIX, not root)', () => {
    const wp = wpInstall();
    plugin(join(wp, 'wp-content', 'plugins'), 'akismet');
    chmodSync(join(wp, 'wp-content', 'plugins'), 0o000);
    try {
      expect(inventoryWordPressSource(wp).not_inventoried).toEqual(['wp-content/plugins']);
    } finally {
      chmodSync(join(wp, 'wp-content', 'plugins'), 0o755);
    }
  });
});

describe('I3 — a config that is not a plain file is named, never absent', () => {
  it.skipIf(!CAN_SYMLINK)('a symlinked .gitleaks.toml (which gitleaks follows) is named as a link', async () => {
    const p = makeTempDir('hen-cfg-');
    const outside = makeTempDir('hen-out-');
    writeFileSync(join(outside, 'gitleaks.toml'), '[allowlist]\npaths = [".*"]\n');
    symlinkSync(join(outside, 'gitleaks.toml'), join(p, '.gitleaks.toml'), 'file');
    const files = await honouredFiles(p, 'gitleaks');
    expect(files.find((f) => f.path === '.gitleaks.toml')?.decides).toMatch(/\(a link, which the scanner follows\)$/);
  });

  it('a directory named .gitleaks.toml is named as present, not checked', async () => {
    const p = makeTempDir('hen-cfg-');
    mkdirSync(join(p, '.gitleaks.toml'));
    const files = await honouredFiles(p, 'gitleaks');
    expect(files.find((f) => f.path === '.gitleaks.toml')?.decides).toMatch(/present, not checked: a directory under that name$/);
  });

  it.skipIf(!POSIX)('a FIFO .gitleaksignore is named, never opened (POSIX)', async () => {
    const p = makeTempDir('hen-cfg-');
    mkfifo(join(p, '.gitleaksignore'));
    const files = await honouredFiles(p, 'gitleaks');
    expect(files.find((f) => f.path === '.gitleaksignore')?.decides).toMatch(/not a regular file/);
  });
});

describe('M2 — detect_stack names every candidate it refused, whatever its kind', () => {
  it.skipIf(!CAN_SYMLINK)('a linked requirements-dev.txt, root plugin .php, Kubernetes .yaml and nested package.json', () => {
    const p = makeTempDir('hen-stack-');
    const outside = makeTempDir('hen-out-');
    writeFileSync(join(outside, 'r.txt'), 'django\n');
    writeFileSync(join(outside, 'p.php'), '<?php\n/* Plugin Name: x */\n');
    writeFileSync(join(outside, 'd.yaml'), 'apiVersion: v1\nkind: Pod\n');
    writeFileSync(join(outside, 'package.json'), '{"dependencies":{"react":"1"}}');
    writeFileSync(join(p, 'requirements.txt'), 'flask\n');
    symlinkSync(join(outside, 'r.txt'), join(p, 'requirements-dev.txt'), 'file');
    symlinkSync(join(outside, 'p.php'), join(p, 'plugin.php'), 'file');
    symlinkSync(join(outside, 'd.yaml'), join(p, 'deploy.yaml'), 'file');
    mkdirSync(join(p, 'web'));
    symlinkSync(join(outside, 'package.json'), join(p, 'web', 'package.json'), 'file');
    const snap = detectStack(p);
    const unread = (snap.unread_files ?? []).map((u) => u.path);
    expect(unread).toEqual(expect.arrayContaining(['requirements-dev.txt', 'plugin.php', 'deploy.yaml', 'web/package.json']));
    expect(snap.frameworks).not.toContain('react');
  });

  it('a directory link out of the project is named: a sub-project behind it was not detected', () => {
    const p = makeTempDir('hen-stack-');
    const outside = makeTempDir('hen-out-');
    writeFileSync(join(outside, 'package.json'), '{"dependencies":{"react":"1"}}');
    dirLink(outside, join(p, 'web'));
    const snap = detectStack(p);
    expect((snap.unread_files ?? []).find((u) => u.path === 'web')?.reason).toMatch(/directory link out of the project/);
  });
});

describe('M3 — a directory a walk could not list is named (POSIX, not root)', () => {
  it.skipIf(!NOT_ROOT)('the IaC walk and the nested .semgrepignore walk', async () => {
    const p = makeTempDir('hen-walk-');
    mkdirSync(join(p, 'infra'));
    writeFileSync(join(p, 'infra', 'main.tf'), 'resource "x" "y" {}\n');
    chmodSync(join(p, 'infra'), 0o000);
    try {
      const iac = iacLookingFiles(p, null);
      expect(iac.incomplete ?? '').toMatch(/infra/);
      const nested = await honouredFiles(p, 'semgrep');
      expect(nested.map((f) => f.path).join('\n')).toMatch(/infra/);
    } finally {
      chmodSync(join(p, 'infra'), 0o755);
    }
  });
});

describe('M4 — scan_skill names a FIFO it skipped (POSIX)', () => {
  it.skipIf(!POSIX)('a FIFO in the skill is skipped with a warning naming it, never waited on', async () => {
    const p = makeTempDir('hen-skill-');
    writeFileSync(join(p, 'SKILL.md'), '# s\n');
    mkfifo(join(p, 'pipe'));
    const t0 = Date.now();
    const r = await ingestTarget(p);
    expect(Date.now() - t0).toBeLessThan(5_000);
    if (!r.ok) throw new Error(r.message);
    expect(r.skipped).toBeGreaterThanOrEqual(1);
    expect(r.warnings).toContain('not read: pipe (not a regular file: a FIFO, a device or a socket)');
  });
});

describe('M5 — a FIFO .git/shallow reads as undetermined, and says so (POSIX)', () => {
  it.skipIf(!POSIX)('shallowBoundary returns undetermined at once, never waiting on the FIFO', async () => {
    const p = makeTempDir('hen-shallow-');
    expect(spawnSync('git', ['init', '-q', p]).status).toBe(0);
    mkfifo(join(p, '.git', 'shallow'));
    const t0 = Date.now();
    expect(await shallowBoundary(p)).toEqual([SHALLOW_UNDETERMINED]);
    expect(Date.now() - t0).toBeLessThan(15_000);
  }, 30_000);
});
