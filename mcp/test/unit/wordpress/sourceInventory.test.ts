/**
 * `wordpress/sourceInventory.ts` — reads a local WordPress install (no live
 * URL, no WP-CLI) and reports core/plugin/theme versions from the files
 * themselves: `wp-includes/version.php`, each plugin's main-file header
 * (falling back to `readme.txt`'s `Stable tag:`), each theme's `style.css`
 * header.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { inventoryWordPressSource } from '../../../src/wordpress/sourceInventory.js';

afterAll(cleanupTempDirs);

function writeFile(path: string, content: string): void {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content, 'utf8');
}

describe('inventoryWordPressSource', () => {
  it('reads the core version from wp-includes/version.php', () => {
    const root = makeTempDir('wpinv-core-');
    writeFile(join(root, 'wp-includes', 'version.php'), "<?php\n$wp_version = '6.5.2';\n");

    const inv = inventoryWordPressSource(root);

    expect(inv.core.version).toBe('6.5.2');
  });

  it('reports core version null and a warning when version.php is absent', () => {
    const root = makeTempDir('wpinv-nocore-');
    mkdirSync(root, { recursive: true });

    const inv = inventoryWordPressSource(root);

    expect(inv.core.version).toBeNull();
    expect(inv.warnings.some((w) => w.includes('version.php'))).toBe(true);
  });

  it('reads a plugin version from its main file header', () => {
    const root = makeTempDir('wpinv-plugin-');
    writeFile(
      join(root, 'wp-content', 'plugins', 'akismet', 'akismet.php'),
      [
        '<?php',
        '/**',
        ' * Plugin Name: Akismet Anti-spam',
        ' * Version: 5.3.1',
        ' * Description: Something',
        ' */',
      ].join('\n'),
    );

    const inv = inventoryWordPressSource(root);

    expect(inv.plugins).toHaveLength(1);
    expect(inv.plugins[0]).toMatchObject({
      slug: 'akismet',
      name: 'Akismet Anti-spam',
      version: '5.3.1',
    });
  });

  it('finds the main file even when it is not named after the slug', () => {
    const root = makeTempDir('wpinv-plugin-altname-');
    writeFile(join(root, 'wp-content', 'plugins', 'my-plugin', 'helpers.php'), '<?php\n// no header here\n');
    writeFile(
      join(root, 'wp-content', 'plugins', 'my-plugin', 'bootstrap.php'),
      ['<?php', '/*', 'Plugin Name: My Plugin', 'Version: 2.0', '*/'].join('\n'),
    );

    const inv = inventoryWordPressSource(root);

    expect(inv.plugins).toHaveLength(1);
    expect(inv.plugins[0]).toMatchObject({ slug: 'my-plugin', name: 'My Plugin', version: '2.0' });
  });

  it('falls back to readme.txt Stable tag when the main file has no Version header', () => {
    const root = makeTempDir('wpinv-plugin-readme-');
    writeFile(
      join(root, 'wp-content', 'plugins', 'headerless', 'headerless.php'),
      ['<?php', '/*', 'Plugin Name: Headerless', '*/'].join('\n'),
    );
    writeFile(
      join(root, 'wp-content', 'plugins', 'headerless', 'readme.txt'),
      ['=== Headerless ===', 'Stable tag: 3.1.4', ''].join('\n'),
    );

    const inv = inventoryWordPressSource(root);

    expect(inv.plugins[0]?.version).toBe('3.1.4');
    expect(inv.plugins[0]?.stable_tag).toBe('3.1.4');
  });

  it('treats "Stable tag: trunk" as not a real version', () => {
    const root = makeTempDir('wpinv-plugin-trunk-');
    writeFile(
      join(root, 'wp-content', 'plugins', 'dev-tracks-trunk', 'dev-tracks-trunk.php'),
      ['<?php', '/*', 'Plugin Name: Dev Tracks Trunk', '*/'].join('\n'),
    );
    writeFile(
      join(root, 'wp-content', 'plugins', 'dev-tracks-trunk', 'readme.txt'),
      ['=== Dev Tracks Trunk ===', 'Stable tag: trunk', ''].join('\n'),
    );

    const inv = inventoryWordPressSource(root);

    expect(inv.plugins[0]?.version).toBeNull();
    expect(inv.plugins[0]?.stable_tag).toBe('trunk');
  });

  it('reads a single-file plugin directly under wp-content/plugins/', () => {
    const root = makeTempDir('wpinv-plugin-singlefile-');
    writeFile(
      join(root, 'wp-content', 'plugins', 'hello.php'),
      ['<?php', '/*', 'Plugin Name: Hello Dolly', 'Version: 1.7.2', '*/'].join('\n'),
    );

    const inv = inventoryWordPressSource(root);

    expect(inv.plugins).toHaveLength(1);
    expect(inv.plugins[0]).toMatchObject({ slug: 'hello', name: 'Hello Dolly', version: '1.7.2' });
  });

  it('ignores a plugin directory with no discoverable main file', () => {
    const root = makeTempDir('wpinv-plugin-nomain-');
    writeFile(join(root, 'wp-content', 'plugins', 'broken', 'index.php'), '<?php\n// silence is golden\n');

    const inv = inventoryWordPressSource(root);

    expect(inv.plugins).toHaveLength(0);
  });

  it('reads a theme version from style.css', () => {
    const root = makeTempDir('wpinv-theme-');
    writeFile(
      join(root, 'wp-content', 'themes', 'twentytwentyfour', 'style.css'),
      ['/*', 'Theme Name: Twenty Twenty-Four', 'Version: 1.2', '*/'].join('\n'),
    );

    const inv = inventoryWordPressSource(root);

    expect(inv.themes).toHaveLength(1);
    expect(inv.themes[0]).toMatchObject({
      slug: 'twentytwentyfour',
      name: 'Twenty Twenty-Four',
      version: '1.2',
    });
  });

  it('inventories multiple plugins and themes together', () => {
    const root = makeTempDir('wpinv-multi-');
    writeFile(join(root, 'wp-includes', 'version.php'), "<?php\n$wp_version = '6.6';\n");
    writeFile(
      join(root, 'wp-content', 'plugins', 'p1', 'p1.php'),
      ['<?php', '/*', 'Plugin Name: P1', 'Version: 1.0', '*/'].join('\n'),
    );
    writeFile(
      join(root, 'wp-content', 'plugins', 'p2', 'p2.php'),
      ['<?php', '/*', 'Plugin Name: P2', 'Version: 2.0', '*/'].join('\n'),
    );
    writeFile(
      join(root, 'wp-content', 'themes', 't1', 'style.css'),
      ['/*', 'Theme Name: T1', 'Version: 3.0', '*/'].join('\n'),
    );

    const inv = inventoryWordPressSource(root);

    expect(inv.core.version).toBe('6.6');
    expect(inv.plugins.map((p) => p.slug).sort()).toEqual(['p1', 'p2']);
    expect(inv.themes.map((t) => t.slug)).toEqual(['t1']);
  });
});
