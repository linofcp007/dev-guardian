/**
 * `detectStack` — the TypeScript port of `scripts/detect/detect-stack.sh`.
 *
 * Pure filesystem logic: every test builds a real temp directory tree and
 * reads the returned `StackSnapshot`, no mocking. Covers the defects the
 * bash script reproduced (task 15, brief item 1):
 *
 *   - PHP was only detected via `composer.json`, so a WordPress site/theme/
 *     plugin with no composer.json reported `languages: []`.
 *   - Manifests were read at the project root only, so a repo with a nested
 *     manifest (this repo's own `mcp/package.json`) reported zero languages.
 *   - `build.gradle.kts` was folded into `java` instead of `kotlin`.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { detectStack } from '../../../src/runners/stackDetect.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function project(): string {
  return makeTempDir('stack-detect-');
}

function write(root: string, rel: string, content = ''): void {
  const abs = join(root, ...rel.split('/'));
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content, 'utf8');
}

describe('detectStack', () => {
  it('detects JS/TS from a root package.json, with framework and package manager', () => {
    const root = project();
    write(
      root,
      'package.json',
      JSON.stringify({ name: 'x', dependencies: { react: '^18.0.0' } }),
    );
    write(root, 'pnpm-lock.yaml', '');
    write(root, 'tsconfig.json', '{}');
    const snap = detectStack(root);
    expect(snap.languages).toContain('javascript');
    expect(snap.languages).toContain('typescript');
    expect(snap.package_managers).toContain('pnpm');
    expect(snap.frameworks).toContain('react');
  });

  it('detects PHP by *.php alone, without composer.json', () => {
    const root = project();
    write(root, 'index.php', '<?php echo "hi";');
    const snap = detectStack(root);
    expect(snap.languages).toContain('php');
    expect(snap.languages).not.toContain('javascript');
  });

  it('detects WordPress from wp-config.php with no composer.json', () => {
    const root = project();
    write(root, 'wp-config.php', '<?php // config');
    write(root, 'wp-content/plugins/hello.php', '<?php');
    const snap = detectStack(root);
    expect(snap.languages).toContain('php');
    expect(snap.frameworks).toContain('wordpress');
  });

  it('detects a bare theme by style.css "Theme Name:" header (no wp-config.php)', () => {
    const root = project();
    write(
      root,
      'style.css',
      '/*\nTheme Name: My Theme\nAuthor: Someone\n*/\nbody { color: red; }\n',
    );
    const snap = detectStack(root);
    expect(snap.frameworks).toContain('wordpress');
    expect(snap.languages).toContain('php');
  });

  it('detects a bare plugin by its main file "Plugin Name:" header', () => {
    const root = project();
    write(
      root,
      'my-plugin.php',
      '<?php\n/**\n * Plugin Name: My Plugin\n * Version: 1.0\n */\n',
    );
    const snap = detectStack(root);
    expect(snap.frameworks).toContain('wordpress');
  });

  it('detects WooCommerce alongside WordPress', () => {
    const root = project();
    write(root, 'wp-config.php', '<?php');
    write(root, 'wp-content/plugins/woocommerce/woocommerce.php', '<?php // WC');
    const snap = detectStack(root);
    expect(snap.frameworks).toContain('wordpress');
    expect(snap.frameworks).toContain('woocommerce');
  });

  it('finds nested manifests to depth 3 and unions them at the top level', () => {
    const root = project();
    // depth 1: this repo's own shape (mcp/package.json).
    write(root, 'mcp/package.json', JSON.stringify({ name: 'inner' }));
    write(root, 'mcp/package-lock.json', '{}');
    const snap = detectStack(root);
    expect(snap.languages).toContain('javascript');
    expect(snap.package_managers).toContain('npm');
    const sub = snap.projects.find((p) => p.path === 'mcp');
    expect(sub).toBeDefined();
    expect(sub?.languages).toContain('javascript');
  });

  it('excludes node_modules, vendor, .git, dist and build from the nested walk', () => {
    const root = project();
    write(root, 'node_modules/pkg/package.json', JSON.stringify({ name: 'dep' }));
    write(root, 'vendor/lib/composer.json', JSON.stringify({ name: 'dep' }));
    write(root, 'dist/package.json', JSON.stringify({ name: 'built' }));
    write(root, 'build/package.json', JSON.stringify({ name: 'built' }));
    const snap = detectStack(root);
    expect(snap.projects).toHaveLength(0);
    expect(snap.languages).toEqual([]);
  });

  it('does not descend past depth 3', () => {
    const root = project();
    write(root, 'a/b/c/d/package.json', JSON.stringify({ name: 'too-deep' }));
    const snap = detectStack(root);
    expect(snap.projects.find((p) => p.path === 'a/b/c/d')).toBeUndefined();
  });

  it('finds a manifest exactly at depth 3', () => {
    const root = project();
    write(root, 'a/b/c/package.json', JSON.stringify({ name: 'just-deep-enough' }));
    const snap = detectStack(root);
    expect(snap.projects.find((p) => p.path === 'a/b/c')).toBeDefined();
  });

  it('labels build.gradle.kts as kotlin, not java', () => {
    const root = project();
    write(root, 'build.gradle.kts', 'plugins { kotlin("jvm") }');
    const snap = detectStack(root);
    expect(snap.languages).toContain('kotlin');
    expect(snap.languages).not.toContain('java');
    expect(snap.package_managers).toContain('gradle');
  });

  it('still labels build.gradle (Groovy) as java', () => {
    const root = project();
    write(root, 'build.gradle', "apply plugin: 'java'");
    const snap = detectStack(root);
    expect(snap.languages).toContain('java');
    expect(snap.languages).not.toContain('kotlin');
  });

  it('sets has_iac when Terraform, Kubernetes or Ansible is present', () => {
    const root = project();
    write(root, 'main.tf', 'resource "x" "y" {}');
    const snap = detectStack(root);
    expect(snap.has_terraform).toBe(true);
    expect(snap.has_iac).toBe(true);
  });

  it('leaves has_iac false when none of the three is present', () => {
    const root = project();
    write(root, 'package.json', '{}');
    const snap = detectStack(root);
    expect(snap.has_iac).toBe(false);
  });

  it('keeps every pre-existing field', () => {
    const root = project();
    write(root, 'package.json', '{}');
    const snap = detectStack(root);
    for (const key of [
      'os',
      'arch',
      'languages',
      'package_managers',
      'frameworks',
      'existing_tools',
      'has_docker',
      'has_compose',
      'has_terraform',
      'has_kubernetes',
      'has_ansible',
      'has_github_actions',
      'has_gitlab_ci',
    ]) {
      expect(snap).toHaveProperty(key);
    }
  });
});
