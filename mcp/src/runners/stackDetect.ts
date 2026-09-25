/**
 * `detect_stack`'s detection engine — the TypeScript port of
 * `scripts/detect/detect-stack.sh`. Pure and synchronous: every check reads
 * the filesystem directly, with no shell, so a host with no bash/WSL can
 * still detect a stack (the shell script required one).
 *
 * Three defects the bash script reproduced, fixed here:
 *
 *   - PHP was only detected via `composer.json`. A typical WordPress site,
 *     theme or plugin ships no composer.json at all, so it reported
 *     `languages: []`. Fixed by detecting PHP from any `*.php` file, and
 *     WordPress from `wp-config.php`, a `wp-content/` directory, a theme's
 *     `style.css` "Theme Name:" header, or a plugin's own "Plugin Name:"
 *     header — any of which can be true with zero PHP package manifest.
 *   - Manifests were read at the project root ONLY, so a repo whose manifest
 *     lives one or more directories down (this repo: `mcp/package.json`)
 *     reported zero languages for itself. Fixed by walking to depth 3,
 *     excluding the directories no scan of the project's own files reads;
 *     each manifest-bearing directory becomes one entry in `projects`, and
 *     the top-level arrays are the union across all of them.
 *   - `build.gradle.kts` (a Kotlin Gradle *build script*) was folded into
 *     `java`. Fixed: it now reports `kotlin`.
 */

import { existsSync, readFileSync, readdirSync, type Dirent } from 'node:fs';
import { join } from 'node:path';
import type { StackSnapshot, SubProjectStack } from '../types.js';
import { hasFileWithExtension, PROJECT_WALK_EXCLUDE } from './projectFiles.js';

/** How many directories below the project root the manifest walk descends. */
const MAX_MANIFEST_DEPTH = 3;

/** A soft ceiling on directories visited by the manifest walk, so a
 *  pathological tree (thousands of tiny directories, none excluded) cannot
 *  make `detect_stack` hang. Never reached by an ordinary project. */
const MAX_DIRS_VISITED = 20_000;

export function detectStack(projectPath: string): StackSnapshot {
  const manifestDirs = walkManifestDirs(projectPath);
  const projects: SubProjectStack[] = [];

  const rootDetected = detectManifestsIn(projectPath);
  const rootWp = detectWordPress(projectPath);
  const rootPhpByGlob = hasFileWithExtension(projectPath, ['.php']);
  const root: SubProjectStack = {
    path: '.',
    languages: unique([
      ...rootDetected.languages,
      ...(rootPhpByGlob || rootWp.isWordPress ? ['php'] : []),
    ]),
    package_managers: [...rootDetected.package_managers],
    frameworks: unique([...rootDetected.frameworks, ...rootWp.frameworks]),
  };
  if (root.languages.length > 0 || root.frameworks.length > 0) projects.push(root);

  for (const dir of manifestDirs) {
    if (dir.rel === '') continue; // the root is handled above, with the WP/PHP-glob signals folded in.
    const detected = detectManifestsIn(dir.abs);
    if (detected.languages.length === 0) continue;
    projects.push({
      path: dir.rel,
      languages: detected.languages,
      package_managers: detected.package_managers,
      frameworks: detected.frameworks,
    });
  }

  const languages = unique(projects.flatMap((p) => p.languages)).sort();
  const packageManagers = unique(projects.flatMap((p) => p.package_managers)).sort();
  const frameworks = unique(projects.flatMap((p) => p.frameworks)).sort();

  const hasTerraform = hasGlob(projectPath, /\.tf$/i);
  const hasKubernetes = detectKubernetes(projectPath);
  const hasAnsible = existsSync(join(projectPath, 'roles')) || existsSync(join(projectPath, 'ansible.cfg'));

  return {
    os: detectStackOs(),
    arch: detectStackArch(),
    languages,
    package_managers: packageManagers,
    frameworks,
    existing_tools: detectExistingTools(projectPath).sort(),
    has_docker: existsSync(join(projectPath, 'Dockerfile')),
    has_compose: hasComposeFile(projectPath),
    has_terraform: hasTerraform,
    has_kubernetes: hasKubernetes,
    has_ansible: hasAnsible,
    has_github_actions: existsSync(join(projectPath, '.github', 'workflows')),
    has_gitlab_ci: existsSync(join(projectPath, '.gitlab-ci.yml')),
    has_iac: hasTerraform || hasKubernetes || hasAnsible,
    projects,
  };
}

// ---------------------------------------------------------------------- OS / arch

function detectStackOs(): StackSnapshot['os'] {
  switch (process.platform) {
    case 'darwin':
      return 'macos';
    case 'win32':
      return 'windows';
    case 'linux':
      if (isWsl()) return 'wsl';
      if (existsSync('/etc/debian_version')) return 'debian';
      if (existsSync('/etc/redhat-release')) return 'rhel';
      if (existsSync('/etc/arch-release')) return 'arch';
      return 'linux';
    default:
      return 'unknown';
  }
}

function isWsl(): boolean {
  try {
    return /microsoft/i.test(readFileSync('/proc/version', 'utf8'));
  } catch {
    return false;
  }
}

/**
 * `arch`, in the same spelling the bash script's `uname -m` used — which is
 * NOT what `process.arch` spells 64-bit ARM as on every OS. Linux's `uname
 * -m` reports `aarch64`; Apple's own `uname -m` reports `arm64`; Node's
 * `process.arch` collapses both to `'arm64'`. `platform`/`arch` are
 * parameters (defaulting to the real `process.platform`/`process.arch`) so
 * this is directly unit-testable without stubbing globals.
 */
export function detectStackArch(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): string {
  switch (arch) {
    case 'x64':
      return 'x86_64';
    case 'arm64':
      return platform === 'darwin' ? 'arm64' : 'aarch64';
    case 'ia32':
      return 'i686';
    case 'arm':
      return 'armv7l';
    default:
      return arch;
  }
}

// ---------------------------------------------------------------------- manifest walk

interface ManifestDir {
  /** `/`-separated, relative to the project root; `''` for the root itself. */
  rel: string;
  abs: string;
}

/** Manifest file names that make a directory count as a (sub-)project. */
const MANIFEST_FILES: readonly string[] = [
  'package.json',
  'pyproject.toml',
  'requirements.txt',
  'Pipfile',
  'setup.py',
  'setup.cfg',
  'composer.json',
  'go.mod',
  'Cargo.toml',
  'Gemfile',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
];

/**
 * Every directory at depth 0..{@link MAX_MANIFEST_DEPTH} (root inclusive)
 * that holds at least one file in {@link MANIFEST_FILES}, skipping
 * `node_modules`, `vendor`, `.git`, `dist`, `build` (and the rest of
 * `PROJECT_WALK_EXCLUDE`, a superset already used by every other walk of a
 * project's own files) at any depth.
 */
function walkManifestDirs(root: string): ManifestDir[] {
  const found: ManifestDir[] = [];
  const stack: Array<{ abs: string; rel: string; depth: number }> = [{ abs: root, rel: '', depth: 0 }];
  let visited = 0;
  while (stack.length > 0) {
    const cur = stack.pop();
    if (cur === undefined) break;
    if (visited >= MAX_DIRS_VISITED) break;
    visited += 1;
    const entries = readDirSafe(cur.abs);
    if (entries.some((e) => e.isFile() && MANIFEST_FILES.includes(e.name))) {
      found.push({ rel: cur.rel, abs: cur.abs });
    }
    if (cur.depth >= MAX_MANIFEST_DEPTH) continue;
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      if (PROJECT_WALK_EXCLUDE.has(e.name) || e.name.startsWith('.')) continue;
      stack.push({
        abs: join(cur.abs, e.name),
        rel: cur.rel === '' ? e.name : `${cur.rel}/${e.name}`,
        depth: cur.depth + 1,
      });
    }
  }
  return found;
}

function readDirSafe(dir: string): Dirent[] {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------- per-directory detection

interface Detected {
  languages: string[];
  package_managers: string[];
  frameworks: string[];
}

/** Manifest-driven detection, scoped to one directory (root or a nested one). */
function detectManifestsIn(dir: string): Detected {
  const languages: string[] = [];
  const packageManagers: string[] = [];
  const frameworks: string[] = [];
  const has = (rel: string): boolean => existsSync(join(dir, rel));
  const read = (rel: string): string | null => readTextSafe(join(dir, rel));

  // JS/TS
  const pkgJsonText = read('package.json');
  if (pkgJsonText !== null) {
    languages.push('javascript');
    if (has('tsconfig.json') || hasTopLevelExtension(dir, '.ts')) languages.push('typescript');
    if (has('pnpm-lock.yaml')) packageManagers.push('pnpm');
    else if (has('yarn.lock')) packageManagers.push('yarn');
    else if (has('bun.lockb') || has('bun.lock')) packageManagers.push('bun');
    else packageManagers.push('npm');

    for (const [needle, framework] of JS_FRAMEWORK_MARKERS) {
      if (pkgJsonText.includes(needle)) frameworks.push(framework);
    }
  }

  // Python
  const pyprojectText = read('pyproject.toml');
  if (has('pyproject.toml') || has('requirements.txt') || has('Pipfile') || has('setup.py') || has('setup.cfg')) {
    languages.push('python');
    if (has('poetry.lock')) packageManagers.push('poetry');
    else if (has('uv.lock')) packageManagers.push('uv');
    else if (has('Pipfile.lock')) packageManagers.push('pipenv');
    else packageManagers.push('pip');

    const reqTexts = readRequirementsTxts(dir);
    const haystack = `${pyprojectText ?? ''}\n${reqTexts}`;
    if (/django/i.test(haystack)) frameworks.push('django');
    if (/flask/i.test(haystack)) frameworks.push('flask');
    if (/fastapi/i.test(haystack)) frameworks.push('fastapi');
  }

  // PHP (composer-driven part; `*.php`-only and WordPress signals are layered
  // on at the root by the caller, since they are whole-project concerns).
  const composerText = read('composer.json');
  if (composerText !== null) {
    languages.push('php');
    packageManagers.push('composer');
    if (composerText.includes('laravel/framework')) frameworks.push('laravel');
    if (composerText.includes('symfony/')) frameworks.push('symfony');
  }

  // Go
  if (has('go.mod')) {
    languages.push('go');
    packageManagers.push('gomod');
  }

  // Rust
  if (has('Cargo.toml')) {
    languages.push('rust');
    packageManagers.push('cargo');
  }

  // Ruby
  if (has('Gemfile')) {
    languages.push('ruby');
    packageManagers.push('bundler');
  }

  // Java / Kotlin
  if (has('pom.xml')) {
    languages.push('java');
    packageManagers.push('maven');
  }
  if (has('build.gradle')) {
    languages.push('java');
    packageManagers.push('gradle');
  }
  if (has('build.gradle.kts')) {
    languages.push('kotlin');
    packageManagers.push('gradle');
  }
  if (hasTopLevelExtension(dir, '.kt')) languages.push('kotlin');

  return {
    languages: unique(languages),
    package_managers: unique(packageManagers),
    frameworks: unique(frameworks),
  };
}

const JS_FRAMEWORK_MARKERS: ReadonlyArray<readonly [string, string]> = [
  ['"react"', 'react'],
  ['"next"', 'nextjs'],
  ['"vue"', 'vue'],
  ['"@angular', 'angular'],
  ['"svelte"', 'svelte'],
  ['"express"', 'express'],
  ['"fastify"', 'fastify'],
  ['"@nestjs', 'nestjs'],
  ['"astro"', 'astro'],
];

/** `requirements*.txt` at this directory's top level, concatenated. */
function readRequirementsTxts(dir: string): string {
  const entries = readDirSafe(dir);
  const texts: string[] = [];
  for (const e of entries) {
    if (e.isFile() && /^requirements.*\.txt$/i.test(e.name)) {
      const text = readTextSafe(join(dir, e.name));
      if (text !== null) texts.push(text);
    }
  }
  return texts.join('\n');
}

/** Whether `dir` (top level only, no recursion) has a file ending in `ext`. */
function hasTopLevelExtension(dir: string, ext: string): boolean {
  return readDirSafe(dir).some((e) => e.isFile() && e.name.toLowerCase().endsWith(ext));
}

// ---------------------------------------------------------------------- WordPress

interface WordPressSignals {
  isWordPress: boolean;
  frameworks: string[];
}

/**
 * WordPress/WooCommerce/Kadence detection, scoped to `dir` — deliberately a
 * whole-project concern (evaluated once, at the root), unlike the manifest
 * walk above: `wp-content/themes/*` conventionally lives at the site root,
 * not at an arbitrary nesting depth.
 */
function detectWordPress(dir: string): WordPressSignals {
  const has = (rel: string): boolean => existsSync(join(dir, rel));
  let isWordPress = has('wp-config.php') || has('wp-config-sample.php') || has('wp-content');

  const styleCss = readTextSafe(join(dir, 'style.css'));
  if (styleCss !== null && /^\s*(?:\*\s*)?Theme Name:/im.test(styleCss)) isWordPress = true;

  if (hasTopLevelPluginHeader(dir)) isWordPress = true;

  const isKadence =
    has(join('wp-content', 'themes', 'kadence')) || has(join('wp-content', 'plugins', 'kadence-blocks'));

  const isWooCommerce =
    has(join('wp-content', 'plugins', 'woocommerce')) ||
    (readTextSafe(join(dir, 'composer.json'))?.includes('woocommerce/woocommerce') ?? false) ||
    /requires plugins:.*woocommerce|wc requires at least/i.test(
      `${styleCss ?? ''}\n${firstTopLevelPluginHeaderText(dir) ?? ''}`,
    );

  const frameworks: string[] = [];
  if (isWordPress || isWooCommerce) frameworks.push('wordpress');
  if (isWooCommerce) frameworks.push('woocommerce');
  if (isKadence) frameworks.push('kadence');

  return { isWordPress: isWordPress || isWooCommerce, frameworks: unique(frameworks) };
}

/** Whether any top-level `*.php` file's docblock has a "Plugin Name:" header. */
function hasTopLevelPluginHeader(dir: string): boolean {
  return firstTopLevelPluginHeaderText(dir) !== null;
}

/** The text of the first top-level `*.php` file whose header names a plugin,
 *  or null when none does. Bounded to top-level files and the first 8 KB of
 *  each — a plugin header is always near the top of the main file. */
function firstTopLevelPluginHeaderText(dir: string): string | null {
  for (const e of readDirSafe(dir)) {
    if (!e.isFile() || !e.name.toLowerCase().endsWith('.php')) continue;
    const text = readTextSafe(join(dir, e.name), 8192);
    if (text !== null && /^\s*(?:\*|\/\/)?\s*Plugin Name:/im.test(text)) return text;
  }
  return null;
}

// ---------------------------------------------------------------------- IaC / CI / existing tools

function hasComposeFile(dir: string): boolean {
  return (
    existsSync(join(dir, 'docker-compose.yml')) ||
    existsSync(join(dir, 'compose.yml')) ||
    existsSync(join(dir, 'docker-compose.yaml'))
  );
}

/** Top-level files only (mirrors the bash script's `compgen -G`, which never recursed). */
function hasGlob(dir: string, pattern: RegExp): boolean {
  return readDirSafe(dir).some((e) => e.isFile() && pattern.test(e.name));
}

function detectKubernetes(dir: string): boolean {
  if (existsSync(join(dir, 'k8s')) || existsSync(join(dir, 'kubernetes'))) return true;
  for (const e of readDirSafe(dir)) {
    if (!e.isFile() || !/\.ya?ml$/i.test(e.name)) continue;
    const text = readTextSafe(join(dir, e.name));
    if (text !== null && /apiVersion:\s/.test(text)) return true;
  }
  return false;
}

function detectExistingTools(dir: string): string[] {
  const has = (rel: string): boolean => existsSync(join(dir, rel));
  const contains = (rel: string, needle: string): boolean => (readTextSafe(join(dir, rel)) ?? '').includes(needle);
  const tools: string[] = [];
  if (has('.semgrep.yml') || has(join('.semgrep', 'semgrep.yml'))) tools.push('semgrep');
  if (has('.gitleaks.toml')) tools.push('gitleaks');
  if (has('.trivyignore')) tools.push('trivy');
  if (has('renovate.json') || has('.renovaterc') || has('.renovaterc.json')) tools.push('renovate');
  if (has(join('.github', 'dependabot.yml'))) tools.push('dependabot');
  if (has('.pre-commit-config.yaml')) tools.push('pre-commit');
  if (has('.eslintrc') || has('.eslintrc.json') || has('eslint.config.js')) tools.push('eslint');
  if (has('.prettierrc') || has('.prettierrc.json')) tools.push('prettier');
  if (has('ruff.toml') || contains('pyproject.toml', '[tool.ruff]')) tools.push('ruff');
  if (has('playwright.config.ts') || has('playwright.config.js')) tools.push('playwright');
  if (has('vitest.config.ts') || has('vitest.config.js')) tools.push('vitest');
  if (has('jest.config.js') || has('jest.config.ts')) tools.push('jest');
  if (has('pytest.ini') || contains('pyproject.toml', '[tool.pytest')) tools.push('pytest');
  return tools;
}

// ---------------------------------------------------------------------- shared helpers

function readTextSafe(path: string, maxBytes?: number): string | null {
  try {
    const text = readFileSync(path, 'utf8');
    return maxBytes !== undefined && text.length > maxBytes ? text.slice(0, maxBytes) : text;
  } catch {
    return null;
  }
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}
