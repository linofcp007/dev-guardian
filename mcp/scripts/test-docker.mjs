#!/usr/bin/env node
/**
 * The test suite in Linux containers, locally, with your own Docker (review
 * 8, finding 1): dev-guardian is developed on Windows, has no hosted CI by
 * policy, and its POSIX-only tests, the Node floor's code paths and (with
 * `--toolchain`) the scanner-dependent tests otherwise never run before a
 * release. Run it before tagging one (CONTRIBUTING.md).
 *
 *   npm run test:docker                       # the floor (22.13, with coverage) and the current LTS
 *   node scripts/test-docker.mjs [--image <name>]... [--toolchain] [--no-coverage] [--max-workers <n>] [--only <path>]...
 *
 * Default images: `node:22.13-bookworm-slim` — the `engines` floor, where
 * `node:sqlite` lacks `isTransaction` and the busy-timeout option — run with
 * coverage, so the thresholds in `vitest.config.ts` are enforced there; and
 * `node:24-bookworm-slim`, the current LTS. `--image` (repeatable) replaces
 * the list. `--toolchain` adds pinned Semgrep and Bandit (pip) and gitleaks
 * and Trivy (release archives, the same versions and sha256 sums as
 * `src/runners/installCatalog.ts`) and sets `GUARDIAN_REQUIRE_SEMGREP=1` and
 * `GUARDIAN_REQUIRE_GITLEAKS=1`, so a missing scanner fails instead of
 * skipping.
 *
 * How it runs: `git archive HEAD` of the repository is streamed into
 * `docker run --rm --init -i` — the committed tree, so commit first — unpacked
 * in the container, made a git repository (the plugin-install test reads `git
 * ls-files`), `npm ci` in `mcp/`, then `vitest run` as the unprivileged `node`
 * user (root reads every file whatever its mode, and the permission tests
 * would skip). The container needs the network for `npm ci` and the first
 * image builds; nothing is written to this machine but Docker's cache and a
 * log per image under `<os.tmpdir()>/dev-guardian-docker/`.
 *
 * Exit code: 0 every image passed · 1 an image failed or could not be
 * prepared · 2 Docker is not available (or a usage error).
 */

import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const MCP = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = resolve(MCP, '..');
const FLOOR_IMAGE = 'node:22.13-bookworm-slim';
const DEFAULT_IMAGES = [FLOOR_IMAGE, 'node:24-bookworm-slim'];
const RUN_TIMEOUT_MS = 3 * 60 * 60 * 1000;
const LOG_DIR = join(tmpdir(), 'dev-guardian-docker');
/** The Python scanners, pinned (the versions this suite last passed with on the maintainer machine). */
const PIP_PINS = ['semgrep==1.182.0', 'bandit==1.9.4'];

const USAGE = `usage: node scripts/test-docker.mjs [--image <name>]... [--toolchain] [--no-coverage] [--max-workers <n>] [--only <path>]...

Runs the vitest suite in Linux containers (git archive HEAD, npm ci, vitest run as the node user).
  --image <name>      a Docker image with Node >= 22.13 and apt (repeatable; replaces ${DEFAULT_IMAGES.join(', ')})
  --toolchain         add pinned Semgrep, Bandit, gitleaks and Trivy; a missing scanner then fails the tests
  --no-coverage       skip coverage on the floor image (${FLOOR_IMAGE} runs with coverage by default)
  --max-workers <n>   vitest workers per container (default 4)
  --only <path>       run only these test files or directories (repeatable)
Exit: 0 all passed · 1 an image failed · 2 Docker is not available (or a usage error).`;

/**
 * @param {string} message
 * @returns {never}
 */
function usageError(message) {
  console.error(`test-docker: ${message}\n\n${USAGE}`);
  process.exit(2);
}

/**
 * @typedef {{ images: string[], toolchain: boolean, coverage: boolean, workers: number, only: string[] }} Options
 */

/**
 * @param {string[]} argv
 * @returns {Options}
 */
function parseArgs(argv) {
  /** @type {Options} */
  const o = { images: [], toolchain: false, coverage: true, workers: 4, only: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i] ?? '';
    const value = () => {
      const v = a.includes('=') ? a.slice(a.indexOf('=') + 1) : argv[++i];
      if (v === undefined || v === '' || v.startsWith('--')) usageError(`${a.split('=')[0]} needs a value`);
      return v;
    };
    if (a === '--help' || a === '-h') {
      console.log(USAGE);
      process.exit(0);
    } else if (a === '--image' || a.startsWith('--image=')) o.images.push(value());
    else if (a === '--toolchain') o.toolchain = true;
    else if (a === '--no-coverage') o.coverage = false;
    else if (a === '--max-workers' || a.startsWith('--max-workers=')) {
      o.workers = Number(value());
      if (!Number.isInteger(o.workers) || o.workers < 1) usageError('--max-workers takes a positive integer');
    } else if (a === '--only' || a.startsWith('--only=')) o.only.push(value());
    else usageError(`unknown argument '${a}'`);
  }
  if (o.images.length === 0) o.images = [...DEFAULT_IMAGES];
  return o;
}

/**
 * @param {string[]} args
 * @param {import('node:child_process').SpawnSyncOptions} [opts]
 */
const docker = (args, opts = {}) => spawnSync('docker', args, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, windowsHide: true, ...opts });
/** @param {unknown} s */
const firstLine = (s) => String(s ?? '').trim().split(/\r?\n/)[0] ?? '';

/** Docker answers, and runs Linux containers. */
function checkDocker() {
  const v = docker(['version', '--format', '{{.Server.Version}}|{{.Server.Os}}|{{.Server.Arch}}']);
  if (v.error) {
    const code = /** @type {NodeJS.ErrnoException} */ (v.error).code;
    return { ok: false, why: code === 'ENOENT' ? 'the docker command was not found' : v.error.message };
  }
  if (v.status !== 0) return { ok: false, why: `the Docker daemon did not answer (is Docker running?) — ${firstLine(v.stderr)}` };
  const [version, os, arch] = String(v.stdout).trim().split('|');
  if (os !== 'linux') return { ok: false, why: `Docker runs ${os} containers — switch it to Linux containers` };
  return { ok: true, version, arch };
}

/**
 * gitleaks' and Trivy's pinned release for this architecture, read from the install catalog so the two never drift.
 *
 * @param {string | undefined} arch
 */
function pinnedReleases(arch) {
  const text = readFileSync(join(MCP, 'src', 'runners', 'installCatalog.ts'), 'utf8');
  const platform = arch === 'arm64' ? 'linux-arm64' : 'linux-amd64';
  const trivyVersion = /TRIVY_INSTALL_TAG = 'v([^']+)'/.exec(text)?.[1];
  const gitleaksVersion = /GITLEAKS_VERSION = '([^']+)'/.exec(text)?.[1];
  // A catalog that no longer spells them so must fail here, not build a URL holding "undefined".
  if (trivyVersion === undefined || gitleaksVersion === undefined) throw new Error('no Trivy or gitleaks version in installCatalog.ts');
  /** @param {string} tool */
  const asset = (tool) => {
    const block = text.slice(text.indexOf(`version: ${tool.toUpperCase()}_VERSION`));
    const m = new RegExp(`'${platform}': \\{ file: \`([^\`]+)\`, sha256: '([0-9a-f]{64})'`).exec(block);
    if (m === null) throw new Error(`no ${platform} asset for ${tool} in installCatalog.ts`);
    return { file: m[1] ?? '', sha256: m[2] ?? '' };
  };
  const trivy = asset('trivy');
  const gitleaks = asset('gitleaks');
  return {
    trivy: { ...trivy, file: trivy.file.replace('${TRIVY_VERSION}', trivyVersion), url: `https://github.com/aquasecurity/trivy/releases/download/v${trivyVersion}/` },
    gitleaks: { ...gitleaks, file: gitleaks.file.replace('${GITLEAKS_VERSION}', gitleaksVersion), url: `https://github.com/gitleaks/gitleaks/releases/download/v${gitleaksVersion}/` },
  };
}

/**
 * @param {string} image
 * @param {boolean} toolchain
 */
function imageTag(image, toolchain) {
  const t = image.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[.-]+/, '').slice(0, 100);
  return `dev-guardian-test:${t}${toolchain ? '-toolchain' : ''}`;
}

/**
 * The image a run uses: the base plus git (and, with --toolchain, the scanners) — built once, cached by Docker.
 *
 * @param {string} image
 * @param {Options} o
 * @param {string | undefined} arch
 * @returns {{ ref: string } | { error: string }}
 */
function prepare(image, o, arch) {
  if (docker(['image', 'inspect', image]).status !== 0) {
    console.log(`  pulling ${image} (needs network)…`);
    if (docker(['pull', image], { stdio: ['ignore', 'inherit', 'inherit'] }).status !== 0) return { error: `could not pull ${image}` };
  }
  const tag = imageTag(image, o.toolchain);
  const lines = [
    `FROM ${image}`,
    'RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates' +
      (o.toolchain ? ' curl python3 python3-venv' : '') +
      ' && rm -rf /var/lib/apt/lists/*',
  ];
  if (o.toolchain) {
    const r = pinnedReleases(arch);
    /**
     * @param {{ url: string, file: string, sha256: string }} rel
     * @param {string} binary
     */
    const fetch = (rel, binary) =>
      `RUN curl -fsSL -o /tmp/a.tgz ${rel.url}${rel.file} && echo "${rel.sha256}  /tmp/a.tgz" | sha256sum -c - ` +
      `&& tar -C /usr/local/bin -xzf /tmp/a.tgz ${binary} && rm /tmp/a.tgz`;
    lines.push(
      `RUN python3 -m venv /opt/scanners && /opt/scanners/bin/pip install --no-cache-dir ${PIP_PINS.join(' ')}`,
      fetch(r.gitleaks, 'gitleaks'),
      fetch(r.trivy, 'trivy'),
      'ENV PATH=/opt/scanners/bin:$PATH',
    );
  }
  lines.push(`LABEL dev-guardian-test.base="${image}"`, '');
  if (docker(['image', 'inspect', tag]).status !== 0) {
    console.log(`  building ${tag} (once, cached — needs network)…`);
    const b = docker(['build', '-q', '-t', tag, '-'], { input: lines.join('\n') });
    if (b.status !== 0) {
      `${String(b.stderr)}${String(b.stdout)}`.trim().split(/\r?\n/).slice(-8).forEach((l) => console.log(`    ${l}`));
      return { error: `could not build ${tag}` };
    }
  }
  return { ref: tag };
}

/** `git archive HEAD` of the repository, as a Buffer. */
function archive() {
  const r = spawnSync('git', ['archive', '--format=tar', 'HEAD'], { cwd: ROOT, maxBuffer: 1024 * 1024 * 1024, windowsHide: true });
  if (r.status !== 0) throw new Error(`git archive failed: ${String(r.stderr)}`);
  return r.stdout;
}

/**
 * @param {string} ref
 * @param {string} image
 * @param {Options} o
 * @param {Buffer} tar
 * @returns {Promise<{ code: number | null, out: string, coverage: boolean }>}
 */
function runIn(ref, image, o, tar) {
  const coverage = o.coverage && image === FLOOR_IMAGE;
  const vitest = ['npx', 'vitest', 'run', `--maxWorkers=${o.workers}`, ...(coverage ? ['--coverage', '--coverage.reporter=text-summary', '--coverage.reportOnFailure'] : []), ...o.only];
  const script = [
    'set -e',
    'mkdir -p /tmp/dg && tar -C /tmp/dg -xf -',
    'cd /tmp/dg',
    'git init -q && git add -A && git -c user.email=test@dev-guardian.invalid -c user.name=test commit -qm "test-docker" --no-verify',
    'cd mcp',
    'npm ci --no-audit --no-fund --loglevel=error',
    `exec ${vitest.map((a) => `'${a.replace(/'/g, "'\\''")}'`).join(' ')}`,
  ].join('\n');
  const env = o.toolchain ? ['-e', 'GUARDIAN_REQUIRE_SEMGREP=1', '-e', 'GUARDIAN_REQUIRE_GITLEAKS=1'] : [];
  const name = `dev-guardian-test-${process.pid}-${Date.now()}`;
  return new Promise((resolveRun) => {
    const child = spawn('docker', ['run', '--rm', '--init', '-i', '--name', name, '--user', 'node', '-e', 'HOME=/home/node', ...env, ref, 'sh', '-c', script], {
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    const timer = setTimeout(() => {
      out += '\n[test-docker: timed out]\n';
      docker(['rm', '-f', name]);
    }, RUN_TIMEOUT_MS);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolveRun({ code, out, coverage });
    });
    child.stdin.end(tar);
  });
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  const d = checkDocker();
  if (!d.ok) {
    console.error(`test-docker: Docker is not available: ${d.why}.\nThe suite still runs natively: npm test`);
    process.exit(2);
  }
  mkdirSync(LOG_DIR, { recursive: true });
  const tar = archive();
  console.log(`dev-guardian — the test suite in Linux containers (Docker ${d.version}, linux/${d.arch}), HEAD of ${ROOT}\n`);
  /** @type {Array<{ image: string, ok: boolean, summary: string }>} */
  const rows = [];
  for (const image of o.images) {
    console.log(`▸ ${image}${o.toolchain ? ' + toolchain' : ''}`);
    const p = prepare(image, o, d.arch);
    if ('error' in p) {
      console.log(`  ✗ ${p.error}\n`);
      rows.push({ image, ok: false, summary: p.error });
      continue;
    }
    const started = Date.now();
    const r = await runIn(p.ref, image, o, tar);
    const minutes = ((Date.now() - started) / 60000).toFixed(1);
    const log = join(LOG_DIR, `${p.ref.split(':')[1]}.log`);
    writeFileSync(log, r.out);
    // vitest colours its summary: read it without the escapes.
    const out = r.out.replace(new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, 'g'), '');
    const files = /Test Files\s+([^\n]+)/.exec(out)?.[1]?.trim() ?? '?';
    const tests = /\n\s*Tests\s+([^\n]+)/.exec(out)?.[1]?.trim() ?? '?';
    /** @param {string} label */
    const pct = (label) => new RegExp(`${label}\\s*:\\s*([\\d.]+%)`).exec(out)?.[1] ?? '?';
    const failedThresholds = [...out.matchAll(/ERROR: Coverage for (\w+) \(([\d.]+%)\) does not meet global threshold \(([\d.]+%)\)/g)];
    const cov = !r.coverage
      ? ''
      : `coverage ${pct('Statements')} / ${pct('Branches')} / ${pct('Functions')} / ${pct('Lines')}` +
        (failedThresholds.length > 0 ? ` — BELOW: ${failedThresholds.map((m) => `${m[1]} ${m[2]} < ${m[3]}`).join(', ')}` : '');
    const ok = r.code === 0;
    console.log(`  ${ok ? '✓' : '✗'} exit ${String(r.code)} · files ${files} · tests ${tests}${cov ? ` · ${cov}` : ''} · ${minutes} min`);
    if (!ok) {
      r.out.split(/\r?\n/).filter((l) => /^\s*(FAIL|×)\s/.test(l)).slice(0, 30).forEach((l) => console.log(`      ${l.trim().slice(0, 300)}`));
      console.log(`      full log: ${log}`);
    }
    rows.push({ image, ok, summary: `${files}; ${tests}` });
    console.log('');
  }
  const bad = rows.filter((r) => !r.ok).length;
  console.log(bad > 0 ? `${bad} of ${rows.length} image(s) failed.` : `All passed on ${rows.length} image(s).`);
  process.exitCode = bad > 0 ? 1 : 0;
}

await main();
