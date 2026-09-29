/**
 * Catalogue facts that were wrong, pinned: the install hints users are shown,
 * the one install that piped a moving branch into `sh`, the probe every entry
 * now carries, and the known-compromised Trivy releases.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  COSIGN_RELEASE_SHA256,
  COSIGN_VERSION,
  PINNED_RELEASES,
  TOOL_CATALOG,
  TRIVY_INSTALL_TAG,
  knownCompromise,
  suggestedInstallCommandString,
} from '../../../src/runners/installCatalog.js';
import { COSIGN_MIN_VERSION } from '../../../src/runners/cosignCheck.js';

describe('install hints', () => {
  it('suggests the current .NET LTS SDK, not .NET 6 (out of support since 2024-11)', () => {
    const hint = suggestedInstallCommandString('dotnet-sdk', 'win32') ?? '';
    expect(hint).toContain('Microsoft.DotNet.SDK.10');
    expect(hint).not.toMatch(/SDK\.6\b/);
  });

  it('gives nuclei a Windows install command (scoop main bucket carries it)', () => {
    const scoop = TOOL_CATALOG['nuclei']?.install.win32.scoop;
    expect(scoop?.command).toBe('scoop');
    expect(scoop?.args).toEqual(['install', 'nuclei']);
    expect(suggestedInstallCommandString('nuclei', 'win32')).toBe('scoop install nuclei');
  });
});

describe('version probes', () => {
  it('every catalogue entry names a binary and a version command', () => {
    for (const [name, meta] of Object.entries(TOOL_CATALOG)) {
      expect(meta.probe.command, name).toMatch(/\S/);
      expect(Array.isArray(meta.probe.args), name).toBe(true);
    }
  });

  it('the SDK is probed with --list-sdks and wp-cli through its `wp` binary', () => {
    expect(TOOL_CATALOG['dotnet-sdk']?.probe).toMatchObject({
      command: 'dotnet',
      args: ['--list-sdks'],
      parse: 'dotnet-sdks',
    });
    expect(TOOL_CATALOG['wp-cli']?.probe.command).toBe('wp');
  });
});

describe('knownCompromise (GHSA-69fq-xp46-6x23)', () => {
  it.each(['0.69.4', '0.69.5', '0.69.6', 'v0.69.4'])('flags trivy %s', (v) => {
    const hit = knownCompromise('trivy', v);
    expect(hit?.advisory).toBe('GHSA-69fq-xp46-6x23');
    expect(hit?.cve).toBe('CVE-2026-33634');
  });

  it.each(['0.69.3', '0.69.2', '0.69.7', '0.70.0', '0.74.0'])('does not flag trivy %s', (v) => {
    expect(knownCompromise('trivy', v)).toBeNull();
  });

  it('does not flag other tools or unparseable versions', () => {
    expect(knownCompromise('semgrep', '0.69.4')).toBeNull();
    expect(knownCompromise('trivy', '')).toBeNull();
  });
});

describe('semgrep catalog entry', () => {
  // compliance_check runs the RGPD pack (configs/semgrep/rgpd.yml) with it.
  it('names every tool that runs it, compliance_check included', () => {
    expect(TOOL_CATALOG['semgrep']?.required_by).toEqual(
      expect.arrayContaining(['scan_sast', 'security_scan_full', 'bug_hunt', 'review_pr', 'compliance_check']),
    );
  });
});

describe('hadolint catalog entry', () => {
  // scan_containers (task 15) runs hadolint on a Dockerfile when it is
  // installed; check_toolchain/install_toolchain need to know about it too.
  it('is registered with a probe and per-OS install hints', () => {
    const meta = TOOL_CATALOG['hadolint'];
    expect(meta).toBeDefined();
    expect(meta?.probe.command).toBe('hadolint');
    expect(meta?.required_by).toContain('scan_containers');
    expect(meta?.install.darwin.brew?.args).toEqual(['install', 'hadolint']);
    expect(meta?.install.win32.scoop?.args).toEqual(['install', 'hadolint']);
  });
});

describe('zizmor catalog entry', () => {
  // scan_iac (task 21) runs zizmor against .github/workflows when it exists
  // and zizmor is installed; check_toolchain/install_toolchain need to know
  // about it too.
  it('is registered with a probe and per-OS install hints', () => {
    const meta = TOOL_CATALOG['zizmor'];
    expect(meta).toBeDefined();
    expect(meta?.probe.command).toBe('zizmor');
    expect(meta?.required_by).toContain('scan_iac');
    expect(meta?.install.linux.pipx?.args).toEqual(['install', 'zizmor']);
    expect(meta?.install.linux.uv?.args).toEqual(['tool', 'install', 'zizmor']);
    expect(meta?.install.linux.cargo?.args).toEqual(['install', '--locked', 'zizmor']);
    expect(meta?.install.darwin.brew?.args).toEqual(['install', 'zizmor']);
  });
});

describe('actionlint catalog entry', () => {
  it('is registered with a probe and per-OS install hints', () => {
    const meta = TOOL_CATALOG['actionlint'];
    expect(meta).toBeDefined();
    expect(meta?.probe.command).toBe('actionlint');
    expect(meta?.probe.args).toEqual(['-version']); // single-dash: Go's flag package, not double-dash
    expect(meta?.required_by).toContain('scan_iac');
    expect(meta?.install.win32.scoop?.args).toEqual(['install', 'actionlint']);
    expect(meta?.install.win32.choco?.args).toEqual(['install', '-y', 'actionlint']);
    expect(meta?.install.darwin.brew?.args).toEqual(['install', 'actionlint']);
    expect(meta?.install.linux.go?.args).toEqual(['install', 'github.com/rhysd/actionlint/cmd/actionlint@latest']);
  });
});

describe('cosign catalog entry', () => {
  // scan_containers checks an image's Sigstore signature and SLSA provenance
  // with cosign; check_toolchain/install_toolchain need to know about it.
  const meta = TOOL_CATALOG['cosign'];

  it('is registered with a `cosign version` probe, required by scan_containers, not a default install', () => {
    expect(meta).toBeDefined();
    expect(meta?.probe).toEqual({ command: 'cosign', args: ['version'] });
    expect(meta?.required_by).toEqual(['scan_containers']);
    expect(meta?.default).toBe(false);
    expect(COSIGN_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('floors at 3.0.0 — the same floor scan_containers enforces (cosign 2.x `tree` cannot see OCI referrers)', () => {
    expect(meta?.version_floor).toBe('3.0.0');
    expect(meta?.version_floor).toBe(COSIGN_MIN_VERSION);
  });

  it('pins the Windows installers to that version (winget and scoop both take an exact version)', () => {
    expect(meta?.install.win32.winget?.args).toEqual([
      'install', '--id', 'Sigstore.Cosign', '--exact', '--version', COSIGN_VERSION,
      '--accept-source-agreements', '--accept-package-agreements',
    ]);
    expect(meta?.install.win32.scoop?.args).toEqual(['install', `cosign@${COSIGN_VERSION}`]);
    expect(suggestedInstallCommandString('cosign', 'win32')).toContain(COSIGN_VERSION);
  });

  it.each([
    ['linux', 'sha256sum -c -'],
    ['darwin', 'shasum -a 256 -c -'],
  ] as const)('%s: downloads the pinned release binary and checks its sha256 before installing it', (os, checker) => {
    const script = meta?.install[os].curl?.args[1] ?? '';
    expect(meta?.install[os].curl?.command).toBe('bash');
    for (const arch of ['amd64', 'arm64'] as const) {
      const key = `${os}-${arch}` as const;
      expect(script).toContain(`https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-${os}-$arch`);
      expect(script).toContain(COSIGN_RELEASE_SHA256[key]);
      expect(COSIGN_RELEASE_SHA256[key]).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(script).toContain(checker);
    // The check runs BEFORE the install, and a failed check stops it (set -e).
    expect(script.indexOf(checker)).toBeLessThan(script.indexOf('install -m 0755'));
    expect(script.startsWith('set -eu')).toBe(true);
    expect(script).not.toMatch(/latest/);
    // An architecture with no pinned checksum is refused, never guessed.
    expect(script).toMatch(/\*\) echo "[^"]*" >&2; exit 1/);
  });

  it('macOS also offers Homebrew, the convention every other darwin entry follows', () => {
    expect(meta?.install.darwin.brew?.args).toEqual(['install', 'cosign']);
  });
});

/**
 * Review 3.0, wave 2 (e) and its round 2: every install of Syft, Trivy and
 * gitleaks is a pinned release archive, checked against its sha256 before
 * it is unpacked — never a script piped from a moving branch, never
 * "latest", never a package repository that follows upstream. That is the
 * route the credential-stealing Trivy v0.69.4 took on 2026-03-19
 * (`TRIVY_INSTALL_TAG`), and `install_toolchain` ran it: Syft's `install.sh`
 * from `main`, Trivy from apt or `releases/latest`, gitleaks from
 * `releases/latest` — in the default Linux profile, the script it runs for
 * the Linux defaults and the Windows WSL fallback, and scoop/choco on
 * Windows. The POSIX installers are the shape of cosign's; the Windows one
 * downloads the pinned ZIP with PowerShell and checks it with Get-FileHash.
 */
const PINNED_TOOLS = ['syft', 'trivy', 'gitleaks'] as const;

describe('pinned release archives: syft, trivy, gitleaks', () => {
  it('pins trivy to TRIVY_INSTALL_TAG, a release no advisory names', () => {
    expect(PINNED_RELEASES.trivy.version).toBe(TRIVY_INSTALL_TAG.slice(1));
    expect(knownCompromise('trivy', PINNED_RELEASES.trivy.version)).toBeNull();
  });

  it.each(PINNED_TOOLS)('%s: every sum is a sha256, every asset of its own pinned version', (tool) => {
    const r = PINNED_RELEASES[tool];
    expect(r.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(r.base).toBe(`${r.base.slice(0, r.base.lastIndexOf('/'))}/v${r.version}`);
    expect(r.base).toMatch(/^https:\/\/github\.com\/[^/]+\/[^/]+\/releases\/download\/v\d+\.\d+\.\d+$/);
    for (const a of Object.values(r.assets)) {
      expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(a.file).toContain(r.version);
    }
  });

  it.each(PINNED_TOOLS.flatMap((tool) => [
    [tool, 'linux', 'sha256sum -c -'],
    [tool, 'darwin', 'shasum -a 256 -c -'],
  ] as const))('%s on %s: the pinned archive for each CPU, checked before it is unpacked', (tool, os, checker) => {
    const r = PINNED_RELEASES[tool];
    const spec = TOOL_CATALOG[tool]?.install[os].curl;
    const script = spec?.args[1] ?? '';
    expect(spec?.command).toBe('bash');
    for (const arch of ['amd64', 'arm64'] as const) {
      const a = r.assets[`${os}-${arch}`];
      // The sum sits in the same case arm as the asset it belongs to.
      expect(script).toContain(`asset=${a.file}; sum=${a.sha256}`);
    }
    expect(script).toContain(`"${r.base}/$asset"`);
    expect(script).toContain(checker);
    // Checked, then unpacked, then installed; a failed check stops it (set -e).
    expect(script.indexOf(checker)).toBeLessThan(script.indexOf('tar -xzf'));
    expect(script.indexOf('tar -xzf')).toBeLessThan(script.indexOf('install -m 0755'));
    expect(script.startsWith('set -eu')).toBe(true);
    // No moving branch, no "latest", no script piped into a shell.
    expect(script).not.toMatch(/\/main\/|latest|install\.sh|\|\s*sh\b/);
    // An architecture with no pinned checksum is refused, never guessed.
    expect(script).toMatch(/\*\) echo "[^"]*" >&2; exit 1/);
    expect(spec?.description).toContain(r.version);
  });

  it.each(PINNED_TOOLS)('%s on Windows: the pinned ZIP through PowerShell, Get-FileHash before Expand-Archive', (tool) => {
    const r = PINNED_RELEASES[tool];
    const a = r.assets['windows-amd64'];
    const win = TOOL_CATALOG[tool]?.install.win32;
    // First: the manager install_toolchain prefers, and the hint check_toolchain shows.
    expect(Object.keys(win ?? {})[0]).toBe('release');
    const spec = win?.release;
    expect(spec?.command).toBe('powershell');
    expect(spec?.needs_elevation).toBe(false);
    expect(spec?.args.slice(0, -1)).toEqual(['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command']);
    const script = spec?.args[spec.args.length - 1] ?? '';
    expect(script).toContain(`'${r.base}/${a.file}'`);
    expect(script).toContain(`'${a.sha256}'`);
    expect(script.startsWith("$ErrorActionPreference = 'Stop'")).toBe(true);
    expect(script.indexOf('Get-FileHash')).toBeGreaterThan(script.indexOf('Invoke-WebRequest'));
    expect(script.indexOf('Get-FileHash')).toBeLessThan(script.indexOf('Expand-Archive'));
    expect(script.indexOf('Expand-Archive')).toBeLessThan(script.indexOf('Copy-Item'));
    // Into the per-user tools directory, the Windows twin of ~/.local/bin.
    expect(script).toContain("Join-Path $env:USERPROFILE '.local\\bin'");
    expect(script).toContain(`${tool}.exe`);
    // A CPU with no pinned sum is refused; no double quote for the command line to mangle.
    expect(script).toMatch(/-ne 'AMD64'\) \{ throw/);
    expect(script).not.toContain('"');
    expect(script).not.toMatch(/latest/i);
    expect(spec?.description).toContain(r.version);
    expect(spec?.description).toContain('%USERPROFILE%\\.local\\bin');
  });

  it.each(PINNED_TOOLS)('%s on Windows: scoop, choco and winget only as fallbacks that name the pinned version', (tool) => {
    const { version } = PINNED_RELEASES[tool];
    const win = TOOL_CATALOG[tool]?.install.win32;
    expect(win?.scoop?.args).toEqual(['install', `${tool}@${version}`]);
    expect(win?.choco?.args).toEqual(['install', '-y', tool, '--version', version]);
    if (win?.winget !== undefined) {
      expect(win.winget.args).toEqual(expect.arrayContaining(['--exact', '--version', version]));
      expect(win.winget.args[win.winget.args.indexOf('--version') + 1]).toBe(version);
    }
    for (const spec of Object.values(win ?? {})) expect(spec.description ?? '').toContain(version);
  });

  it('no Linux or macOS entry of the three installs from a repository that follows upstream, but brew', () => {
    for (const tool of PINNED_TOOLS) {
      const { linux, darwin } = TOOL_CATALOG[tool]?.install ?? { linux: {}, darwin: {} };
      expect(Object.keys(linux), tool).toEqual(['curl']);
      expect(Object.keys(darwin), tool).toEqual(['brew', 'curl']);
    }
  });
});

describe('install-linux.sh installs the same pinned archives', () => {
  const script = readFileSync(fileURLToPath(new URL('../../../../scripts/install/install-linux.sh', import.meta.url)), 'utf8');
  const flat = script.replace(/\\\r?\n\s*/g, ' ').replace(/[ \t]+/g, ' ');

  it.each(PINNED_TOOLS)('%s: the catalogue’s version, assets and sums', (tool) => {
    const r = PINNED_RELEASES[tool];
    const amd = r.assets['linux-amd64'];
    const arm = r.assets['linux-arm64'];
    expect(flat).toContain(`instala_fixado ${tool} "${r.base}" ${amd.file} ${amd.sha256} ${arm.file} ${arm.sha256}`);
  });

  it('fetches nothing from a moving target: no releases/latest, no GitHub API lookup, no apt repository, no main', () => {
    expect(script).not.toMatch(/releases\/latest|api\.github\.com|trivy-repo|\/main\/install\.sh/);
    expect(script).not.toMatch(/apt-get install[^\n]*\btrivy\b/);
  });

  it('checks the sum before unpacking, and every step fails on its own (set -e does not reach a function run under ||)', () => {
    const fn = script.slice(script.indexOf('instala_fixado() {'), script.indexOf('\n}\n', script.indexOf('instala_fixado() {')));
    expect(fn).toContain('sha256sum -c -');
    expect(fn.indexOf('sha256sum -c -')).toBeLessThan(fn.indexOf('tar -xzf'));
    expect(fn.indexOf('tar -xzf')).toBeLessThan(fn.indexOf('install -m 0755'));
    expect(fn).toMatch(/\*\) echo "[^"]*" >&2; return 1 ;;/);
  });

  it("runs `semgrep --version` with Semgrep's version check off", () => {
    expect(script).toContain('SEMGREP_ENABLE_VERSION_CHECK=0 semgrep --version');
    expect(script).not.toMatch(/\$\(semgrep --version/);
  });
});

describe('bandit install', () => {
  // The pre-commit template's bandit hook reads pyproject.toml's
  // [tool.bandit] section when the project has one (configs/pre-commit/
  // pre-commit-config.yaml) — which needs the `toml` extra installed, or
  // bandit cannot parse the file at all. Every pipx-based install path
  // should ask for it, so `install_toolchain` leaves a bandit that can
  // actually do what the shipped hook asks of it.
  it('installs the toml extra everywhere it uses pipx', () => {
    const meta = TOOL_CATALOG['bandit'];
    expect(meta?.install.win32.scoop?.args).toContain('bandit[toml]');
    expect(meta?.install.linux.pipx?.args).toContain('bandit[toml]');
    expect(meta?.install.darwin.pipx?.args).toContain('bandit[toml]');
  });
});
