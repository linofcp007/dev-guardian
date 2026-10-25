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
  PSALM_PHAR_SHA256,
  PSALM_VERSION,
  TOOL_CATALOG,
  TRIVY_INSTALL_TAG,
  knownCompromise,
  pickInstallSpec,
  suggestedInstallCommandString,
} from '../../../src/runners/installCatalog.js';
import { COSIGN_MIN_VERSION } from '../../../src/runners/cosignCheck.js';
import { CPPCHECK_MIN_VERSION } from '../../../src/runners/cppcheckRun.js';
import { PHP_MIN_VERSION } from '../../../src/runners/psalmRun.js';

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
      // Trivy: the pinned archive first on macOS too (see the next describe).
      expect(Object.keys(darwin), tool).toEqual(tool === 'trivy' ? ['curl', 'brew'] : ['brew', 'curl']);
    }
  });
});

describe('Trivy on macOS: the pinned archive first, homebrew-core after, never the vendor tap', () => {
  const all = (...names: string[]): Array<{ name: 'brew' | 'curl' | 'pipx' }> =>
    names.map((name) => ({ name: name as 'brew' | 'curl' | 'pipx' }));

  it('install_toolchain picks the pinned archive though Homebrew is first in the macOS order', () => {
    const picked = pickInstallSpec('trivy', 'darwin', all('brew', 'pipx', 'curl'));
    expect(picked?.manager).toBe('curl');
    expect(picked?.spec.description).toContain(`trivy v${PINNED_RELEASES.trivy.version} release archive (darwin, sha256-checked)`);
    expect(suggestedInstallCommandString('trivy', 'darwin')).toBe(picked?.spec.description);
  });

  it("without curl, homebrew-core's own formula — not a tap", () => {
    const picked = pickInstallSpec('trivy', 'darwin', all('brew'));
    expect(picked).toEqual({ manager: 'brew', spec: expect.objectContaining({ command: 'brew', args: ['install', 'trivy'] }) });
  });

  it('the preference is Trivy’s alone: gitleaks and syft keep Homebrew first on macOS', () => {
    for (const tool of ['gitleaks', 'syft']) expect(pickInstallSpec(tool, 'darwin', all('brew', 'curl'))?.manager, tool).toBe('brew');
  });

  it('no catalogue entry installs Trivy from a Homebrew tap', () => {
    const specs = Object.values(TOOL_CATALOG['trivy']?.install ?? {}).flatMap((os) => Object.values(os));
    for (const spec of specs) expect(spec.args.join(' ')).not.toMatch(/aquasecurity\/trivy\/trivy|\btap\b/);
  });
});

describe('install-macos.sh installs the pinned Trivy archive', () => {
  const script = readFileSync(fileURLToPath(new URL('../../../../scripts/install/install-macos.sh', import.meta.url)), 'utf8');
  const flat = script.replace(/\\\r?\n\s*/g, ' ').replace(/[ \t]+/g, ' ');

  it('the catalogue’s version, macOS assets and sums, and no brew install of trivy', () => {
    const r = PINNED_RELEASES.trivy;
    const amd = r.assets['darwin-amd64'];
    const arm = r.assets['darwin-arm64'];
    expect(flat).toContain(`instala_fixado trivy "${r.base}" ${amd.file} ${amd.sha256} ${arm.file} ${arm.sha256}`);
    expect(script).not.toMatch(/brew_install trivy|aquasecurity\/trivy\/trivy/);
  });

  it('checks the sum with shasum before unpacking, and every step fails on its own', () => {
    const fn = script.slice(script.indexOf('instala_fixado() {'), script.indexOf('\n}\n', script.indexOf('instala_fixado() {')));
    expect(fn).toContain('shasum -a 256 -c -');
    expect(fn.indexOf('shasum -a 256 -c -')).toBeLessThan(fn.indexOf('tar -xzf'));
    expect(fn.indexOf('tar -xzf')).toBeLessThan(fn.indexOf('install -m 0755'));
    expect(fn).toMatch(/\*\) echo "[^"]*" >&2; return 1 ;;/);
    expect(script).not.toMatch(/releases\/latest/);
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

describe('gosec: the pinned release archive everywhere, Windows’ own tar.exe for its .tar.gz', () => {
  const r = PINNED_RELEASES.gosec;

  it('every sum is a sha256 of an asset of the pinned version', () => {
    expect(r.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(r.base).toBe(`https://github.com/securego/gosec/releases/download/v${r.version}`);
    for (const a of Object.values(r.assets)) {
      expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(a.file).toContain(`gosec_${r.version}_`);
      expect(a.file.endsWith('.tar.gz')).toBe(true);
    }
  });

  it.each([
    ['linux', 'sha256sum -c -'],
    ['darwin', 'shasum -a 256 -c -'],
  ] as const)('on %s: the archive for each CPU, checked before it is unpacked', (os, checker) => {
    const script = TOOL_CATALOG['gosec']?.install[os].curl?.args[1] ?? '';
    for (const arch of ['amd64', 'arm64'] as const) {
      const a = r.assets[`${os}-${arch}`];
      expect(script).toContain(`asset=${a.file}; sum=${a.sha256}`);
    }
    expect(script.indexOf(checker)).toBeLessThan(script.indexOf('tar -xzf'));
    expect(script).toContain('tar -xzf "$tmp/gosec.tar.gz" -C "$tmp" gosec');
    expect(script).not.toMatch(/\/main\/|latest|install\.sh|\|\s*sh\b/);
  });

  it('go install names the same tag, never @latest', () => {
    for (const os of ['linux', 'darwin'] as const) {
      expect(TOOL_CATALOG['gosec']?.install[os].go?.args).toEqual(['install', `github.com/securego/gosec/v2/cmd/gosec@v${r.version}`]);
    }
  });

  it("on Windows: Get-FileHash, then System32's tar.exe unpacks gosec.exe alone, its exit code checked", () => {
    const win = TOOL_CATALOG['gosec']?.install.win32;
    expect(Object.keys(win ?? {})).toEqual(['release']);
    const script = win?.release?.args.at(-1) ?? '';
    const a = r.assets['windows-amd64'];
    expect(script).toContain(`'${r.base}/${a.file}'`);
    expect(script).toContain(`'${a.sha256}'`);
    expect(script).toContain("$zip = Join-Path $tmp 'gosec.tar.gz'");
    expect(script).toContain("& (Join-Path $env:SystemRoot 'System32\\tar.exe') -xzf $zip -C (Join-Path $tmp 'x') gosec.exe");
    expect(script).toContain('if ($LASTEXITCODE -ne 0) { throw');
    expect(script).not.toContain('Expand-Archive');
    expect(script.indexOf('Get-FileHash')).toBeLessThan(script.indexOf('tar.exe'));
    expect(script.indexOf('tar.exe')).toBeLessThan(script.indexOf('Copy-Item'));
    expect(script).not.toContain('"');
  });

  it('the ZIP releases keep Expand-Archive, and never reach for tar.exe', () => {
    for (const tool of ['syft', 'trivy', 'gitleaks']) {
      const script = TOOL_CATALOG[tool]?.install.win32.release?.args.at(-1) ?? '';
      expect(script, tool).toContain('Expand-Archive');
      expect(script, tool).not.toContain('tar.exe');
    }
  });

  it('is probed with -version and is only installed when Go is detected', () => {
    expect(TOOL_CATALOG['gosec']?.probe).toEqual({ command: 'gosec', args: ['-version'] });
    expect(TOOL_CATALOG['gosec']?.default).toBe(false);
  });
});

describe('the Go toolchain: hints only, never installed', () => {
  it('names go version as its probe and a manual hint per OS', () => {
    const go = TOOL_CATALOG['go'];
    expect(go?.probe).toEqual({ command: 'go', args: ['version'] });
    expect(suggestedInstallCommandString('go', 'win32')).toBe('winget install GoLang.Go');
    expect(suggestedInstallCommandString('go', 'darwin')).toBe('brew install go');
    for (const os of ['win32', 'linux', 'darwin'] as const) {
      for (const spec of Object.values(go?.install[os] ?? {})) expect(spec.command).toBe('echo');
    }
  });
});

describe('shellcheck: the pinned archive, its binary nested in a versioned directory', () => {
  const r = PINNED_RELEASES.shellcheck;

  it.each(['linux', 'darwin'] as const)('on %s: each CPU names its archive, sum and member; the member is what is unpacked and installed', (os) => {
    const script = TOOL_CATALOG['shellcheck']?.install[os].curl?.args[1] ?? '';
    for (const arch of ['amd64', 'arm64'] as const) {
      const a = r.assets[`${os}-${arch}`];
      expect(a.member).toBe(`shellcheck-v${r.version}/shellcheck`);
      expect(script).toContain(`asset=${a.file}; sum=${a.sha256}; member=${a.member ?? ''}`);
    }
    expect(script).toContain('tar -xzf "$tmp/shellcheck.tar.gz" -C "$tmp" "$member"');
    expect(script).toContain('install -m 0755 "$tmp/$member" "$HOME/.local/bin/shellcheck"');
  });

  it('on Windows: the ZIP, whose shellcheck.exe is at the root', () => {
    const script = TOOL_CATALOG['shellcheck']?.install.win32.release?.args.at(-1) ?? '';
    expect(script).toContain(`'${r.base}/${r.assets['windows-amd64'].file}'`);
    expect(script).toContain('Expand-Archive');
    expect(script).toContain("Join-Path $tmp 'x\\shellcheck.exe'");
  });

  it('a release without a member keeps the tool name at the root (gosec)', () => {
    const script = TOOL_CATALOG['gosec']?.install.linux.curl?.args[1] ?? '';
    expect(script).not.toContain('member=');
    expect(script).toContain('tar -xzf "$tmp/gosec.tar.gz" -C "$tmp" gosec');
  });
});

describe('govulncheck: go install of a pinned tag into the per-user tools directory', () => {
  it('POSIX: GOBIN is ~/.local/bin, the tag exact', () => {
    for (const os of ['linux', 'darwin'] as const) {
      const spec = TOOL_CATALOG['govulncheck']?.install[os].go;
      expect(spec?.command).toBe('bash');
      expect(spec?.args[1]).toContain(`GOBIN="$HOME/.local/bin" go install 'golang.org/x/vuln/cmd/govulncheck@v1.9.0'`);
      expect(spec?.user_bin).toBe('govulncheck');
      expect(spec?.args[1]).not.toMatch(/@latest/);
    }
  });

  it('Windows: PowerShell sets GOBIN to the per-user tools directory, with no double quote', () => {
    const spec = TOOL_CATALOG['govulncheck']?.install.win32.go;
    const script = spec?.args.at(-1) ?? '';
    expect(spec?.command).toBe('powershell');
    expect(script).toContain("$env:GOBIN = Join-Path $env:USERPROFILE '.local\\bin'");
    expect(script).toContain("go install 'golang.org/x/vuln/cmd/govulncheck@v1.9.0'");
    expect(script).toContain('if ($LASTEXITCODE -ne 0) { throw');
    expect(script).not.toContain('"');
    expect(spec?.user_bin).toBe('govulncheck.exe');
  });
});

describe('cppcheck: scoop first on Windows, the release pinned, the floor the runner enforces', () => {
  it('scoop (per user) is picked before winget, whose MSI installs per machine and so needs elevation', () => {
    const win = TOOL_CATALOG['cppcheck']?.install.win32;
    expect(win?.scoop?.args).toEqual(['install', 'cppcheck@2.22.0']);
    expect(win?.winget?.args).toEqual(expect.arrayContaining(['Cppcheck.Cppcheck', '--exact', '--version', '2.22.0']));
    expect(win?.winget?.needs_elevation).toBe(true);
    expect(pickInstallSpec('cppcheck', 'win32', [{ name: 'release' }, { name: 'winget' }, { name: 'scoop' }])?.manager).toBe('scoop');
    expect(pickInstallSpec('cppcheck', 'win32', [{ name: 'release' }, { name: 'winget' }])?.manager).toBe('winget');
  });

  it('version_floor is CPPCHECK_MIN_VERSION, which scan_sast checks before every run', () => {
    expect(TOOL_CATALOG['cppcheck']?.version_floor).toBe(`${CPPCHECK_MIN_VERSION}.0`);
    expect(TOOL_CATALOG['cppcheck']?.required_by).toEqual(['scan_sast', 'security_scan_full', 'review_pr']);
  });
});

describe('Psalm: the release PHAR, sha256-checked, run by php; PHP itself never installed', () => {
  it('POSIX: curl, the pinned sum checked before the PHAR is installed to ~/.local/bin/psalm.phar', () => {
    for (const os of ['linux', 'darwin'] as const) {
      const spec = TOOL_CATALOG['psalm']?.install[os].curl;
      const script = spec?.args[1] ?? '';
      expect(script).toContain(`https://github.com/vimeo/psalm/releases/download/${PSALM_VERSION}/psalm.phar`);
      expect(script).toContain(`echo "${PSALM_PHAR_SHA256}  $tmp" | ${os === 'linux' ? 'sha256sum' : 'shasum -a 256'} -c -`);
      expect(script.indexOf('-c -')).toBeLessThan(script.indexOf('install -m 0755'));
      expect(spec?.user_bin).toBe('psalm.phar');
    }
  });

  it('Windows: PowerShell checks the same sum and copies psalm.phar to the per-user tools directory', () => {
    const script = TOOL_CATALOG['psalm']?.install.win32.release?.args.at(-1) ?? '';
    expect(script).toContain(`if ($got -ne '${PSALM_PHAR_SHA256}')`);
    expect(script).toContain("Join-Path $env:USERPROFILE '.local\\bin'");
    expect(TOOL_CATALOG['psalm']?.probe).toEqual({ command: 'psalm.phar', args: ['--version'], interpreter: 'php' });
  });

  it('PHP: manual steps only, on every OS', () => {
    expect(suggestedInstallCommandString('php', 'win32')).toBe('winget install PHP.PHP.8.4');
    expect(suggestedInstallCommandString('php', 'linux')).toBe('sudo apt-get install php-cli php-xml php-mbstring');
    for (const os of ['win32', 'linux', 'darwin'] as const) {
      for (const spec of Object.values(TOOL_CATALOG['php']?.install[os] ?? {})) expect(spec.command).toBe('echo');
    }
    expect(TOOL_CATALOG['php']?.version_floor).toBe(`${PHP_MIN_VERSION.join('.')}.0`);
  });
});

describe('detekt, SpotBugs and RuboCop: pinned, checked before installed; Java and Ruby never installed', () => {
  it('detekt: the Maven Central jar, its sum checked before it is installed to ~/.local/bin/detekt-cli.jar, run by java -jar', () => {
    for (const os of ['linux', 'darwin'] as const) {
      const spec = TOOL_CATALOG['detekt']?.install[os].curl;
      const script = spec?.args[1] ?? '';
      expect(script).toContain('https://repo1.maven.org/maven2/io/gitlab/arturbosch/detekt/detekt-cli/1.23.8/detekt-cli-1.23.8-all.jar');
      expect(script).toMatch(/echo "[0-9a-f]{64} {2}\$tmp" \| (sha256sum|shasum -a 256) -c -/);
      expect(script.indexOf('-c -')).toBeLessThan(script.indexOf('install -m 0755'));
      expect(spec?.user_bin).toBe('detekt-cli.jar');
    }
    const win = TOOL_CATALOG['detekt']?.install.win32.release?.args.at(-1) ?? '';
    expect(win).toMatch(/if \(\$got -ne '[0-9a-f]{64}'\)/);
    expect(win.indexOf('Get-FileHash')).toBeLessThan(win.indexOf('Copy-Item'));
    expect(TOOL_CATALOG['detekt']?.probe).toEqual({ command: 'detekt-cli.jar', args: ['--version'], interpreter: 'java' });
  });

  it('SpotBugs: its archive and the FindSecBugs jar each checked, then the tree moved into place with the plugin in plugin/', () => {
    const script = TOOL_CATALOG['spotbugs']?.install.linux.curl?.args[1] ?? '';
    expect(script).toContain('https://github.com/spotbugs/spotbugs/releases/download/4.10.5/spotbugs-4.10.5.tgz');
    expect(script).toContain('https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.14.0/findsecbugs-plugin-1.14.0.jar');
    expect(script.match(/sha256sum -c -/g)).toHaveLength(2);
    expect(script.lastIndexOf('-c -')).toBeLessThan(script.indexOf('tar -xzf'));
    expect(script).toContain('"$home.new/plugin/findsecbugs-plugin-1.14.0.jar"');
    expect(script.indexOf('mv "$home.new" "$home"')).toBeGreaterThan(script.indexOf('install -m 0644'));
    const win = TOOL_CATALOG['spotbugs']?.install.win32.release?.args.at(-1) ?? '';
    expect(win.match(/Get-FileHash/g)).toHaveLength(2);
    expect(win.lastIndexOf('Get-FileHash')).toBeLessThan(win.indexOf('Expand-Archive'));
    // Unpacked beside the install (one volume), and the old one removed only once the new tree is complete.
    expect(win).toContain("Expand-Archive -LiteralPath $zip -DestinationPath $stage");
    expect(win.indexOf("$stage = Join-Path $lib 'spotbugs.new'")).toBeLessThan(win.indexOf('Expand-Archive'));
    expect(win.indexOf('Remove-Item -Recurse -Force -LiteralPath $dest')).toBeGreaterThan(win.indexOf('findsecbugs-plugin-1.14.0.jar'));
    expect(TOOL_CATALOG['spotbugs']?.probe.args).toEqual(['-textui', '-version']);
  });

  it('RuboCop: the pinned gem, conservative, for this user, its script into the per-user tools directory, run by ruby -S gem', () => {
    for (const os of ['win32', 'linux', 'darwin'] as const) {
      const spec = TOOL_CATALOG['rubocop']?.install[os].gem;
      expect(spec?.command).toBe('ruby');
      expect(spec?.args.slice(0, 10)).toEqual(['-S', 'gem', 'install', 'rubocop', '-v', '1.92.1', '--user-install', '--conservative', '--no-document', '--bindir']);
      expect(spec?.user_bin).toBe('rubocop');
    }
    expect(TOOL_CATALOG['rubocop']?.probe).toEqual({ command: 'rubocop', args: ['--version'], interpreter: 'ruby' });
  });

  it('Java and Ruby: manual steps only, on every OS', () => {
    expect(suggestedInstallCommandString('java', 'win32')).toBe('winget install EclipseAdoptium.Temurin.21.JRE');
    expect(suggestedInstallCommandString('ruby', 'linux')).toBe('sudo apt-get install ruby ruby-dev build-essential');
    for (const tool of ['java', 'ruby']) {
      for (const os of ['win32', 'linux', 'darwin'] as const) {
        for (const spec of Object.values(TOOL_CATALOG[tool]?.install[os] ?? {})) expect(spec.command).toBe('echo');
      }
    }
  });
});
