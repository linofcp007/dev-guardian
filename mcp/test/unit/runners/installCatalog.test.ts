/**
 * Catalogue facts that were wrong, pinned: the install hints users are shown,
 * the one install that piped a moving branch into `sh`, the probe every entry
 * now carries, and the known-compromised Trivy releases.
 */
import { describe, expect, it } from 'vitest';
import {
  COSIGN_RELEASE_SHA256,
  COSIGN_VERSION,
  TOOL_CATALOG,
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

describe('trivy curl installer', () => {
  const curl = TOOL_CATALOG['trivy']?.install.linux.curl;
  const script = curl?.args[1] ?? '';

  it('fetches install.sh from a release tag, never from main', () => {
    expect(script).not.toContain('/main/');
    expect(script).toMatch(/raw\.githubusercontent\.com\/aquasecurity\/trivy\/v\d+\.\d+\.\d+\/contrib\/install\.sh/);
  });

  it('installs that same tag, not whatever is "latest" when it runs', () => {
    const tag = /trivy\/(v\d+\.\d+\.\d+)\//.exec(script)?.[1];
    expect(tag).toBeDefined();
    expect(script.trim().endsWith(` ${tag ?? ''}`)).toBe(true);
  });

  it('never pins a known-compromised release', () => {
    const tag = /trivy\/v(\d+\.\d+\.\d+)\//.exec(script)?.[1] ?? '';
    expect(knownCompromise('trivy', tag)).toBeNull();
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
