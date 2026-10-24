/**
 * Toolchain catalogue.
 *
 * One source of truth for:
 *   - which scanners dev-guardian knows about,
 *   - which MCP tools depend on each scanner (`required_by`),
 *   - the version floor we expect (informational — not enforced strictly),
 *   - the install command per OS / package manager.
 *
 * `check_toolchain` and `install_toolchain` both read from here. Adding a
 * new scanner: append an entry and the rest is wired automatically.
 */

import type { DetectedOs } from '../platform/osDetect.js';
import { compareSemver } from '../platform/semverCompare.js';
import { SEMGREP_NO_VERSION_CHECK_ENV } from './semgrepRun.js';
import type { VersionProbe } from './toolProbe.js';

/**
 * `release`: a pinned GitHub release ZIP, checked against its sha256 with
 * PowerShell before it is unpacked (`windowsReleaseInstaller`) — preferred
 * where the catalogue has one; winget, scoop and choco follow their own
 * manifests.
 */
type WindowsPkgManager = 'release' | 'winget' | 'scoop' | 'choco' | 'wsl';
type PosixPkgManager = 'apt' | 'brew' | 'pipx' | 'npm' | 'curl' | 'uv' | 'cargo' | 'go';

export interface InstallSpec {
  /** Shell command (as a tokenised argv) to install. */
  command: string;
  args: string[];
  /** True when the spec needs admin/sudo (winget on per-machine, apt, brew formula-cask). */
  needs_elevation: boolean;
  /** Optional, human-readable. Shown when `install_toolchain` returns dry-run results. */
  description?: string;
  /**
   * The file this installer writes into the per-user tools directory
   * (`platform/userBin.ts`: `~/.local/bin`, `%USERPROFILE%\.local\bin`), when
   * it writes there: `install_toolchain` says where the binary went, and
   * whether a terminal will find it.
   */
  user_bin?: string;
}

/**
 * A range of releases known to be malicious — a supply-chain compromise, not
 * a vulnerability. Inclusive bounds; checked against the installed version by
 * `check_toolchain`. Every entry must cite its primary-source advisory.
 */
interface CompromisedRange {
  from: string;
  to: string;
  advisory: string;
  cve?: string;
  url: string;
  action: string;
}

interface ToolMeta {
  name: string;
  version_floor: string;
  required_by: string[];
  /** How `check_toolchain` asks this tool for its version (argv, no shell). */
  probe: VersionProbe;
  /** Releases that must never be run. */
  compromised?: CompromisedRange[];
  install: {
    win32: Partial<Record<WindowsPkgManager, InstallSpec>>;
    linux: Partial<Record<PosixPkgManager, InstallSpec>>;
    darwin: Partial<Record<PosixPkgManager, InstallSpec>>;
  };
  /**
   * Installers tried first for this tool on an OS, in this order, when they
   * are available — ahead of `install_toolchain`'s general order for that OS
   * (Homebrew first on macOS). Trivy's pinned archive on macOS: see its entry.
   */
  prefer?: { darwin?: readonly PosixPkgManager[]; linux?: readonly PosixPkgManager[] };
  /** Whether this tool is part of the default install profile. */
  default: boolean;
}

/**
 * The Trivy release every Trivy install fetches: the pinned archive in
 * {@link PINNED_RELEASES} on Linux, macOS (before homebrew-core) and Windows, and
 * the version winget, scoop and choco are asked for. Pinned because the
 * installer used to be piped from the `main` branch into `sh` and then
 * install "latest": on 2026-03-19 "latest" WAS the malicious v0.69.4 (see
 * `compromised` on the trivy entry). v0.76.1 was published 2026-10-21 as an
 * immutable release (enabled on aquasecurity/trivy since 2026-03-03), built
 * with Go 1.27.3 (the eMudhra CA distrust, GO-2026-6809). Bump it and its sums
 * together, deliberately.
 */
export const TRIVY_INSTALL_TAG = 'v0.76.1';

/**
 * The cosign release every pinned installer below fetches (winget, scoop and
 * the release-binary download). v3.1.4 was published 2026-10-20 as an
 * immutable release, built with Go 1.27.3; bump it and
 * {@link COSIGN_RELEASE_SHA256} together, deliberately.
 */
export const COSIGN_VERSION = '3.1.4';

/**
 * sha256 of each POSIX release binary of {@link COSIGN_VERSION}. Each value
 * was checked three ways on 2026-10-24 and all three agreed: the binary
 * downloaded and hashed independently (`curl … | sha256sum`), the release's
 * own `cosign_checksums.txt`, and the digest GitHub records for the release
 * asset. The Windows binary is not listed: winget and scoop verify it against
 * their own manifests, which carry the same hash
 * (cbe95378…1f2a, checked against both manifests the same day).
 */
export const COSIGN_RELEASE_SHA256 = {
  'linux-amd64': '424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa',
  'linux-arm64': 'ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2',
  'darwin-amd64': '9d1e4abe2b6be279ed0d2ff706fde1ccd738747c834e3e6d44039c238867334f',
  'darwin-arm64': '9f9b8cd557cf2e5b3df3373a00baa005a86b02391e3e06dd0ce37b3a1533d3a4',
} as const;

/** A platform a pinned release archive is published for. */
type ReleasePlatform = 'linux-amd64' | 'linux-arm64' | 'darwin-amd64' | 'darwin-arm64' | 'windows-amd64';

/** A release pinned by its version AND by the sha256 of each archive an install may fetch. */
interface PinnedRelease {
  version: string;
  /** `https://github.com/<owner>/<repo>/releases/download/v<version>` */
  base: string;
  assets: Readonly<Record<ReleasePlatform, { file: string; sha256: string }>>;
}

const SYFT_VERSION = '1.55.0';
const TRIVY_VERSION = TRIVY_INSTALL_TAG.slice(1);
const GITLEAKS_VERSION = '8.30.1';
const GOSEC_VERSION = '2.30.0';

/**
 * The Syft, Trivy and gitleaks releases every install of them fetches — the
 * entries below on every OS, and `scripts/install/install-linux.sh`, which
 * `install_toolchain` runs for the Linux defaults and the Windows WSL
 * fallback (a test holds its tags and sums to these). Each used to come in
 * through a route that followed upstream — Syft's `install.sh` piped from
 * `main`, Trivy from apt or `releases/latest`, gitleaks from
 * `releases/latest`, scoop and choco on Windows — the route the malicious
 * Trivy v0.69.4 took on 2026-03-19 ({@link TRIVY_INSTALL_TAG}). Bump a
 * version and its sums together, deliberately.
 *
 * Every sha256 was checked on 2026-09-29 three ways, and they agreed: the
 * archive downloaded and hashed independently; the release's own
 * `<tool>_<version>_checksums.txt` (itself matching its GitHub asset
 * digest); and the digest GitHub records for the asset. The Windows ZIPs
 * also match scoop's Main bucket (all three) and winget-pkgs (Trivy,
 * gitleaks). Syft 1.55.0 (2026-10-19) and Trivy 0.76.1 (2026-10-21) are
 * immutable releases, their sums checked the same three ways on 2026-10-24
 * (scoop and winget carry the same Windows ZIPs); gitleaks 8.30.1 (2026-03-21)
 * is not — its assets could be replaced, which the pinned sums catch.
 *
 * gosec 2.30.0 (2026-10-23) was checked on 2026-10-24: each archive hashed
 * independently and matched against the release's
 * `gosec_2.30.0_checksums.txt`, and that file and the archives verified with
 * `cosign verify-blob` against the project's own key (`cosign.pub` in
 * securego/gosec, unchanged since 2022) and the release's `.sigstore.json`
 * bundles. It ships `.tar.gz` archives for Windows too, with `gosec.exe` at
 * the root, which {@link windowsReleaseInstaller} unpacks with Windows' own
 * `tar.exe`.
 */
export const PINNED_RELEASES: Readonly<Record<'syft' | 'trivy' | 'gitleaks' | 'gosec', PinnedRelease>> = {
  syft: {
    version: SYFT_VERSION,
    base: `https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}`,
    assets: {
      'linux-amd64': { file: `syft_${SYFT_VERSION}_linux_amd64.tar.gz`, sha256: 'bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d' },
      'linux-arm64': { file: `syft_${SYFT_VERSION}_linux_arm64.tar.gz`, sha256: '929bd163db2d7cd2255d3bcb8967208079813d7b46b0c952f7b794d8e2c7d304' },
      'darwin-amd64': { file: `syft_${SYFT_VERSION}_darwin_amd64.tar.gz`, sha256: 'e2e5831cbabaec9a36fe65c34755c1113982c842a685edce3ce0b54a0ded8003' },
      'darwin-arm64': { file: `syft_${SYFT_VERSION}_darwin_arm64.tar.gz`, sha256: '1217c258bd5eb91ef3189cf22a82e02f9cac07e4ce934350f428e93aff674625' },
      'windows-amd64': { file: `syft_${SYFT_VERSION}_windows_amd64.zip`, sha256: 'ada4c9b93af575f479ce80fce6629897272a2d41f300a14bc49bace020767ca2' },
    },
  },
  trivy: {
    version: TRIVY_VERSION,
    base: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}`,
    assets: {
      'linux-amd64': { file: `trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz`, sha256: 'c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0' },
      'linux-arm64': { file: `trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz`, sha256: 'e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f' },
      'darwin-amd64': { file: `trivy_${TRIVY_VERSION}_macOS-64bit.tar.gz`, sha256: '7aa762eacd582052d053b62dcf972a1ab058abe39a57ccae234ed8894945b6b7' },
      'darwin-arm64': { file: `trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz`, sha256: '11a9b6cd2752011b54f01ea4bd0dbfa9f0c41dc6538d5a3f9d23955f471bf4e5' },
      'windows-amd64': { file: `trivy_${TRIVY_VERSION}_windows-64bit.zip`, sha256: '1051f49cb22d5284f43425f72aad9cda63ca12ceb92e7caa06903490c82dc9bf' },
    },
  },
  gitleaks: {
    version: GITLEAKS_VERSION,
    base: `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}`,
    assets: {
      'linux-amd64': { file: `gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz`, sha256: '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb' },
      'linux-arm64': { file: `gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz`, sha256: 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080' },
      'darwin-amd64': { file: `gitleaks_${GITLEAKS_VERSION}_darwin_x64.tar.gz`, sha256: 'dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709' },
      'darwin-arm64': { file: `gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz`, sha256: 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5' },
      'windows-amd64': { file: `gitleaks_${GITLEAKS_VERSION}_windows_x64.zip`, sha256: 'd29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e' },
    },
  },
  gosec: {
    version: GOSEC_VERSION,
    base: `https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}`,
    assets: {
      'linux-amd64': { file: `gosec_${GOSEC_VERSION}_linux_amd64.tar.gz`, sha256: '3fcce2c4e802ff4169217874602a7df355e9a37bcb6ffaa34b08f3d5f336cdfb' },
      'linux-arm64': { file: `gosec_${GOSEC_VERSION}_linux_arm64.tar.gz`, sha256: '0867994920453070a5d6a713e35921a3058473e5c3bf777fdd5a2d6f95313fda' },
      'darwin-amd64': { file: `gosec_${GOSEC_VERSION}_darwin_amd64.tar.gz`, sha256: '1b10b496954791f4b57448722f0cb93c0fa4aba24e9d286c0459dfde593e0898' },
      'darwin-arm64': { file: `gosec_${GOSEC_VERSION}_darwin_arm64.tar.gz`, sha256: 'cac8c480673fc179798402b6d86efc12b6bcf11c18bcf377fda02cc55846dd97' },
      'windows-amd64': { file: `gosec_${GOSEC_VERSION}_windows_amd64.tar.gz`, sha256: '503bdfe6155584f2497ef855846b66406bce5b574ce1a9c7a7bb171aff2caa02' },
    },
  },
};

export const TOOL_CATALOG: Record<string, ToolMeta> = {
  semgrep: {
    name: 'semgrep',
    version_floor: '1.0.0',
    // `semgrep --version` runs Semgrep's version check too: off (semgrepRun.ts).
    probe: { command: 'semgrep', args: ['--version'], env: SEMGREP_NO_VERSION_CHECK_ENV },
    required_by: ['scan_sast', 'security_scan_full', 'bug_hunt', 'review_pr', 'compliance_check'],
    install: {
      win32: {
        scoop: pipxInstall('semgrep'),
        choco: pipxInstall('semgrep'),
      },
      linux: { pipx: pipxInstall('semgrep') },
      darwin: { brew: brewInstall('semgrep'), pipx: pipxInstall('semgrep') },
    },
    default: true,
  },
  trivy: {
    name: 'trivy',
    version_floor: '0.40.0',
    probe: { command: 'trivy', args: ['--version'] },
    compromised: [
      {
        // Verified against the primary source, the GitHub advisory
        // (https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23,
        // published 2026-03-21, CVE-2026-33634): v0.69.4 binaries and images
        // were published with credential-stealing code on 2026-03-19, and
        // malicious v0.69.5 / v0.69.6 images were pushed to Docker Hub on
        // 2026-03-22 with no matching GitHub release. The advisory names
        // v0.69.2 and v0.69.3 as known-safe. A binary reporting any of the
        // three versions came from one of those artifacts.
        from: '0.69.4',
        to: '0.69.6',
        advisory: 'GHSA-69fq-xp46-6x23',
        cve: 'CVE-2026-33634',
        url: 'https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23',
        action:
          'Remove this Trivy build now, install a release the advisory lists as safe (or a later one), ' +
          'and rotate every secret it could read — it exfiltrated credentials.',
      },
    ],
    required_by: [
      'scan_deps',
      'scan_containers',
      'scan_iac',
      'security_scan_full',
      'deps_audit',
      'compliance_check',
      'generate_sbom',
    ],
    install: {
      // The pinned release archive, sha256-checked, on every OS (see
      // PINNED_RELEASES); a package manager only at that same version. No
      // apt entry: aquasecurity's apt repository serves whatever is latest.
      win32: {
        release: windowsReleaseInstaller('trivy'),
        scoop: scoopInstall(`trivy@${TRIVY_VERSION}`),
        choco: chocoInstall('trivy', TRIVY_VERSION),
        winget: wingetInstall('AquaSecurity.Trivy', TRIVY_VERSION),
      },
      linux: { curl: releaseArchiveInstaller('trivy', 'linux') },
      // macOS: the pinned archive FIRST (`prefer` below), then homebrew-core's
      // own `trivy` formula (built and bottled by Homebrew). Homebrew used to
      // come first here through the vendor tap `aquasecurity/trivy/trivy`,
      // which installs Aqua's own release binaries rather than a Homebrew
      // bottle — found serving 0.69.3 by the 3.0 review, older than the pin
      // and the route a compromised release would take — while every other
      // install of Trivy was pinned. `scripts/install/install-macos.sh` takes
      // the same archive.
      darwin: { curl: releaseArchiveInstaller('trivy', 'darwin'), brew: brewInstall('trivy') },
    },
    prefer: { darwin: ['curl'] },
    default: true,
  },
  gitleaks: {
    name: 'gitleaks',
    version_floor: '8.0.0',
    probe: { command: 'gitleaks', args: ['version'] },
    required_by: ['scan_secrets', 'security_scan_full', 'review_pr'],
    install: {
      // The pinned release archive, sha256-checked (see PINNED_RELEASES).
      // Linux had no entry at all — gitleaks ships archives, no install
      // script — and install-linux.sh took `releases/latest` unchecked.
      win32: {
        release: windowsReleaseInstaller('gitleaks'),
        scoop: scoopInstall(`gitleaks@${GITLEAKS_VERSION}`),
        choco: chocoInstall('gitleaks', GITLEAKS_VERSION),
        // The id as winget-pkgs spells it: `--exact` matches case too.
        winget: wingetInstall('Gitleaks.Gitleaks', GITLEAKS_VERSION),
      },
      linux: { curl: releaseArchiveInstaller('gitleaks', 'linux') },
      darwin: { brew: brewInstall('gitleaks'), curl: releaseArchiveInstaller('gitleaks', 'darwin') },
    },
    default: true,
  },
  syft: {
    name: 'syft',
    version_floor: '0.80.0',
    probe: { command: 'syft', args: ['version'] },
    required_by: ['generate_sbom'],
    install: {
      // The pinned release archive, sha256-checked (see PINNED_RELEASES) —
      // never install.sh from `main`, never "latest".
      win32: {
        release: windowsReleaseInstaller('syft'),
        scoop: scoopInstall(`syft@${SYFT_VERSION}`),
        choco: chocoInstall('syft', SYFT_VERSION),
      },
      linux: { curl: releaseArchiveInstaller('syft', 'linux') },
      darwin: { brew: brewInstall('syft'), curl: releaseArchiveInstaller('syft', 'darwin') },
    },
    default: true,
  },
  'pre-commit': {
    name: 'pre-commit',
    version_floor: '3.0.0',
    probe: { command: 'pre-commit', args: ['--version'] },
    required_by: ['init_project'],
    install: {
      win32: { scoop: pipxInstall('pre-commit') },
      linux: { pipx: pipxInstall('pre-commit') },
      darwin: { brew: brewInstall('pre-commit'), pipx: pipxInstall('pre-commit') },
    },
    default: true,
  },
  ruff: {
    name: 'ruff',
    version_floor: '0.1.0',
    probe: { command: 'ruff', args: ['--version'] },
    required_by: ['quality_check'],
    install: {
      win32: { scoop: pipxInstall('ruff') },
      linux: { pipx: pipxInstall('ruff') },
      darwin: { brew: brewInstall('ruff'), pipx: pipxInstall('ruff') },
    },
    default: false, // only when Python detected
  },
  bandit: {
    name: 'bandit',
    version_floor: '1.7.0',
    probe: { command: 'bandit', args: ['--version'] },
    required_by: ['scan_sast', 'security_scan_full', 'init_project'],
    install: {
      // `bandit[toml]` everywhere pipx is the installer: the pre-commit
      // template's bandit hook (configs/pre-commit/pre-commit-config.yaml)
      // passes `-c pyproject.toml` when the project has one, which needs the
      // `toml` extra to parse it — plain `bandit` cannot read that file at
      // all. brew's own formula does not expose extras, so darwin's brew
      // entry stays as the base package.
      win32: { scoop: pipxInstall('bandit[toml]') },
      linux: { pipx: pipxInstall('bandit[toml]') },
      darwin: { brew: brewInstall('bandit'), pipx: pipxInstall('bandit[toml]') },
    },
    default: false, // only when Python detected
  },
  gosec: {
    name: 'gosec',
    // 2.25.0: the taint rules (G701+, since 2.23.0) with the fix for their
    // hang on packages with many call graphs. Not enforced strictly.
    version_floor: '2.25.0',
    probe: { command: 'gosec', args: ['-version'] },
    required_by: ['scan_sast', 'security_scan_full', 'review_pr'],
    install: {
      // The pinned release archive, sha256-checked (see PINNED_RELEASES);
      // `go install` of the same tag where Go is (the checksum database
      // verifies the module). gosec needs the Go toolchain to run either way.
      win32: { release: windowsReleaseInstaller('gosec') },
      linux: {
        curl: releaseArchiveInstaller('gosec', 'linux'),
        go: goInstall(`github.com/securego/gosec/v2/cmd/gosec@v${GOSEC_VERSION}`),
      },
      darwin: {
        brew: brewInstall('gosec'),
        curl: releaseArchiveInstaller('gosec', 'darwin'),
        go: goInstall(`github.com/securego/gosec/v2/cmd/gosec@v${GOSEC_VERSION}`),
      },
    },
    default: false, // only when Go is detected
  },
  // The Go toolchain gosec loads packages through — like the .NET SDK, never
  // auto-installed (install_toolchain routes it to manual steps): the
  // project's go.mod decides which Go it needs.
  go: {
    name: 'go',
    version_floor: '1.22.0',
    probe: { command: 'go', args: ['version'] },
    required_by: ['scan_sast', 'security_scan_full', 'review_pr'],
    install: {
      win32: { winget: manualHint('winget install GoLang.Go') },
      linux: { apt: manualHint('see https://go.dev/doc/install') },
      darwin: { brew: manualHint('brew install go') },
    },
    default: false,
  },
  jscpd: {
    name: 'jscpd',
    version_floor: '3.0.0',
    probe: { command: 'jscpd', args: ['--version'] },
    required_by: ['quality_check'],
    install: {
      win32: { choco: npmInstallGlobal('jscpd') },
      linux: { npm: npmInstallGlobal('jscpd') },
      darwin: { npm: npmInstallGlobal('jscpd') },
    },
    default: false, // requires Node
  },
  lighthouse: {
    name: 'lighthouse',
    version_floor: '11.0.0',
    probe: { command: 'lighthouse', args: ['--version'] },
    required_by: ['perf_check'],
    install: {
      win32: { choco: npmInstallGlobal('lighthouse') },
      linux: { npm: npmInstallGlobal('lighthouse') },
      darwin: { npm: npmInstallGlobal('lighthouse') },
    },
    default: false, // opt-in
  },
  k6: {
    name: 'k6',
    version_floor: '0.50.0',
    probe: { command: 'k6', args: ['version'] },
    required_by: ['perf_check'],
    install: {
      win32: {
        scoop: scoopInstall('k6'),
        choco: chocoInstall('k6'),
        winget: wingetInstall('k6.k6'),
      },
      linux: { apt: aptInstall('k6') },
      darwin: { brew: brewInstall('k6') },
    },
    default: false,
  },
  // ---------- Containers ----------
  hadolint: {
    name: 'hadolint',
    version_floor: '2.0.0',
    probe: { command: 'hadolint', args: ['--version'] },
    required_by: ['scan_containers'],
    install: {
      // No install.sh on hadolint/hadolint (verified: no `install` entry in
      // its repo tree) — releases are prebuilt binaries only, and none is
      // pinned here with its sum, so Linux is left empty rather than
      // fabricated (see cosignReleaseInstaller's doc comment).
      win32: {
        scoop: scoopInstall('hadolint'),
        winget: wingetInstall('hadolint.hadolint'),
      },
      linux: {},
      darwin: { brew: brewInstall('hadolint') },
    },
    default: false, // only when a Dockerfile is present
  },
  cosign: {
    name: 'cosign',
    // 3.0.0, and scan_containers enforces it (runners/cosignCheck.ts
    // COSIGN_MIN_VERSION, the same value): cosign 2.x's `tree` does not list
    // OCI referrers — where every v3 signature and every GitHub provenance
    // attestation lives — so it reads a signed image as unsigned (measured:
    // 2.6.5 on a signed ghcr.io/sigstore/cosign/cosign:v3.1.3 prints "No …
    // Artifacts found", exit 0).
    version_floor: '3.0.0',
    probe: { command: 'cosign', args: ['version'] },
    required_by: ['scan_containers'],
    install: {
      // Verified 2026-10-24: microsoft/winget-pkgs carries Sigstore.Cosign
      // 3.1.4 and ScoopInstaller/Main carries cosign 3.1.4, both pointing
      // at the official cosign-windows-amd64.exe with the release's sha256.
      // Both take an exact version, so both are pinned.
      win32: {
        winget: {
          command: 'winget',
          args: [
            'install', '--id', 'Sigstore.Cosign', '--exact', '--version', COSIGN_VERSION,
            '--accept-source-agreements', '--accept-package-agreements',
          ],
          needs_elevation: false,
          description: `winget install Sigstore.Cosign --version ${COSIGN_VERSION}`,
        },
        scoop: scoopInstall(`cosign@${COSIGN_VERSION}`),
      },
      linux: { curl: cosignReleaseInstaller('linux') },
      // Homebrew first, as for every other darwin entry: its formula follows
      // upstream releases and brew verifies its own bottle, but it cannot be
      // held at COSIGN_VERSION. Without brew, the pinned binary.
      darwin: { brew: brewInstall('cosign'), curl: cosignReleaseInstaller('darwin') },
    },
    default: false, // only when an image is scanned
  },
  // ---------- GitHub Actions workflows ----------
  zizmor: {
    name: 'zizmor',
    // 1.0.0 marks zizmor's own API-stability baseline; `--format=json`,
    // `--no-exit-codes` and `--collect=workflows` (scan_iac.ts's invocation)
    // are all long-stable CLI surface with no "available in vX" note of
    // their own in the project's usage docs, unlike `--format=json-v1`
    // (v1.6.0+) and `--strict-collection` (v1.7.0+), neither of which this
    // repo uses. Not enforced strictly — see the module doc comment.
    version_floor: '1.0.0',
    probe: { command: 'zizmor', args: ['--version'] },
    required_by: ['scan_iac'],
    install: {
      // Verified on docs.zizmor.sh/installation (2026-09-25): zizmor is a
      // Rust tool also published to PyPI as prebuilt wheels (pip/pipx/uv)
      // and to crates.io. No scoop/choco/winget manifest was found, so
      // Windows gets the same pipx-via-scoop heuristic semgrep's and
      // bandit's win32 entries already use — a Windows box with scoop
      // almost always has Python, hence pipx, on it too.
      win32: { scoop: pipxInstall('zizmor') },
      linux: { pipx: pipxInstall('zizmor'), uv: uvInstall('zizmor'), cargo: cargoInstall('zizmor') },
      darwin: {
        brew: brewInstall('zizmor'),
        pipx: pipxInstall('zizmor'),
        uv: uvInstall('zizmor'),
        cargo: cargoInstall('zizmor'),
      },
    },
    default: false, // only when .github/workflows exists
  },
  actionlint: {
    name: 'actionlint',
    // 1.6.0: conservative floor a couple of minor releases back from the
    // current 1.7.12 (verified via the GitHub releases API, 2026-09-25);
    // nothing scan_iac.ts uses (`-format`, `-pyflakes=`, `-shellcheck=`)
    // needs a newer one.
    version_floor: '1.6.0',
    probe: { command: 'actionlint', args: ['-version'] },
    required_by: ['scan_iac'],
    install: {
      // Verified against rhysd/actionlint's docs/install.md (2026-09-25):
      // choco/scoop/winget package ids are all literally `actionlint`; the
      // Homebrew formula is official (`brew install actionlint`, no tap);
      // no apt/pacman package, so linux falls back to `go install`, the
      // README's own primary install path.
      win32: { scoop: scoopInstall('actionlint'), choco: chocoInstall('actionlint') },
      linux: { go: goInstall('github.com/rhysd/actionlint/cmd/actionlint@latest') },
      darwin: { brew: brewInstall('actionlint') },
    },
    default: false, // only when .github/workflows exists
  },
  // ---------- DAST ----------
  nuclei: {
    name: 'nuclei',
    version_floor: '3.0.0',
    probe: { command: 'nuclei', args: ['-version'] },
    required_by: ['scan_dast'],
    install: {
      // Scoop's MAIN bucket — the one every scoop install has by default —
      // carries `bucket/nuclei.json` (verified 2026-09-25 through the GitHub
      // API on ScoopInstaller/Main: version 3.11.1, the official
      // `nuclei_<v>_windows_amd64.zip` from projectdiscovery/nuclei's own
      // releases). An earlier check here looked only at the Extras bucket,
      // found nothing, and left win32 empty. No ProjectDiscovery manifest was
      // found in microsoft/winget-pkgs (path lookup and code search, same
      // day), so scoop is the only entry.
      win32: { scoop: scoopInstall('nuclei') },
      linux: {
        // No curl entry: `.../releases/latest` resolves to the release's
        // HTML page, not an install script (measured: Content-Type:
        // text/html on the final 200), and no nuclei archive is pinned
        // here with its sum. Left empty rather than fabricated (see
        // cosignReleaseInstaller's doc comment).
      },
      darwin: { brew: brewInstall('nuclei') },
    },
    default: false,
  },
  // ---------- WordPress ----------
  'wp-cli': {
    name: 'wp-cli',
    version_floor: '2.8.0',
    // The binary is `wp`. `--allow-root` because WP-CLI refuses to run as
    // root without it, which is the normal case inside a container.
    probe: { command: 'wp', args: ['--version', '--allow-root'] },
    required_by: ['wp_audit', 'wp_vuln_check'],
    install: {
      win32: { scoop: scoopInstall('wp-cli'), choco: chocoInstall('wp-cli') },
      linux: { curl: wpCliCurlInstaller() },
      darwin: { brew: brewInstall('wp-cli') },
    },
    default: false,
  },
  wpscan: {
    name: 'wpscan',
    version_floor: '3.8.0',
    probe: { command: 'wpscan', args: ['--version'] },
    required_by: ['wp_vuln_check'],
    install: {
      // wpscan is a Ruby gem. Windows native needs Ruby; we recommend WSL.
      win32: { scoop: scoopInstall('wpscan') },
      linux: { apt: gemInstall('wpscan') },
      darwin: { brew: brewInstall('wpscanteam/tap/wpscan') },
    },
    default: false,
  },
  phpcs: {
    name: 'phpcs',
    version_floor: '3.7.0',
    probe: { command: 'phpcs', args: ['--version'] },
    required_by: ['scan_wordpress'],
    install: {
      win32: { choco: chocoInstall('php-codesniffer') },
      linux: { apt: aptInstall('php-codesniffer') },
      darwin: { brew: brewInstall('php-code-sniffer') },
    },
    default: false,
  },
  // ---------- .NET (SDK never auto-installed) ----------
  'dotnet-sdk': {
    name: 'dotnet-sdk',
    version_floor: '6.0.0',
    probe: { command: 'dotnet', args: ['--list-sdks'], parse: 'dotnet-sdks' },
    required_by: ['scan_sast', 'deps_update_plan'],
    install: {
      // dev-guardian NEVER auto-installs the .NET SDK. These specs only
      // exist so check_toolchain surfaces install hints. The hint names the
      // current LTS: .NET 10 (released 2025-11-11, supported to 2028-11-14 —
      // dotnet.microsoft.com support policy); .NET 6, which it used to name,
      // left support in November 2024. winget id verified in
      // microsoft/winget-pkgs (manifests/m/Microsoft/DotNet/SDK/10).
      win32: { winget: manualHint('winget install Microsoft.DotNet.SDK.10') },
      linux: { apt: manualHint('see https://learn.microsoft.com/dotnet/core/install/linux') },
      darwin: { brew: manualHint('brew install --cask dotnet-sdk') },
    },
    default: false,
  },
  'dotnet-outdated': {
    name: 'dotnet-outdated',
    version_floor: '4.0.0',
    probe: { command: 'dotnet-outdated', args: ['--version'] },
    required_by: ['deps_update_plan'],
    install: {
      win32: { winget: dotnetGlobalTool('dotnet-outdated-tool') },
      linux: { apt: dotnetGlobalTool('dotnet-outdated-tool') },
      darwin: { brew: dotnetGlobalTool('dotnet-outdated-tool') },
    },
    default: false,
  },
  'dotnet-format': {
    name: 'dotnet-format',
    version_floor: '5.0.0',
    // The standalone global tool. Since .NET 6 `dotnet format` ships inside
    // the SDK, and check_toolchain treats an SDK >= 6 as providing it.
    probe: { command: 'dotnet-format', args: ['--version'] },
    required_by: ['quality_check'],
    install: {
      win32: { winget: dotnetGlobalTool('dotnet-format') },
      linux: { apt: dotnetGlobalTool('dotnet-format') },
      darwin: { brew: dotnetGlobalTool('dotnet-format') },
    },
    default: false,
  },
};

// ---------------------------------------------------------------------- spec helpers

function aptInstall(pkg: string): InstallSpec {
  return {
    command: 'sudo',
    args: ['apt-get', 'install', '-y', pkg],
    needs_elevation: true,
    description: `apt-get install ${pkg}`,
  };
}

function brewInstall(pkg: string): InstallSpec {
  return {
    command: 'brew',
    args: ['install', pkg],
    needs_elevation: false,
    description: `brew install ${pkg}`,
  };
}

function pipxInstall(pkg: string): InstallSpec {
  return {
    command: 'pipx',
    args: ['install', pkg],
    needs_elevation: false,
    description: `pipx install ${pkg}`,
  };
}

function scoopInstall(pkg: string): InstallSpec {
  return {
    command: 'scoop',
    args: ['install', pkg],
    needs_elevation: false,
    description: `scoop install ${pkg}`,
  };
}

/** `choco install`, at `version` when given — never "whatever is latest" for a pinned tool. */
function chocoInstall(pkg: string, version?: string): InstallSpec {
  const pinned = version !== undefined ? ['--version', version] : [];
  return {
    command: 'choco',
    args: ['install', '-y', pkg, ...pinned],
    needs_elevation: true,
    description: `choco install -y ${pkg}${version !== undefined ? ` --version ${version}` : ''}`,
  };
}

/** `winget install`, exactly `id` at `version` when given (as cosign's entry). */
function wingetInstall(id: string, version?: string): InstallSpec {
  const pinned = version !== undefined ? ['--exact', '--version', version] : [];
  return {
    command: 'winget',
    args: ['install', '--id', id, ...pinned, '--accept-source-agreements', '--accept-package-agreements'],
    needs_elevation: false,
    description: `winget install ${id}${version !== undefined ? ` --version ${version}` : ''}`,
  };
}

function npmInstallGlobal(pkg: string): InstallSpec {
  return {
    command: 'npm',
    args: ['install', '-g', pkg],
    needs_elevation: true,
    description: `npm install -g ${pkg}`,
  };
}

/**
 * cosign's pinned release binary for this CPU, checked against
 * {@link COSIGN_RELEASE_SHA256} before it is installed to `~/.local/bin`.
 * sigstore/cosign ships no install script — releases are bare binaries — so
 * this is the download itself. A CPU with no pinned checksum is refused
 * rather than guessed, and `set -eu` stops at a failed download or a
 * checksum mismatch, before `install`.
 *
 * No entry pipes a script into `sh`: a script fetched from a branch or a
 * `releases/latest` redirect installs whatever upstream published last, and
 * one pinned by tag still downloads an archive checked only against the
 * same release's own checksums. Where a tool ships no pinned archive with a
 * sum here, its OS bucket stays empty (nuclei, hadolint on Linux) rather
 * than hold a command that has not been checked.
 */
function cosignReleaseInstaller(os: 'linux' | 'darwin'): InstallSpec {
  const url = `https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-${os}-$arch`;
  const check = os === 'linux' ? 'sha256sum -c -' : 'shasum -a 256 -c -';
  const script = [
    'set -eu',
    'case "$(uname -m)" in',
    `  x86_64|amd64) arch=amd64; sum=${COSIGN_RELEASE_SHA256[`${os}-amd64`]} ;;`,
    `  aarch64|arm64) arch=arm64; sum=${COSIGN_RELEASE_SHA256[`${os}-arm64`]} ;;`,
    '  *) echo "cosign: no pinned release binary for this CPU ($(uname -m))" >&2; exit 1 ;;',
    'esac',
    'tmp="$(mktemp)"',
    'trap \'rm -f "$tmp"\' EXIT',
    `curl -sSfL -o "$tmp" "${url}"`,
    `echo "$sum  $tmp" | ${check}`,
    'mkdir -p "$HOME/.local/bin"',
    'install -m 0755 "$tmp" "$HOME/.local/bin/cosign"',
  ].join('\n');
  return {
    command: 'bash',
    args: ['-c', script],
    needs_elevation: false,
    description: `cosign v${COSIGN_VERSION} release binary (${os}, sha256-checked) → ~/.local/bin/cosign`,
    user_bin: 'cosign',
  };
}

/**
 * `tool`'s pinned release archive for this CPU ({@link PINNED_RELEASES}),
 * checked against its sha256 before it is unpacked and its binary installed
 * to `~/.local/bin` — the shape of {@link cosignReleaseInstaller}, for a
 * `.tar.gz`. Each case arm holds an asset and its own sum; a CPU with no
 * pinned archive is refused rather than guessed, and `set -eu` stops at a
 * failed download or a checksum mismatch, before anything is unpacked.
 */
function releaseArchiveInstaller(tool: keyof typeof PINNED_RELEASES, os: 'linux' | 'darwin'): InstallSpec {
  const r = PINNED_RELEASES[tool];
  const amd = r.assets[`${os}-amd64`];
  const arm = r.assets[`${os}-arm64`];
  const check = os === 'linux' ? 'sha256sum -c -' : 'shasum -a 256 -c -';
  const script = [
    'set -eu',
    'case "$(uname -m)" in',
    `  x86_64|amd64) asset=${amd.file}; sum=${amd.sha256} ;;`,
    `  aarch64|arm64) asset=${arm.file}; sum=${arm.sha256} ;;`,
    `  *) echo "${tool}: no pinned release archive for this CPU ($(uname -m))" >&2; exit 1 ;;`,
    'esac',
    'tmp="$(mktemp -d)"',
    'trap \'rm -rf "$tmp"\' EXIT',
    `curl -sSfL -o "$tmp/${tool}.tar.gz" "${r.base}/$asset"`,
    `echo "$sum  $tmp/${tool}.tar.gz" | ${check}`,
    `tar -xzf "$tmp/${tool}.tar.gz" -C "$tmp" ${tool}`,
    'mkdir -p "$HOME/.local/bin"',
    `install -m 0755 "$tmp/${tool}" "$HOME/.local/bin/${tool}"`,
  ].join('\n');
  return {
    command: 'bash',
    args: ['-c', script],
    needs_elevation: false,
    description: `${tool} v${r.version} release archive (${os}, sha256-checked) → ~/.local/bin/${tool}`,
    user_bin: tool,
  };
}

/**
 * The Windows twin of {@link releaseArchiveInstaller}: `tool`'s pinned
 * release ZIP, downloaded with PowerShell (`powershell.exe`, in every
 * supported Windows), checked with `Get-FileHash` before `Expand-Archive` —
 * or, for a release that ships a `.tar.gz` (gosec), before Windows' own
 * `%SystemRoot%\System32\tar.exe` unpacks `<tool>.exe` alone (never a `tar`
 * found on PATH: Git's is another program) — and its `<tool>.exe` copied to `%USERPROFILE%\.local\bin` — the per-user
 * directory the POSIX installers use as `~/.local/bin`. The user's PATH is
 * not changed (a warning says when it lacks the directory): the server
 * appends the directory to its own PATH (`platform/userBin.ts`), so its
 * scans and `check_toolchain` find the tool, and `install_toolchain` names
 * where it went. x64 only; any other CPU is refused. Written with single
 * quotes alone, so the Windows command line has no `"` to re-quote.
 */
function windowsReleaseInstaller(tool: keyof typeof PINNED_RELEASES): InstallSpec {
  const r = PINNED_RELEASES[tool];
  const a = r.assets['windows-amd64'];
  const tarball = a.file.endsWith('.tar.gz');
  const unpack = tarball
    ? [
        "  New-Item -ItemType Directory -Path (Join-Path $tmp 'x') | Out-Null",
        `  & (Join-Path $env:SystemRoot 'System32\\tar.exe') -xzf $zip -C (Join-Path $tmp 'x') ${tool}.exe`,
        `  if ($LASTEXITCODE -ne 0) { throw ('${tool}: tar.exe could not unpack the archive (exit ' + $LASTEXITCODE + ')') }`,
      ]
    : ["  Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $tmp 'x')"];
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    '$arch = $env:PROCESSOR_ARCHITEW6432',
    'if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }',
    `if ($arch -ne 'AMD64') { throw ('${tool}: no pinned release archive for this CPU (' + $arch + ')') }`,
    '[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12',
    '$tmp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())',
    'New-Item -ItemType Directory -Path $tmp | Out-Null',
    'try {',
    `  $zip = Join-Path $tmp '${tool}${tarball ? '.tar.gz' : '.zip'}'`,
    `  Invoke-WebRequest -UseBasicParsing -Uri '${r.base}/${a.file}' -OutFile $zip`,
    '  $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()',
    `  if ($got -ne '${a.sha256}') { throw ('${tool}: sha256 mismatch, got ' + $got) }`,
    ...unpack,
    "  $bin = Join-Path $env:USERPROFILE '.local\\bin'",
    '  New-Item -ItemType Directory -Force -Path $bin | Out-Null',
    `  Copy-Item -LiteralPath (Join-Path $tmp 'x\\${tool}.exe') -Destination (Join-Path $bin '${tool}.exe') -Force`,
    `  if (-not (($env:PATH -split ';') -contains $bin)) { Write-Warning ('${tool}: ' + $bin + ' is not on PATH; dev-guardian looks there itself, but add it to PATH for a terminal to find ${tool}.exe') }`,
    '} finally {',
    '  Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue',
    '}',
  ].join('\n');
  return {
    command: 'powershell',
    args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    needs_elevation: false,
    description: `${tool} v${r.version} release archive (windows, sha256-checked) → %USERPROFILE%\\.local\\bin\\${tool}.exe`,
    user_bin: `${tool}.exe`,
  };
}

function uvInstall(pkg: string): InstallSpec {
  return {
    command: 'uv',
    args: ['tool', 'install', pkg],
    needs_elevation: false,
    description: `uv tool install ${pkg}`,
  };
}

function cargoInstall(pkg: string): InstallSpec {
  return {
    // `--locked` is documented upstream (zizmor's own installation guide) as
    // strongly recommended: an unlocked build can pull different dependency
    // versions than the ones actually tested for that release.
    command: 'cargo',
    args: ['install', '--locked', pkg],
    needs_elevation: false,
    description: `cargo install --locked ${pkg}`,
  };
}

function goInstall(modulePath: string): InstallSpec {
  return {
    command: 'go',
    args: ['install', modulePath],
    needs_elevation: false,
    description: `go install ${modulePath}`,
  };
}

function gemInstall(pkg: string): InstallSpec {
  return {
    command: 'gem',
    args: ['install', pkg],
    needs_elevation: false,
    description: `gem install ${pkg}`,
  };
}

function wpCliCurlInstaller(): InstallSpec {
  // Official one-liner from https://wp-cli.org/.
  return {
    command: 'bash',
    args: [
      '-c',
      'curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && ' +
        'chmod +x wp-cli.phar && mv wp-cli.phar "$HOME/.local/bin/wp"',
    ],
    needs_elevation: false,
    description: 'curl wp-cli.phar → ~/.local/bin/wp',
  };
}

/** The toolchains install_toolchain never installs, and what each is called in its manual step. */
export const MANUAL_ONLY_TOOLS: Readonly<Record<string, string>> = { 'dotnet-sdk': 'the .NET SDK', go: 'the Go toolchain' };

function manualHint(humanCommand: string): InstallSpec {
  // SENTINEL: this spec is NEVER executed by install_toolchain — the tool
  // treats every MANUAL_ONLY_TOOLS entry as read-only. We surface this
  // string via `check_toolchain.install_command` so the user knows how to
  // proceed manually.
  return {
    command: 'echo',
    args: [humanCommand],
    needs_elevation: false,
    description: humanCommand,
  };
}

function dotnetGlobalTool(pkg: string): InstallSpec {
  return {
    command: 'dotnet',
    args: ['tool', 'install', '--global', pkg],
    needs_elevation: false,
    description: `dotnet tool install --global ${pkg}`,
  };
}

// ---------------------------------------------------------------------- selectors

export function listDefaultTools(): string[] {
  return Object.values(TOOL_CATALOG)
    .filter((m) => m.default)
    .map((m) => m.name);
}

export function pickInstallSpec(
  toolName: string,
  os: DetectedOs,
  availableManagers: { name: WindowsPkgManager | PosixPkgManager }[],
): { manager: string; spec: InstallSpec } | null {
  const meta = TOOL_CATALOG[toolName];
  if (!meta) return null;
  const candidates =
    os === 'win32'
      ? meta.install.win32
      : os === 'darwin'
        ? meta.install.darwin
        : os === 'linux'
          ? meta.install.linux
          : null;
  if (!candidates) return null;
  const byName = candidates as Record<string, InstallSpec | undefined>;
  // The tool's own preference first ({@link ToolMeta.prefer}), then the OS's order.
  const preferred: readonly string[] = os === 'darwin' ? (meta.prefer?.darwin ?? []) : os === 'linux' ? (meta.prefer?.linux ?? []) : [];
  const available = new Set<string>(availableManagers.map((m) => m.name));
  for (const name of [...preferred.filter((n) => available.has(n)), ...availableManagers.map((m) => m.name)]) {
    const spec = byName[name];
    if (spec) return { manager: name, spec };
  }
  return null;
}

export function suggestedInstallCommandString(
  toolName: string,
  os: DetectedOs,
): string | null {
  const meta = TOOL_CATALOG[toolName];
  if (!meta) return null;
  const candidates =
    os === 'win32'
      ? meta.install.win32
      : os === 'darwin'
        ? meta.install.darwin
        : os === 'linux'
          ? meta.install.linux
          : null;
  if (!candidates) return null;
  // Surface the first declared option for the OS — most common entry point.
  const first = Object.values(candidates)[0];
  return first?.description ?? null;
}

/**
 * The known-compromised range `version` of `toolName` falls in, or null.
 * An unparseable version is never flagged: "we could not tell" must not read
 * as "compromised" any more than as "safe" — `check_toolchain` reports the
 * version as-is either way.
 */
export function knownCompromise(toolName: string, version: string): CompromisedRange | null {
  for (const range of TOOL_CATALOG[toolName]?.compromised ?? []) {
    const low = compareSemver(version, range.from);
    const high = compareSemver(version, range.to);
    if (low !== null && high !== null && low >= 0 && high <= 0) return range;
  }
  return null;
}
