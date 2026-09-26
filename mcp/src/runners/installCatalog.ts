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
import type { VersionProbe } from './toolProbe.js';

export type WindowsPkgManager = 'winget' | 'scoop' | 'choco' | 'wsl';
export type PosixPkgManager = 'apt' | 'brew' | 'pipx' | 'npm' | 'curl' | 'uv' | 'cargo' | 'go';

export interface InstallSpec {
  /** Shell command (as a tokenised argv) to install. */
  command: string;
  args: string[];
  /** True when the spec needs admin/sudo (winget on per-machine, apt, brew formula-cask). */
  needs_elevation: boolean;
  /** Optional, human-readable. Shown when `install_toolchain` returns dry-run results. */
  description?: string;
}

/**
 * A range of releases known to be malicious — a supply-chain compromise, not
 * a vulnerability. Inclusive bounds; checked against the installed version by
 * `check_toolchain`. Every entry must cite its primary-source advisory.
 */
export interface CompromisedRange {
  from: string;
  to: string;
  advisory: string;
  cve?: string;
  url: string;
  action: string;
}

export interface ToolMeta {
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
  /** Whether this tool is part of the default install profile. */
  default: boolean;
}

/**
 * The Trivy release the curl installer fetches AND installs. Pinned because
 * the installer used to be piped from the `main` branch into `sh` and then
 * install "latest": on 2026-03-19 "latest" WAS the malicious v0.69.4 (see
 * `compromised` on the trivy entry). A tag's `install.sh` is immutable
 * (GitHub immutable releases, enabled on aquasecurity/trivy since
 * 2026-03-03); v0.74.0 was published 2026-08-14. Bump deliberately.
 */
export const TRIVY_INSTALL_TAG = 'v0.74.0';

export const TOOL_CATALOG: Record<string, ToolMeta> = {
  semgrep: {
    name: 'semgrep',
    version_floor: '1.0.0',
    probe: { command: 'semgrep', args: ['--version'] },
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
      win32: {
        scoop: scoopInstall('trivy'),
        choco: chocoInstall('trivy'),
        winget: wingetInstall('AquaSecurity.Trivy'),
      },
      linux: {
        apt: aptInstall('trivy'),
        curl: curlInstaller(
          `https://raw.githubusercontent.com/aquasecurity/trivy/${TRIVY_INSTALL_TAG}/contrib/install.sh`,
          TRIVY_INSTALL_TAG,
        ),
      },
      darwin: { brew: brewInstall('aquasecurity/trivy/trivy') },
    },
    default: true,
  },
  gitleaks: {
    name: 'gitleaks',
    version_floor: '8.0.0',
    probe: { command: 'gitleaks', args: ['version'] },
    required_by: ['scan_secrets', 'security_scan_full', 'review_pr'],
    install: {
      win32: {
        scoop: scoopInstall('gitleaks'),
        choco: chocoInstall('gitleaks'),
        winget: wingetInstall('gitleaks.gitleaks'),
      },
      linux: {
        // No curl entry: `.../releases/latest` resolves to the release's
        // HTML page, not an install script (measured: Content-Type:
        // text/html on the final 200 — see curlInstaller's doc comment).
        // gitleaks ships per-arch release archives, not a stable
        // install.sh, so there is no safe URL to hand curlInstaller here.
        // The default bootstrap flow is unaffected — it delegates to
        // install-linux.sh, which resolves the real download URL itself;
        // only an explicit install_toolchain(tools:["gitleaks"]) call on
        // Linux reaches this empty bucket, and degrades to manual_steps
        // the same way nuclei's linux entry below does.
      },
      darwin: { brew: brewInstall('gitleaks') },
    },
    default: true,
  },
  syft: {
    name: 'syft',
    version_floor: '0.80.0',
    probe: { command: 'syft', args: ['version'] },
    required_by: ['generate_sbom'],
    install: {
      win32: { scoop: scoopInstall('syft'), choco: chocoInstall('syft') },
      linux: {
        curl: curlInstaller('https://raw.githubusercontent.com/anchore/syft/main/install.sh'),
      },
      darwin: { brew: brewInstall('syft') },
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
      // its repo tree) — releases are prebuilt binaries only, so per
      // curlInstaller's own doc comment this is left unfabricated.
      win32: {
        scoop: scoopInstall('hadolint'),
        winget: wingetInstall('hadolint.hadolint'),
      },
      linux: {},
      darwin: { brew: brewInstall('hadolint') },
    },
    default: false, // only when a Dockerfile is present
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
        // No curl entry, for the same reason as gitleaks' linux entry
        // above: `.../releases/latest`
        // resolves to the release's HTML page, not an install script
        // (measured: Content-Type: text/html on the final 200). Left
        // empty rather than fabricated, per curlInstaller's doc comment.
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
      win32: { winget: dotnetSdkHint('winget install Microsoft.DotNet.SDK.10') },
      linux: { apt: dotnetSdkHint('see https://learn.microsoft.com/dotnet/core/install/linux') },
      darwin: { brew: dotnetSdkHint('brew install --cask dotnet-sdk') },
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

function chocoInstall(pkg: string): InstallSpec {
  return {
    command: 'choco',
    args: ['install', '-y', pkg],
    needs_elevation: true,
    description: `choco install -y ${pkg}`,
  };
}

function wingetInstall(id: string): InstallSpec {
  return {
    command: 'winget',
    args: ['install', '--id', id, '--accept-source-agreements', '--accept-package-agreements'],
    needs_elevation: false,
    description: `winget install ${id}`,
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
 * Single-shot install script — invocation is `bash -c "curl … | sh"`.
 *
 * PRECONDITION: `url` must resolve to a raw shell script (trivy's and
 * syft's `contrib/install.sh` / `install.sh` on raw.githubusercontent.com
 * are the real examples in this file), never a GitHub *page* — in
 * particular never a bare `.../releases/latest`. That URL 302s to the
 * release's HTML tag page, which `-f` accepts (it only fails on HTTP
 * error status) and `sh` cannot execute: the caller gets a wall of shell
 * syntax errors, not an install and not a usable instruction. Measured
 * directly with `curl -sSIL` rather than assumed — gitleaks' and
 * nuclei's linux entries both once took this shape and both came back
 * `Content-Type: text/html` on the final 200; see the comments on those
 * catalog entries. A broken command is worse than none: leave the OS
 * bucket empty (as nuclei's and gitleaks' linux entries do) rather than call
 * this helper on a URL that has not been checked.
 *
 * `tag`, when given, is passed to the script as the release to install —
 * godownloader-style scripts (trivy's, syft's) otherwise install "latest"
 * at the moment they run, so pinning the script's URL alone pins nothing.
 */
function curlInstaller(url: string, tag?: string): InstallSpec {
  const pinned = tag !== undefined ? ` ${tag}` : '';
  return {
    command: 'bash',
    args: ['-c', `curl -sSfL ${url} | sh -s -- -b "$HOME/.local/bin"${pinned}`],
    needs_elevation: false,
    description: `curl ${url} | sh${pinned}`,
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

function dotnetSdkHint(humanCommand: string): InstallSpec {
  // SENTINEL: this spec is NEVER executed by install_toolchain — the tool
  // checks meta.name and treats `dotnet-sdk` as read-only. We surface this
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
  for (const { name } of availableManagers) {
    const spec = (candidates as Record<string, InstallSpec | undefined>)[name];
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
