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
import { compareSemver } from '../platform/semverCompare.js';
import { SEMGREP_NO_VERSION_CHECK_ENV } from './semgrepRun.js';
/**
 * The Trivy release every Trivy install fetches: the pinned archive in
 * {@link PINNED_RELEASES} on Linux, macOS (after Homebrew) and Windows, and
 * the version winget, scoop and choco are asked for. Pinned because the
 * installer used to be piped from the `main` branch into `sh` and then
 * install "latest": on 2026-03-19 "latest" WAS the malicious v0.69.4 (see
 * `compromised` on the trivy entry). v0.74.0 was published 2026-08-14 as an
 * immutable release (enabled on aquasecurity/trivy since 2026-03-03). Bump it
 * and its sums together, deliberately.
 */
export const TRIVY_INSTALL_TAG = 'v0.74.0';
/**
 * The cosign release every pinned installer below fetches (winget, scoop and
 * the release-binary download). v3.1.3 was published 2026-08-06; bump it and
 * {@link COSIGN_RELEASE_SHA256} together, deliberately.
 */
export const COSIGN_VERSION = '3.1.3';
/**
 * sha256 of each POSIX release binary of {@link COSIGN_VERSION}. Each value
 * was checked three ways on 2026-09-28 and all three agreed: the binary
 * downloaded and hashed independently (`curl … | sha256sum`), the release's
 * own `cosign_checksums.txt`, and the digest GitHub records for the release
 * asset. The Windows binary is not listed: winget and scoop verify it against
 * their own manifests, which carry the same hash
 * (9fe59be0…33be, checked against both manifests the same day).
 */
export const COSIGN_RELEASE_SHA256 = {
    'linux-amd64': '4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71',
    'linux-arm64': 'c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a',
    'darwin-amd64': '2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c',
    'darwin-arm64': '5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76',
};
const SYFT_VERSION = '1.52.0';
const TRIVY_VERSION = TRIVY_INSTALL_TAG.slice(1);
const GITLEAKS_VERSION = '8.30.1';
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
 * gitleaks). Syft 1.52.0 (2026-09-17) and Trivy 0.74.0 (2026-08-14) are
 * immutable releases; gitleaks 8.30.1 (2026-03-21) is not — its assets could
 * be replaced, which the pinned sums catch.
 */
export const PINNED_RELEASES = {
    syft: {
        version: SYFT_VERSION,
        base: `https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}`,
        assets: {
            'linux-amd64': { file: `syft_${SYFT_VERSION}_linux_amd64.tar.gz`, sha256: 'caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d' },
            'linux-arm64': { file: `syft_${SYFT_VERSION}_linux_arm64.tar.gz`, sha256: 'c46d5e4c28e12aa4c5becfaa343ef1c7f89045b6b895f2c21d471c62db09c706' },
            'darwin-amd64': { file: `syft_${SYFT_VERSION}_darwin_amd64.tar.gz`, sha256: '56975f5d7ffa9846a1eaf64330647841b878097bc7e3730cb9325f93add96917' },
            'darwin-arm64': { file: `syft_${SYFT_VERSION}_darwin_arm64.tar.gz`, sha256: '014d561b6d13059124155f74a6c5a9a99501f5e209313638dd884f39eb418ee6' },
            'windows-amd64': { file: `syft_${SYFT_VERSION}_windows_amd64.zip`, sha256: 'de787a374cf961c56fd7b206b2e183295abba32d0af3cb44d9aef2357ca9eda2' },
        },
    },
    trivy: {
        version: TRIVY_VERSION,
        base: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}`,
        assets: {
            'linux-amd64': { file: `trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz`, sha256: '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a' },
            'linux-arm64': { file: `trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz`, sha256: 'b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5' },
            'darwin-amd64': { file: `trivy_${TRIVY_VERSION}_macOS-64bit.tar.gz`, sha256: '472816f6888dda689d075c30254d4210b4d1035acf365aa72332f584c2f60485' },
            'darwin-arm64': { file: `trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz`, sha256: '1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11' },
            'windows-amd64': { file: `trivy_${TRIVY_VERSION}_windows-64bit.zip`, sha256: '94c40e0696e4b907a74b7b2e1438d5d72ebaca83115817407f568a002d520842' },
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
};
export const TOOL_CATALOG = {
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
                action: 'Remove this Trivy build now, install a release the advisory lists as safe (or a later one), ' +
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
            darwin: { brew: brewInstall('aquasecurity/trivy/trivy'), curl: releaseArchiveInstaller('trivy', 'darwin') },
        },
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
            // Verified 2026-09-28: microsoft/winget-pkgs carries Sigstore.Cosign
            // 3.1.3 and ScoopInstaller/Main carries cosign 3.1.3, both pointing
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
function aptInstall(pkg) {
    return {
        command: 'sudo',
        args: ['apt-get', 'install', '-y', pkg],
        needs_elevation: true,
        description: `apt-get install ${pkg}`,
    };
}
function brewInstall(pkg) {
    return {
        command: 'brew',
        args: ['install', pkg],
        needs_elevation: false,
        description: `brew install ${pkg}`,
    };
}
function pipxInstall(pkg) {
    return {
        command: 'pipx',
        args: ['install', pkg],
        needs_elevation: false,
        description: `pipx install ${pkg}`,
    };
}
function scoopInstall(pkg) {
    return {
        command: 'scoop',
        args: ['install', pkg],
        needs_elevation: false,
        description: `scoop install ${pkg}`,
    };
}
/** `choco install`, at `version` when given — never "whatever is latest" for a pinned tool. */
function chocoInstall(pkg, version) {
    const pinned = version !== undefined ? ['--version', version] : [];
    return {
        command: 'choco',
        args: ['install', '-y', pkg, ...pinned],
        needs_elevation: true,
        description: `choco install -y ${pkg}${version !== undefined ? ` --version ${version}` : ''}`,
    };
}
/** `winget install`, exactly `id` at `version` when given (as cosign's entry). */
function wingetInstall(id, version) {
    const pinned = version !== undefined ? ['--exact', '--version', version] : [];
    return {
        command: 'winget',
        args: ['install', '--id', id, ...pinned, '--accept-source-agreements', '--accept-package-agreements'],
        needs_elevation: false,
        description: `winget install ${id}${version !== undefined ? ` --version ${version}` : ''}`,
    };
}
function npmInstallGlobal(pkg) {
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
function cosignReleaseInstaller(os) {
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
function releaseArchiveInstaller(tool, os) {
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
    };
}
/**
 * The Windows twin of {@link releaseArchiveInstaller}: `tool`'s pinned
 * release ZIP, downloaded with PowerShell (`powershell.exe`, in every
 * supported Windows), checked with `Get-FileHash` before `Expand-Archive`,
 * and its `<tool>.exe` copied to `%USERPROFILE%\.local\bin` — the per-user
 * directory the POSIX installers use as `~/.local/bin`. It is not added to
 * PATH (a warning says so when it is missing): `check_toolchain` finds the
 * tool once it is. x64 only; any other CPU is refused. Written with single
 * quotes alone, so the Windows command line has no `"` to re-quote.
 */
function windowsReleaseInstaller(tool) {
    const r = PINNED_RELEASES[tool];
    const a = r.assets['windows-amd64'];
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
        `  $zip = Join-Path $tmp '${tool}.zip'`,
        `  Invoke-WebRequest -UseBasicParsing -Uri '${r.base}/${a.file}' -OutFile $zip`,
        '  $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()',
        `  if ($got -ne '${a.sha256}') { throw ('${tool}: sha256 mismatch, got ' + $got) }`,
        "  Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $tmp 'x')",
        "  $bin = Join-Path $env:USERPROFILE '.local\\bin'",
        '  New-Item -ItemType Directory -Force -Path $bin | Out-Null',
        `  Copy-Item -LiteralPath (Join-Path $tmp 'x\\${tool}.exe') -Destination (Join-Path $bin '${tool}.exe') -Force`,
        `  if (-not (($env:PATH -split ';') -contains $bin)) { Write-Warning ('${tool}: ' + $bin + ' is not on PATH; add it there for dev-guardian to find ${tool}.exe') }`,
        '} finally {',
        '  Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue',
        '}',
    ].join('\n');
    return {
        command: 'powershell',
        args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
        needs_elevation: false,
        description: `${tool} v${r.version} release archive (windows, sha256-checked) → %USERPROFILE%\\.local\\bin\\${tool}.exe`,
    };
}
function uvInstall(pkg) {
    return {
        command: 'uv',
        args: ['tool', 'install', pkg],
        needs_elevation: false,
        description: `uv tool install ${pkg}`,
    };
}
function cargoInstall(pkg) {
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
function goInstall(modulePath) {
    return {
        command: 'go',
        args: ['install', modulePath],
        needs_elevation: false,
        description: `go install ${modulePath}`,
    };
}
function gemInstall(pkg) {
    return {
        command: 'gem',
        args: ['install', pkg],
        needs_elevation: false,
        description: `gem install ${pkg}`,
    };
}
function wpCliCurlInstaller() {
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
function dotnetSdkHint(humanCommand) {
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
function dotnetGlobalTool(pkg) {
    return {
        command: 'dotnet',
        args: ['tool', 'install', '--global', pkg],
        needs_elevation: false,
        description: `dotnet tool install --global ${pkg}`,
    };
}
// ---------------------------------------------------------------------- selectors
export function listDefaultTools() {
    return Object.values(TOOL_CATALOG)
        .filter((m) => m.default)
        .map((m) => m.name);
}
export function pickInstallSpec(toolName, os, availableManagers) {
    const meta = TOOL_CATALOG[toolName];
    if (!meta)
        return null;
    const candidates = os === 'win32'
        ? meta.install.win32
        : os === 'darwin'
            ? meta.install.darwin
            : os === 'linux'
                ? meta.install.linux
                : null;
    if (!candidates)
        return null;
    for (const { name } of availableManagers) {
        const spec = candidates[name];
        if (spec)
            return { manager: name, spec };
    }
    return null;
}
export function suggestedInstallCommandString(toolName, os) {
    const meta = TOOL_CATALOG[toolName];
    if (!meta)
        return null;
    const candidates = os === 'win32'
        ? meta.install.win32
        : os === 'darwin'
            ? meta.install.darwin
            : os === 'linux'
                ? meta.install.linux
                : null;
    if (!candidates)
        return null;
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
export function knownCompromise(toolName, version) {
    for (const range of TOOL_CATALOG[toolName]?.compromised ?? []) {
        const low = compareSemver(version, range.from);
        const high = compareSemver(version, range.to);
        if (low !== null && high !== null && low >= 0 && high <= 0)
            return range;
    }
    return null;
}
//# sourceMappingURL=installCatalog.js.map