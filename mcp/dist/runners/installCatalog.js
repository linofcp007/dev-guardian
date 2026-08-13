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
export const TOOL_CATALOG = {
    semgrep: {
        name: 'semgrep',
        version_floor: '1.0.0',
        required_by: ['scan_sast', 'security_scan_full', 'bug_hunt', 'review_pr'],
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
                curl: curlInstaller('https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh'),
            },
            darwin: { brew: brewInstall('aquasecurity/trivy/trivy') },
        },
        default: true,
    },
    gitleaks: {
        name: 'gitleaks',
        version_floor: '8.0.0',
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
            // the same way nuclei's win32 entry below already does.
            },
            darwin: { brew: brewInstall('gitleaks') },
        },
        default: true,
    },
    syft: {
        name: 'syft',
        version_floor: '0.80.0',
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
        required_by: ['scan_sast', 'security_scan_full'],
        install: {
            win32: { scoop: pipxInstall('bandit') },
            linux: { pipx: pipxInstall('bandit') },
            darwin: { brew: brewInstall('bandit'), pipx: pipxInstall('bandit') },
        },
        default: false, // only when Python detected
    },
    jscpd: {
        name: 'jscpd',
        version_floor: '3.0.0',
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
    // ---------- DAST ----------
    nuclei: {
        name: 'nuclei',
        version_floor: '3.0.0',
        required_by: ['scan_dast'],
        install: {
            // No verified scoop/choco/winget package exists for nuclei: it is not
            // among ProjectDiscovery's own documented install methods (go install,
            // brew, docker, GitHub release binaries, Helm — checked against
            // docs.projectdiscovery.io/opensource/nuclei/install), the
            // ScoopInstaller/Extras bucket has no `nuclei.json` manifest, and
            // winget's community repo returns zero results for it. Every other
            // entry in this catalogue is a real, working command; pointing win32
            // at a package manager that does not carry the tool would be exactly
            // the kind of fabrication this project's whole DAST feature exists to
            // avoid, so it is left empty rather than guessed at. `check_toolchain`
            // / `install_toolchain` already degrade gracefully to "no known
            // install command" when an OS bucket has none.
            win32: {},
            linux: {
            // No curl entry, for the same reason as gitleaks' linux entry
            // above and this tool's own win32 bucket: `.../releases/latest`
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
        required_by: ['scan_sast', 'deps_update_plan'],
        install: {
            // dev-guardian NEVER auto-installs the .NET SDK. These specs only
            // exist so check_toolchain surfaces install hints.
            win32: { winget: dotnetSdkHint('winget install Microsoft.DotNet.SDK.6') },
            linux: { apt: dotnetSdkHint('see https://learn.microsoft.com/dotnet/core/install/linux') },
            darwin: { brew: dotnetSdkHint('brew install --cask dotnet-sdk') },
        },
        default: false,
    },
    'dotnet-outdated': {
        name: 'dotnet-outdated',
        version_floor: '4.0.0',
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
function chocoInstall(pkg) {
    return {
        command: 'choco',
        args: ['install', '-y', pkg],
        needs_elevation: true,
        description: `choco install -y ${pkg}`,
    };
}
function wingetInstall(id) {
    return {
        command: 'winget',
        args: ['install', '--id', id, '--accept-source-agreements', '--accept-package-agreements'],
        needs_elevation: false,
        description: `winget install ${id}`,
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
 * bucket empty (as nuclei's win32 already does) rather than call this
 * helper on a URL that has not been checked.
 */
function curlInstaller(url) {
    return {
        command: 'bash',
        args: ['-c', `curl -sSfL ${url} | sh -s -- -b "$HOME/.local/bin"`],
        needs_elevation: false,
        description: `curl ${url} | sh`,
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
//# sourceMappingURL=installCatalog.js.map