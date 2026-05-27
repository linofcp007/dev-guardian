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

export type WindowsPkgManager = 'winget' | 'scoop' | 'choco' | 'wsl';
export type PosixPkgManager = 'apt' | 'brew' | 'pipx' | 'npm' | 'curl';

export interface InstallSpec {
  /** Shell command (as a tokenised argv) to install. */
  command: string;
  args: string[];
  /** True when the spec needs admin/sudo (winget on per-machine, apt, brew formula-cask). */
  needs_elevation: boolean;
  /** Optional, human-readable. Shown when `install_toolchain` returns dry-run results. */
  description?: string;
}

export interface ToolMeta {
  name: string;
  version_floor: string;
  required_by: string[];
  install: {
    win32: Partial<Record<WindowsPkgManager, InstallSpec>>;
    linux: Partial<Record<PosixPkgManager, InstallSpec>>;
    darwin: Partial<Record<PosixPkgManager, InstallSpec>>;
  };
  /** Whether this tool is part of the default install profile. */
  default: boolean;
}

export const TOOL_CATALOG: Record<string, ToolMeta> = {
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
        curl: curlInstaller(
          'https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh',
        ),
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
        curl: curlInstaller('https://github.com/gitleaks/gitleaks/releases/latest'),
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
    default: false, // opt-in
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

function curlInstaller(url: string): InstallSpec {
  // Single-shot install script — invocation is `bash -c "curl … | sh"`.
  return {
    command: 'bash',
    args: ['-c', `curl -sSfL ${url} | sh -s -- -b "$HOME/.local/bin"`],
    needs_elevation: false,
    description: `curl ${url} | sh`,
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
