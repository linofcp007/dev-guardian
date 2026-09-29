/**
 * `install_toolchain` — install missing scanners.
 *
 * Two flow modes:
 *
 *   1. Default install (no `tools` argument)
 *      - Linux/macOS → delegate to `scripts/install/install-{linux,macos}.sh`.
 *        The scripts are mature, idempotent, and already handle apt/dnf/pacman,
 *        ~/.local/bin fallback, pipx, etc.
 *      - Windows    → walk the catalogue's default set, picking the first
 *        reachable installer (the pinned release ZIP through PowerShell,
 *        where the catalogue has one → winget → scoop → choco, those three
 *        at the pinned version where it names one). If no package manager
 *        is present AND WSL is, delegate to
 *        `wsl bash scripts/install/install-linux.sh`. Otherwise return
 *        `manual_steps` with the suggested commands.
 *
 *   2. Per-tool install (`tools=[...]`)
 *      - Look each one up in TOOL_CATALOG.
 *      - For each, pick the highest-priority available manager for the OS
 *        and run its install spec via `runProcess`.
 *      - `dry_run` prints the commands without executing.
 *      - `elevation_allowed` gates specs that need admin/sudo.
 *
 * After any mode, the tool re-runs `check_toolchain` and embeds the result
 * as `verification`.
 */

import { join } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { detectOs, type DetectedOs } from '../platform/osDetect.js';
import {
  firstWindowsAvailable,
  resolveBinary,
  type PkgManagerCandidate,
} from '../platform/pkgManagerDetect.js';
import { WSL_SHELL } from '../platform/shellProbe.js';
import { ensureUserBinOnPath, userBinPlacement } from '../platform/userBin.js';
import { runProcess } from '../runners/processRunner.js';
import { runShellScript } from '../runners/shellRunner.js';
import {
  TOOL_CATALOG,
  listDefaultTools,
  pickInstallSpec,
  type InstallSpec,
} from '../runners/installCatalog.js';
import type { ToolResult } from '../types.js';
import { registerToolModule, TOOLS, type ToolModule } from './index.js';
import { resetScannerCache } from './scanHelpers.js';

const inputSchema = {
  tools: z
    .array(z.string())
    .optional()
    .describe(
      'When set, install only these scanners (must exist in the catalogue). When omitted, install ' +
        'the default set: semgrep, trivy, gitleaks, syft, pre-commit (+ ruff/bandit/jscpd if stack ' +
        'detected).',
    ),
  dry_run: z
    .boolean()
    .optional()
    .describe('Print commands without executing. Default: false.'),
  elevation_allowed: z
    .boolean()
    .optional()
    .describe(
      'Set true to allow install steps that require sudo/admin (apt, choco, npm install -g). ' +
        'Default: false — steps needing elevation are reported under `requires_elevation` instead. ' +
        'Install steps run without a terminal, so on Linux/macOS this only works with passwordless ' +
        'sudo; "sudo: a terminal is required to read the password" means the user must run the ' +
        'reported command themselves.',
    ),
};

interface InstallEntry {
  tool: string;
  manager?: string;
  command?: string;
  needs_elevation?: boolean;
  /** Where the binary went (or, in a dry run, would go), for an installer that writes into the per-user tools directory. */
  binary_path?: string;
  /** Present when that directory is not on the user's own PATH: the server finds the tool there, a terminal will not. */
  path_note?: string;
}

interface InstallResult {
  installed: InstallEntry[];
  already_present: InstallEntry[];
  skipped: Array<InstallEntry & { reason: string }>;
  failed: Array<InstallEntry & { error: string }>;
  requires_elevation: Array<InstallEntry & { hint: string }>;
  would_install: InstallEntry[];
  manual_steps: Array<{ tool: string; instructions: string }>;
}

const tool: ToolModule = {
  name: 'install_toolchain',
  title: 'Install missing toolchain',
  description:
    'Install missing scanners. Defaults to the standard set; pass `tools=[...]` to limit. ' +
    'Linux/macOS delegate to scripts/install/install-{linux,macos}.sh. Windows uses winget/scoop/' +
    'choco/WSL. Syft, Trivy and gitleaks are a pinned release checked against its sha256 (on Windows ' +
    'a ZIP fetched with PowerShell), or a package manager asked for that same version — never ' +
    '"latest" — except on macOS, where Syft and gitleaks come from Homebrew first (Trivy: the pinned ' +
    'archive first, then homebrew-core). A pinned release goes to ~/.local/bin (%USERPROFILE%\\.local\\bin), ' +
    'which the server searches itself; the result names where each binary went (binary_path) and says ' +
    'when a terminal will not find it (path_note). dry_run prints commands without executing.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    tools?: string[];
    dry_run?: boolean;
    elevation_allowed?: boolean;
  };
  const dryRun = inp.dry_run === true;
  const elevation = inp.elevation_allowed === true;
  const os = detectOs();

  if (os === 'unsupported') {
    return {
      ok: false,
      error: {
        code: 'unsupported_os',
        message: `Unsupported platform: ${process.platform}. install_toolchain only supports linux, darwin, win32.`,
      },
    };
  }

  const result: InstallResult = {
    installed: [],
    already_present: [],
    skipped: [],
    failed: [],
    requires_elevation: [],
    would_install: [],
    manual_steps: [],
  };

  if (inp.tools && inp.tools.length > 0) {
    await installPerTool({
      tools: inp.tools,
      os,
      dryRun,
      elevation,
      ctx,
      result,
    });
  } else {
    await installDefaults({ os, dryRun, elevation, ctx, result });
  }

  // Whatever was installed must be visible to the very next scan: without
  // this, a cached "not installed" from before the install outlived it and
  // the re-scan still reported `not_installed`. The per-user tools directory
  // may only now exist: it joins this server's PATH (platform/userBin.ts).
  ensureUserBinOnPath();
  resetScannerCache();
  const verification = await runCheckToolchain(ctx);

  return {
    ok: true,
    os,
    applied: !dryRun,
    ...result,
    verification: verification as unknown as Record<string, unknown>,
  };
}

// ---------------------------------------------------------------------- defaults

interface DefaultsContext {
  os: DetectedOs;
  dryRun: boolean;
  elevation: boolean;
  ctx: PluginContext;
  result: InstallResult;
}

async function installDefaults(opts: DefaultsContext): Promise<void> {
  if (opts.os === 'linux' || opts.os === 'darwin') {
    await runPosixInstaller(opts);
    return;
  }
  // Windows: prefer native pkg manager. If none, try WSL fallback. If
  // neither, populate manual_steps.
  //
  // WSL needs two things: the `wsl` binary AND at least one installed
  // distro. `wsl -l --quiet` lists installed distros — empty stdout means
  // wsl is installed but no distro exists, in which case `wsl bash …`
  // would fail. We treat that as "WSL not usable".
  const winner = await firstWindowsAvailable();
  const wslReachable = await isWslUsable();

  if (!winner && !wslReachable) {
    opts.result.manual_steps.push(
      ...listDefaultTools().map((t) => ({
        tool: t,
        instructions: `Install ${t} manually — see TOOL_CATALOG for command suggestions.`,
      })),
    );
    return;
  }

  if (winner) {
    await installPerTool({
      tools: listDefaultTools(),
      os: 'win32',
      dryRun: opts.dryRun,
      elevation: opts.elevation,
      ctx: opts.ctx,
      result: opts.result,
    });
    return;
  }

  // WSL fallback
  if (opts.dryRun) {
    opts.result.would_install.push({
      tool: 'all-default',
      command: 'wsl bash scripts/install/install-linux.sh',
    });
    return;
  }
  // Through the shell runner with the WSL shell, so the script path is
  // translated to its /mnt/<drive>/ form — a raw `C:\…` path handed to
  // `wsl bash` names nothing inside WSL.
  const scriptPath = join(opts.ctx.scriptsDir, 'install', 'install-linux.sh');
  const r = await runShellScript({
    shell: WSL_SHELL,
    scriptPath,
    args: ['--no-sudo'],
    cwd: opts.ctx.scriptsDir,
  });
  for (const t of listDefaultTools()) {
    if (r.outcome === 'completed') {
      opts.result.installed.push({ tool: t, manager: 'wsl' });
    } else {
      opts.result.failed.push({
        tool: t,
        manager: 'wsl',
        error: r.stderr.split(/\r?\n/)[0] ?? 'wsl install-linux.sh failed',
      });
    }
  }
}

async function runPosixInstaller(opts: DefaultsContext): Promise<void> {
  if (opts.ctx.shell === null) {
    opts.result.skipped.push({
      tool: 'all-default',
      reason: 'no_bash_shell',
    });
    return;
  }
  const scriptName = opts.os === 'darwin' ? 'install-macos.sh' : 'install-linux.sh';
  const scriptPath = join(opts.ctx.scriptsDir, 'install', scriptName);
  const extraArgs = opts.elevation ? [] : ['--no-sudo'];

  if (opts.dryRun) {
    opts.result.would_install.push({
      tool: 'all-default',
      command: `bash ${scriptPath} ${extraArgs.join(' ')}`.trim(),
    });
    return;
  }

  const r = await runShellScript({
    shell: opts.ctx.shell,
    scriptPath,
    args: extraArgs,
    cwd: opts.ctx.scriptsDir,
  });
  // We can't tell from the script which individual tools succeeded — model
  // them all as "best effort" then let `verification` (re-run of
  // check_toolchain) show the truth.
  for (const t of listDefaultTools()) {
    if (r.outcome === 'completed') {
      opts.result.installed.push({ tool: t, manager: 'bundled-script' });
    } else {
      opts.result.failed.push({
        tool: t,
        manager: 'bundled-script',
        error: r.stderr.split(/\r?\n/)[0] ?? `script exited ${r.outcome}`,
      });
    }
  }
}

// ---------------------------------------------------------------------- per-tool

interface PerToolContext {
  tools: string[];
  os: DetectedOs;
  dryRun: boolean;
  elevation: boolean;
  ctx: PluginContext;
  result: InstallResult;
}

async function installPerTool(opts: PerToolContext): Promise<void> {
  const availableManagers = await listAvailableManagers(opts.os);

  for (const toolName of opts.tools) {
    const meta = TOOL_CATALOG[toolName];
    if (!meta) {
      opts.result.skipped.push({
        tool: toolName,
        reason: 'not_in_catalog',
      });
      continue;
    }
    // Hard rule: never auto-install the .NET SDK. We always route it to
    // manual_steps with the OS-appropriate hint from the catalogue.
    if (toolName === 'dotnet-sdk' && opts.os !== 'unsupported') {
      const specs = TOOL_CATALOG['dotnet-sdk']?.install[opts.os];
      const first = specs ? (Object.values(specs)[0] as { description?: string } | undefined) : undefined;
      const hint = first?.description ?? 'See https://learn.microsoft.com/dotnet/core/install/';
      opts.result.manual_steps.push({
        tool: toolName,
        instructions: `dev-guardian never auto-installs the .NET SDK. ${hint}`,
      });
      continue;
    }
    const picked = pickInstallSpec(
      toolName,
      opts.os,
      // narrow PkgManagerCandidate.name (string) to the catalogue's enum.
      availableManagers
        .filter((c) => c.available)
        .map((c) => ({
          name: c.name as Parameters<typeof pickInstallSpec>[2][number]['name'],
        })),
    );
    if (!picked) {
      opts.result.manual_steps.push({
        tool: toolName,
        instructions: `No available installer for ${toolName} on ${opts.os}. Install manually.`,
      });
      continue;
    }

    const entry: InstallEntry = {
      tool: toolName,
      manager: picked.manager,
      command: describeSpec(picked.spec),
      needs_elevation: picked.spec.needs_elevation,
    };
    // A pinned release into ~/.local/bin (%USERPROFILE%\.local\bin): say where,
    // and whether a terminal will find it (platform/userBin.ts).
    const placement = picked.spec.user_bin !== undefined ? userBinPlacement(picked.spec.user_bin) : null;

    if (picked.spec.needs_elevation && !opts.elevation) {
      opts.result.requires_elevation.push({
        ...entry,
        hint: elevationHint(opts.os, `${picked.spec.command} ${picked.spec.args.join(' ')}`),
      });
      continue;
    }

    if (opts.dryRun) {
      opts.result.would_install.push({ ...entry, ...placement });
      continue;
    }

    const r = await runProcess({
      command: picked.spec.command,
      args: picked.spec.args,
      cwd: opts.ctx.scriptsDir,
    });
    if (r.outcome === 'completed') {
      opts.result.installed.push({ ...entry, ...placement });
    } else {
      opts.result.failed.push({
        ...entry,
        error: (r.stderr.split(/\r?\n/)[0] ?? r.outcome).slice(0, 500),
      });
    }
  }
}

/**
 * What to do about a step that needs elevation. "Re-call with
 * elevation_allowed=true" alone was wrong more often than right: install
 * steps run without a terminal, so `sudo` can only succeed without a
 * password, and `choco` only from a server that is already elevated —
 * otherwise the user has to run the command themselves.
 */
export function elevationHint(os: DetectedOs, command: string): string {
  if (os === 'win32') {
    return (
      'Needs an administrator shell. Re-calling with elevation_allowed=true only works when this ' +
      `server itself runs elevated; otherwise run \`${command}\` yourself in an administrator terminal.`
    );
  }
  return (
    'Needs elevation. Re-calling with elevation_allowed=true only works with passwordless sudo ' +
    `(install steps run without a terminal to type a password in); otherwise run \`${command}\` ` +
    'yourself in a terminal.'
  );
}

function describeSpec(spec: InstallSpec): string {
  return spec.description ?? `${spec.command} ${spec.args.join(' ')}`;
}

/**
 * Every probe here is an independent `where`/`which` call (see
 * `pkgManagerDetect.ts`'s own doc comment) with nothing for one to learn
 * from another, so they run concurrently — `Promise.all` over a `.map()`
 * preserves each list's ORDER in the result regardless of which probe
 * actually finishes first, which matters: `pickInstallSpec` walks
 * `availableManagers` in order and returns the FIRST match, so the array's
 * order is this function's whole notion of "preferred manager first".
 */
async function listAvailableManagers(
  os: DetectedOs,
): Promise<PkgManagerCandidate[]> {
  if (os === 'win32') {
    // `release` first: the pinned, sha256-checked release ZIP, run through
    // PowerShell (installCatalog.ts#windowsReleaseInstaller). The package
    // managers follow their own manifests, and are asked for the pinned
    // version where the catalogue names one.
    // Each installer, and the program on PATH that makes it usable.
    const all: ReadonlyArray<readonly [name: string, onPath: string]> = [
      ['release', 'powershell'],
      ['winget', 'winget'],
      ['scoop', 'scoop'],
      ['choco', 'choco'],
    ];
    return Promise.all(
      all.map(async ([name, onPath]): Promise<PkgManagerCandidate> => {
        const path = await resolveBinary(onPath);
        const candidate: PkgManagerCandidate = { name, available: path !== null };
        if (path !== null) candidate.command_path = path;
        return candidate;
      }),
    );
  }
  // POSIX: probe the managers our catalogue can drive. `uv`, `cargo` and
  // `go` are ranked below the OS package manager and pipx/npm — zizmor's
  // and actionlint's catalog entries list them as fallbacks, not the first
  // choice, so they are probed last (curl stays the true last resort).
  const order =
    os === 'darwin'
      ? ['brew', 'pipx', 'npm', 'uv', 'cargo', 'go']
      : ['apt', 'pipx', 'npm', 'uv', 'cargo', 'go'];
  const [managers, curlPath] = await Promise.all([
    Promise.all(
      order.map(async (name): Promise<PkgManagerCandidate> => {
        const path = await resolveBinary(name === 'apt' ? 'apt-get' : name);
        return { name, available: path !== null };
      }),
    ),
    // `curl` fallback at the bottom — most POSIX systems have it.
    resolveBinary('curl'),
  ]);
  return [...managers, { name: 'curl', available: curlPath !== null }];
}

async function isWslUsable(): Promise<boolean> {
  const wslPath = await resolveBinary('wsl');
  if (!wslPath) return false;
  try {
    const { execa } = await import('execa');
    const r = await execa('wsl', ['-l', '--quiet'], { timeout: 5_000, reject: false });
    // `wsl -l --quiet` prints one distro name per line. UTF-16 BOM on
    // Windows means even with a distro, stdout starts with `\x00\x00\x00`
    // bytes — looking for non-whitespace is enough.
    return r.exitCode === 0 && r.stdout.replace(/\0/g, '').trim().length > 0;
  } catch {
    return false;
  }
}

async function ensurePipxOnPath(ctx: PluginContext): Promise<void> {
  // After installing pipx via `pip --user pipx`, ~/.local/bin is often not
  // on PATH yet. `pipx ensurepath` adds it to the user's shell rc so the
  // NEXT shell sees the binaries. We swallow failures silently — this is
  // best-effort polish, not a fatal step.
  const pipx = await resolveBinary('pipx');
  if (!pipx) return;
  const { execa } = await import('execa');
  await execa('pipx', ['ensurepath'], {
    cwd: ctx.scriptsDir,
    reject: false,
    timeout: 10_000,
  }).catch(() => {
    /* swallow */
  });
}

async function runCheckToolchain(
  ctx: PluginContext,
): Promise<unknown> {
  // After install, make sure pipx-installed binaries are reachable in the
  // shell the user will use next.
  await ensurePipxOnPath(ctx);
  const check = TOOLS.find((t) => t.name === 'check_toolchain');
  if (!check) return null;
  const r = await check.handler({}, ctx);
  return r;
}

