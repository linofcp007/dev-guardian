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
 *        reachable Windows pkg manager (winget → scoop → choco). If none of
 *        them are present AND WSL is, delegate to
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
import { detectOs } from '../platform/osDetect.js';
import { firstWindowsAvailable, resolveBinary, } from '../platform/pkgManagerDetect.js';
import { runProcess } from '../runners/processRunner.js';
import { runShellScript } from '../runners/shellRunner.js';
import { TOOL_CATALOG, listDefaultTools, pickInstallSpec, } from '../runners/installCatalog.js';
import { registerToolModule, TOOLS } from './index.js';
const inputSchema = {
    tools: z
        .array(z.string())
        .optional()
        .describe('When set, install only these scanners (must exist in the catalogue). When omitted, install ' +
        'the default set: semgrep, trivy, gitleaks, syft, pre-commit (+ ruff/bandit/jscpd if stack ' +
        'detected).'),
    dry_run: z
        .boolean()
        .optional()
        .describe('Print commands without executing. Default: false.'),
    elevation_allowed: z
        .boolean()
        .optional()
        .describe('Set true to allow install steps that require sudo/admin (apt, choco, npm install -g). ' +
        'Default: false — steps needing elevation are reported under `requires_elevation` instead.'),
};
const tool = {
    name: 'install_toolchain',
    title: 'Install missing toolchain',
    description: 'Install missing scanners. Defaults to the standard set; pass `tools=[...]` to limit. ' +
        'Linux/macOS delegate to scripts/install/install-{linux,macos}.sh. Windows uses winget/scoop/' +
        'choco/WSL. dry_run prints commands without executing.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
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
    const result = {
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
    }
    else {
        await installDefaults({ os, dryRun, elevation, ctx, result });
    }
    const verification = await runCheckToolchain(ctx);
    return {
        ok: true,
        os,
        applied: !dryRun,
        ...result,
        verification: verification,
    };
}
async function installDefaults(opts) {
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
        opts.result.manual_steps.push(...listDefaultTools().map((t) => ({
            tool: t,
            instructions: `Install ${t} manually — see TOOL_CATALOG for command suggestions.`,
        })));
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
    const scriptPath = join(opts.ctx.scriptsDir, 'install', 'install-linux.sh');
    const r = await runProcess({
        command: 'wsl',
        args: ['bash', scriptPath, '--no-sudo'],
        cwd: opts.ctx.scriptsDir,
    });
    for (const t of listDefaultTools()) {
        if (r.outcome === 'completed') {
            opts.result.installed.push({ tool: t, manager: 'wsl' });
        }
        else {
            opts.result.failed.push({
                tool: t,
                manager: 'wsl',
                error: r.stderr.split(/\r?\n/)[0] ?? 'wsl install-linux.sh failed',
            });
        }
    }
}
async function runPosixInstaller(opts) {
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
        }
        else {
            opts.result.failed.push({
                tool: t,
                manager: 'bundled-script',
                error: r.stderr.split(/\r?\n/)[0] ?? `script exited ${r.outcome}`,
            });
        }
    }
}
async function installPerTool(opts) {
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
            const first = specs ? Object.values(specs)[0] : undefined;
            const hint = first?.description ?? 'See https://learn.microsoft.com/dotnet/core/install/';
            opts.result.manual_steps.push({
                tool: toolName,
                instructions: `dev-guardian never auto-installs the .NET SDK. ${hint}`,
            });
            continue;
        }
        const picked = pickInstallSpec(toolName, opts.os, 
        // narrow PkgManagerCandidate.name (string) to the catalogue's enum.
        availableManagers
            .filter((c) => c.available)
            .map((c) => ({
            name: c.name,
        })));
        if (!picked) {
            opts.result.manual_steps.push({
                tool: toolName,
                instructions: `No available installer for ${toolName} on ${opts.os}. Install manually.`,
            });
            continue;
        }
        const entry = {
            tool: toolName,
            manager: picked.manager,
            command: describeSpec(picked.spec),
            needs_elevation: picked.spec.needs_elevation,
        };
        if (picked.spec.needs_elevation && !opts.elevation) {
            opts.result.requires_elevation.push({
                ...entry,
                hint: 'Re-call with elevation_allowed=true to run this step.',
            });
            continue;
        }
        if (opts.dryRun) {
            opts.result.would_install.push(entry);
            continue;
        }
        const r = await runProcess({
            command: picked.spec.command,
            args: picked.spec.args,
            cwd: opts.ctx.scriptsDir,
        });
        if (r.outcome === 'completed') {
            opts.result.installed.push(entry);
        }
        else {
            opts.result.failed.push({
                ...entry,
                error: (r.stderr.split(/\r?\n/)[0] ?? r.outcome).slice(0, 500),
            });
        }
    }
}
function describeSpec(spec) {
    return spec.description ?? `${spec.command} ${spec.args.join(' ')}`;
}
async function listAvailableManagers(os) {
    if (os === 'win32') {
        const all = ['winget', 'scoop', 'choco'];
        const out = [];
        for (const name of all) {
            const path = await resolveBinary(name);
            const candidate = { name, available: path !== null };
            if (path !== null)
                candidate.command_path = path;
            out.push(candidate);
        }
        return out;
    }
    // POSIX: probe the managers our catalogue can drive.
    const order = os === 'darwin' ? ['brew', 'pipx', 'npm'] : ['apt', 'pipx', 'npm'];
    const out = [];
    for (const name of order) {
        const path = await resolveBinary(name === 'apt' ? 'apt-get' : name);
        out.push({ name, available: path !== null });
    }
    // `curl` fallback at the bottom — most POSIX systems have it.
    const curlPath = await resolveBinary('curl');
    out.push({ name: 'curl', available: curlPath !== null });
    return out;
}
async function isWslUsable() {
    const wslPath = await resolveBinary('wsl');
    if (!wslPath)
        return false;
    try {
        const { execa } = await import('execa');
        const r = await execa('wsl', ['-l', '--quiet'], { timeout: 5_000, reject: false });
        // `wsl -l --quiet` prints one distro name per line. UTF-16 BOM on
        // Windows means even with a distro, stdout starts with `\x00\x00\x00`
        // bytes — looking for non-whitespace is enough.
        return r.exitCode === 0 && r.stdout.replace(/\0/g, '').trim().length > 0;
    }
    catch {
        return false;
    }
}
async function ensurePipxOnPath(ctx) {
    // After installing pipx via `pip --user pipx`, ~/.local/bin is often not
    // on PATH yet. `pipx ensurepath` adds it to the user's shell rc so the
    // NEXT shell sees the binaries. We swallow failures silently — this is
    // best-effort polish, not a fatal step.
    const pipx = await resolveBinary('pipx');
    if (!pipx)
        return;
    const { execa } = await import('execa');
    await execa('pipx', ['ensurepath'], {
        cwd: ctx.scriptsDir,
        reject: false,
        timeout: 10_000,
    }).catch(() => {
        /* swallow */
    });
}
async function runCheckToolchain(ctx) {
    // After install, make sure pipx-installed binaries are reachable in the
    // shell the user will use next.
    await ensurePipxOnPath(ctx);
    const check = TOOLS.find((t) => t.name === 'check_toolchain');
    if (!check)
        return null;
    const r = await check.handler({}, ctx);
    return r;
}
//# sourceMappingURL=installToolchain.js.map