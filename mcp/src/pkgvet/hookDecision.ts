/**
 * The PreToolUse hook's decision for one Bash/PowerShell command: deny,
 * warn, note, or stay silent. Kept here (compiled to `mcp/dist/pkgvet/`)
 * rather than in `hooks/guardian-hook.mjs` so it is unit-testable; the hook
 * itself only calls it and emits the answer.
 *
 *   - **deny** only a package that is malicious or does not exist (and has
 *     no custom registry that could explain its absence);
 *   - **warn** (additionalContext) on a version < 72 h old, install scripts,
 *     typosquat suspicion, known vulnerabilities, an unpublished version;
 *   - **note** — one line — for anything that could not be vetted (offline,
 *     timeout, HTTP error, rate limit, private registry). The command runs;
 *     the note says it was NOT verified, never that it was;
 *   - **silent** when every package came back `ok`, and for every command
 *     that installs nothing by name — which never touches the network.
 *
 * All network work shares one budget ({@link HOOK_BUDGET_MS}, 3 s): the
 * install commands of a compound line are vetted in parallel under it.
 */

import { parseInstallCommands } from './parseCommand.js';
import type { PackageVetResult, PkgEcosystem } from './types.js';
import { HOOK_BUDGET_MS, vetPackages } from './vet.js';

export interface HookVetOptions {
  /** The project directory (the hook payload's `cwd`). */
  cwd: string;
  homeDir?: string;
  env?: Readonly<Record<string, string | undefined>>;
  fetchImpl?: typeof fetch;
  budgetMs?: number;
  now?: number;
  /** `configs/popular-packages`, located by the hook from the plugin root. */
  popularDir?: string;
  /** Test override of the lists. */
  popular?: Partial<Record<PkgEcosystem, readonly string[] | null>>;
}

export interface HookDecision {
  /** Set only when the command must be denied. */
  deny?: string;
  /** Warnings and notes for the model, when there is anything to say. */
  context?: string;
}

function label(r: PackageVetResult): string {
  return r.version !== undefined ? `${r.name}@${r.version}` : r.name;
}

function firstLine(r: PackageVetResult): string {
  return r.reasons[0] ?? 'no reason recorded';
}

/**
 * `null` when there is nothing to say: no install command, or every package
 * vetted clean.
 */
export async function decideInstallCommand(command: string, opts: HookVetOptions): Promise<HookDecision | null> {
  const commands = parseInstallCommands(command).filter((c) => c.packages.length > 0);
  if (commands.length === 0) return null;

  const env = opts.env ?? process.env;
  const offline = env['GUARDIAN_OFFLINE'] === '1';
  const budgetMs = opts.budgetMs ?? HOOK_BUDGET_MS;
  const batches = await Promise.all(
    commands.map((c) =>
      vetPackages(c.packages, {
        budgetMs,
        offline,
        now: opts.now ?? Date.now(),
        registry: { projectDir: opts.cwd, homeDir: opts.homeDir, env },
        commandRegistry: c.customRegistry,
        ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
        ...(opts.popularDir !== undefined ? { popularDir: opts.popularDir } : {}),
        ...(opts.popular !== undefined ? { popular: opts.popular } : {}),
      }),
    ),
  );
  const results = batches.flat();

  const blocked = results.filter((r) => r.verdict === 'block');
  if (blocked.length > 0) {
    const list = blocked
      .map((r) => {
        const failing = Object.values(r.checks)
          .filter((c) => c.status === 'fail' && c.detail !== undefined)
          .map((c) => c.detail ?? '');
        const why = failing.length > 0 ? failing.join('; ') : firstLine(r);
        return `'${label(r)}': ${why}${/[.?!]$/.test(why) ? '' : '.'}`;
      })
      .join(' ');
    return {
      deny:
        `dev-guardian blocked this install: ${list} ` +
        'Check the package name against the project documentation or the registry before installing anything. ' +
        'If this package is genuinely intended, ask the user to install it themselves.',
    };
  }

  const lines: string[] = [];
  const warned = results.filter((r) => r.verdict === 'warn');
  if (warned.length > 0) {
    lines.push('⚠️ dev-guardian package vetting — review before relying on these:');
    for (const r of warned) lines.push(`  • ${label(r)}: ${r.reasons.slice(0, 3).join('; ')}`);
  }
  const unknown = results.filter((r) => r.verdict === 'unknown');
  if (unknown.length > 0) {
    const what = unknown.map((r) => `${label(r)} (${firstLine(r)})`).join(', ');
    lines.push(`dev-guardian could not vet ${what} — not verified.`);
  }
  return lines.length > 0 ? { context: lines.join('\n') } : null;
}
