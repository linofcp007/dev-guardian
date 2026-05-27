/**
 * Probe for a usable bash on the host, caching the choice in `runtime_meta`.
 *
 * Windows order: `wsl bash` → Git Bash absolute path → `bash` on PATH.
 * macOS/Linux:   `/bin/bash` → `bash` on PATH.
 *
 * Cached choices are re-validated cheaply (does the binary still respond to
 * `--version`?). If validation fails, we re-probe and replace the cache.
 *
 * `probe()` returns `null` only when no usable shell is found anywhere. The
 * server treats that as a fatal-for-scripts state: script-invoking tools
 * surface a `no_bash_shell` domain error; non-script tools (resources, diff,
 * suppress) keep working.
 */

import { execa } from 'execa';
import type { RuntimeMetaRepo } from '../storage/runtimeMetaRepo.js';
import { detectOs, type DetectedOs } from './osDetect.js';

export interface ShellChoice {
  /** Absolute path or bare command, executed via `execa(command, args, …)`. */
  command: string;
  /** Arguments to prepend before the user script (e.g. `['bash']` for WSL). */
  args_prefix: string[];
  /** When true, paths must be translated via `pathTranslate.toWsl` first. */
  needs_wsl_path_translate: boolean;
  /** Human-readable label for diagnostics, e.g. "Git Bash 5.2.21(1)". */
  label: string;
}

export interface ShellProbeDeps {
  /** Returns the version line if the candidate is usable, else null. */
  testShell: (command: string, argsPrefix: string[]) => Promise<string | null>;
}

const STORAGE_KEY = 'shell_choice';

export async function probeShell(
  runtimeMeta: RuntimeMetaRepo,
  deps: ShellProbeDeps = defaultDeps(),
  os: DetectedOs = detectOs(),
): Promise<ShellChoice | null> {
  const cached = runtimeMeta.getJson<ShellChoice>(STORAGE_KEY);
  if (cached && (await isStillUsable(cached, deps))) {
    return cached;
  }

  const candidates = candidatesFor(os);
  for (const candidate of candidates) {
    const version = await deps.testShell(candidate.command, candidate.args_prefix);
    if (version) {
      const chosen: ShellChoice = { ...candidate, label: `${candidate.label} (${version})` };
      runtimeMeta.setJson(STORAGE_KEY, chosen);
      return chosen;
    }
  }
  return null;
}

export function candidatesFor(os: DetectedOs): ShellChoice[] {
  if (os === 'win32') {
    return [
      {
        command: 'wsl',
        args_prefix: ['bash'],
        needs_wsl_path_translate: true,
        label: 'WSL bash',
      },
      {
        command: 'C:\\Program Files\\Git\\bin\\bash.exe',
        args_prefix: [],
        needs_wsl_path_translate: false,
        label: 'Git Bash',
      },
      {
        command: 'bash.exe',
        args_prefix: [],
        needs_wsl_path_translate: false,
        label: 'bash on PATH',
      },
    ];
  }
  return [
    {
      command: '/bin/bash',
      args_prefix: [],
      needs_wsl_path_translate: false,
      label: '/bin/bash',
    },
    {
      command: 'bash',
      args_prefix: [],
      needs_wsl_path_translate: false,
      label: 'bash on PATH',
    },
  ];
}

async function isStillUsable(choice: ShellChoice, deps: ShellProbeDeps): Promise<boolean> {
  return (await deps.testShell(choice.command, choice.args_prefix)) !== null;
}

function defaultDeps(): ShellProbeDeps {
  return {
    testShell: async (command, argsPrefix) => {
      try {
        const args = [...argsPrefix, '--version'];
        const result = await execa(command, args, {
          timeout: 3_000,
          reject: false,
          // bash --version prints to stdout, but some embedded shells use
          // stderr — concat both to be safe.
        });
        if (result.exitCode !== 0) return null;
        const text = (result.stdout || result.stderr || '').split(/\r?\n/)[0]?.trim() ?? '';
        // Sanity check — must look like a bash version line.
        if (!/bash|gnu|version/i.test(text)) return null;
        return text;
      } catch {
        return null;
      }
    },
  };
}
