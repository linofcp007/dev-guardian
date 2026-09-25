/**
 * Probe for a usable bash on the host, caching the choice in `runtime_meta`.
 *
 * Windows order: Git Bash absolute path → `wsl bash` → `bash` on PATH.
 * macOS/Linux:   `/bin/bash` → `bash` on PATH.
 *
 * Git Bash comes first on Windows because it runs in the Windows filesystem
 * view: the scanners installed natively (winget/scoop/pip) are on its PATH
 * and Windows paths reach the scripts as they are. WSL sees neither without
 * translation — and a Linux distro usually has none of those scanners at all.
 *
 * Cached choices are re-validated cheaply (does the binary still respond to
 * `--version`?). If validation fails, we re-probe and replace the cache. The
 * candidates that OUTRANK the cached choice are probed first, so a host that
 * cached WSL under the old order moves to Git Bash once it is usable.
 *
 * `probe()` returns `null` only when no usable shell is found anywhere. The
 * server treats that as a fatal-for-scripts state: script-invoking tools
 * surface a `no_bash_shell` domain error; non-script tools (resources, diff,
 * suppress) keep working.
 */
import { execa } from 'execa';
import { detectOs } from './osDetect.js';
const STORAGE_KEY = 'shell_choice';
export async function probeShell(runtimeMeta, deps = defaultDeps(), os = detectOs()) {
    const candidates = candidatesFor(os);
    const cached = runtimeMeta.getJson(STORAGE_KEY);
    if (cached) {
        // Only the candidates ranked above the cached one need a probe; one the
        // current order does not know at all is simply re-validated.
        const rank = candidates.findIndex((c) => c.command === cached.command);
        for (const candidate of rank > 0 ? candidates.slice(0, rank) : []) {
            const chosen = await tryCandidate(candidate, deps);
            if (chosen) {
                runtimeMeta.setJson(STORAGE_KEY, chosen);
                return chosen;
            }
        }
        if (await isStillUsable(cached, deps))
            return cached;
    }
    for (const candidate of candidates) {
        const chosen = await tryCandidate(candidate, deps);
        if (chosen) {
            runtimeMeta.setJson(STORAGE_KEY, chosen);
            return chosen;
        }
    }
    return null;
}
async function tryCandidate(candidate, deps) {
    const version = await deps.testShell(candidate.command, candidate.args_prefix);
    return version ? { ...candidate, label: `${candidate.label} (${version})` } : null;
}
/** The WSL candidate, also used directly by `install_toolchain`'s fallback. */
export const WSL_SHELL = {
    command: 'wsl',
    args_prefix: ['bash'],
    needs_wsl_path_translate: true,
    label: 'WSL bash',
};
export function candidatesFor(os) {
    if (os === 'win32') {
        return [
            {
                command: 'C:\\Program Files\\Git\\bin\\bash.exe',
                args_prefix: [],
                needs_wsl_path_translate: false,
                label: 'Git Bash',
            },
            { ...WSL_SHELL },
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
async function isStillUsable(choice, deps) {
    return (await deps.testShell(choice.command, choice.args_prefix)) !== null;
}
function defaultDeps() {
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
                if (result.exitCode !== 0)
                    return null;
                const text = (result.stdout || result.stderr || '').split(/\r?\n/)[0]?.trim() ?? '';
                // Sanity check — must look like a bash version line.
                if (!/bash|gnu|version/i.test(text))
                    return null;
                return text;
            }
            catch {
                return null;
            }
        },
    };
}
//# sourceMappingURL=shellProbe.js.map