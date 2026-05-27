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
import { detectOs } from './osDetect.js';
const STORAGE_KEY = 'shell_choice';
export async function probeShell(runtimeMeta, deps = defaultDeps(), os = detectOs()) {
    const cached = runtimeMeta.getJson(STORAGE_KEY);
    if (cached && (await isStillUsable(cached, deps))) {
        return cached;
    }
    const candidates = candidatesFor(os);
    for (const candidate of candidates) {
        const version = await deps.testShell(candidate.command, candidate.args_prefix);
        if (version) {
            const chosen = { ...candidate, label: `${candidate.label} (${version})` };
            runtimeMeta.setJson(STORAGE_KEY, chosen);
            return chosen;
        }
    }
    return null;
}
export function candidatesFor(os) {
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