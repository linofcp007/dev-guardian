/**
 * The install hook's gate (review 8, item 17): whether a command can install a
 * package at all, decided before the vetting modules are loaded — `git status`
 * paid ~20 ms for importing them. A superset of what `parseInstallCommands`
 * reads an install from: every tool it knows, as a word, in the command with
 * its quotes taken out and its backslashes read both ways (an escape to bash —
 * `n\pm` runs npm — and a separator to Windows — `C:\…\pip.exe`). A command
 * that names none of them installs nothing; one that names one is parsed in
 * full. `test/unit/pkgvet/mayInstall.test.ts` holds the two together.
 *
 * No imports: the hook loads it on every Bash and PowerShell call.
 */
const INSTALLER_WORD = /(?:^|[^\w.-])(?:npm|pnpm|pnpx|npx|yarn|bunx?|pipx?|pip\d[\d.]*|uvx?|poetry|composer|dotnet)(?:$|[^\w-])/i;
export function mayInstall(command) {
    const unquoted = command.replace(/['"`]/g, '');
    return INSTALLER_WORD.test(unquoted.replace(/\\/g, '')) || INSTALLER_WORD.test(unquoted.replace(/\\/g, '/'));
}
//# sourceMappingURL=mayInstall.js.map