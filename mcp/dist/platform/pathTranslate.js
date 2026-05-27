/**
 * Cross-platform path translation.
 *
 * Only one translation matters in practice: Windows-native paths → WSL
 * paths, used when the chosen shell is WSL and we need to hand a project
 * path to a `.sh` script running inside the WSL filesystem view.
 *
 * `toNative` is the identity for every shell except WSL — call it from the
 * runner to stay agnostic to the shell choice.
 */
/**
 * Convert a Windows-native path to its WSL equivalent.
 *   C:\\Users\\foo       → /mnt/c/Users/foo
 *   D:/Code/proj         → /mnt/d/Code/proj
 *   c:\\users\\foo       → /mnt/c/users/foo  (case preserved past the drive)
 *
 * UNC paths (`\\\\server\\share`) and relative paths are returned unchanged
 * because they have no clean WSL analogue.
 */
export function toWsl(input) {
    if (input.startsWith('\\\\') || input.startsWith('//'))
        return input;
    const driveMatch = /^([a-zA-Z]):[\\/](.*)$/.exec(input);
    if (!driveMatch)
        return input;
    const driveRaw = driveMatch[1];
    const restRaw = driveMatch[2];
    if (driveRaw === undefined || restRaw === undefined)
        return input;
    const drive = driveRaw.toLowerCase();
    const rest = restRaw.replace(/\\/g, '/');
    return `/mnt/${drive}/${rest}`;
}
/**
 * Inverse of `toWsl`, used when the runner gets a path that came back from
 * a WSL-spawned script and needs to be displayed in Windows-native form.
 */
export function fromWsl(input) {
    const match = /^\/mnt\/([a-zA-Z])\/(.*)$/.exec(input);
    if (!match)
        return input;
    const driveRaw = match[1];
    const restRaw = match[2];
    if (driveRaw === undefined || restRaw === undefined)
        return input;
    return `${driveRaw.toUpperCase()}:\\${restRaw.replace(/\//g, '\\')}`;
}
/**
 * Translate a path to whatever form the chosen shell expects. No-op for
 * everything except WSL.
 */
export function toShellPath(input, shell) {
    return shell.needs_wsl_path_translate ? toWsl(input) : input;
}
//# sourceMappingURL=pathTranslate.js.map