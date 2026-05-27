/**
 * OS detection from inside the MCP server process.
 *
 * Note: this answers "what OS is the server running on", not "what shell can
 * we reach". A server on Windows may still execute scripts via WSL — that is
 * a `ShellChoice` concern, not an OS concern.
 */
export function detectOs() {
    switch (process.platform) {
        case 'linux':
            return 'linux';
        case 'darwin':
            return 'darwin';
        case 'win32':
            return 'win32';
        default:
            return 'unsupported';
    }
}
//# sourceMappingURL=osDetect.js.map