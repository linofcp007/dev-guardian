/**
 * Shared types for install-time package vetting (`vet_packages` and the
 * PreToolUse install-command hook).
 *
 * Pure declarations. Everything under `pkgvet/` is imported by the hook
 * straight from `mcp/dist/pkgvet/*.js`, so nothing here may pull in a
 * dependency — Node built-ins only.
 */
export const PKG_ECOSYSTEMS = ['npm', 'pypi', 'packagist', 'nuget'];
/** OSV's own spelling of each ecosystem (https://ossf.github.io/osv-schema/#affectedpackage-field). */
export const OSV_ECOSYSTEM = {
    npm: 'npm',
    pypi: 'PyPI',
    packagist: 'Packagist',
    nuget: 'NuGet',
};
//# sourceMappingURL=types.js.map