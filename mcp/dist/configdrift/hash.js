/**
 * The content hash drift detection compares.
 *
 * ---- What it normalises, and why each one is not optional -------------
 *
 * A raw byte hash is the obvious implementation and it is wrong here, for a
 * reason this repository lives with daily: the configs are authored on
 * Windows and consumed in POSIX CI. Git's `core.autocrlf` rewrites line
 * endings on checkout, so the identical commit lands as CRLF on one machine
 * and LF on another. A byte hash would tell every Windows user "you edited
 * your copy" and every Linux user "you did not", from the same file — and the
 * one state that must not be lost in the noise, "we shipped a fix you never
 * received", is exactly the state a false `local_edit` suppresses.
 *
 *   - **CRLF / CR → LF.** The case above.
 *   - **Leading BOM.** Windows editors add one on save; it changes no config
 *     semantics in YAML, TOML or JSON and is invisible to the user who would
 *     have to explain the resulting warning.
 *   - **Trailing newlines at EOF.** `end-of-file-fixer` ships in the very
 *     `pre-commit-config.yaml` `init_project` installs, so a project that
 *     adopts our own hooks would otherwise immediately register as drifted
 *     against our own baseline.
 *   - **Our provenance header.** The shipped file has none and the installed
 *     copy has one; without stripping it, every stamped file is permanently
 *     "different from what we ship".
 *
 * ---- What it deliberately still notices ------------------------------
 *
 * Trailing whitespace *inside* a line, indentation, and comment text all
 * count as changes. Trailing whitespace is nearly always cosmetic, but
 * indentation is not — it is structural in YAML — and no rule that strips one
 * without the other is worth the words needed to explain it. Comment text
 * matters because half of what a security rule pack communicates lives in its
 * comments. Erring toward "this changed" is the safe direction: the cost is a
 * `local_edit`, which is silent by design.
 */
import { createHash } from 'node:crypto';
import { readProjectText } from '../platform/projectFs.js';
import { stripProvenanceHeader } from './header.js';
export { stripProvenanceHeader };
/** The comparable form of a config file's text. */
export function canonicaliseConfig(text) {
    const withoutBom = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
    const lf = withoutBom.replace(/\r\n?/g, '\n');
    return stripProvenanceHeader(lf).replace(/\n+$/, '');
}
/** sha256 of the canonical form, hex. */
export function hashConfigText(text) {
    return createHash('sha256').update(canonicaliseConfig(text), 'utf8').digest('hex');
}
/** The largest config file hashed; a real one is a few KB. */
export const MAX_CONFIG_FILE_BYTES = 1024 * 1024;
/**
 * `hashConfigText` of `rel`'s contents below `root` — the project, or the
 * plugin's `configs/` — or `null` when the file is missing, unreadable, or
 * refused.
 *
 * Both paths can come from `.dev-guardian/configs.json`, a file in the
 * scanned repository: its `target` and `source` fields are joined to the
 * project and to `configs/`. So the read is `platform/projectFs.ts`'s,
 * contained in `root`, bounded, regular files only — `"source":
 * "../../../../dev/zero"` in a committed manifest would otherwise have been
 * read without end on every scan.
 *
 * Never throws. Every caller sits on a path — a scan, or `init_project` — that
 * must not fail because a config file was deleted or locked mid-read.
 */
export function hashConfigFile(root, rel) {
    const r = readProjectText(root, rel, MAX_CONFIG_FILE_BYTES);
    return r.status === 'ok' ? hashConfigText(r.text) : null;
}
//# sourceMappingURL=hash.js.map