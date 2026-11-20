/**
 * The one rule that decides whether a host READ from a URL of a project file may be said (install-vet: lockfile
 * sources, the project's default registry, a configured registry).
 *
 * A URL parser takes user information up to the LAST `@` of the authority, which ends at the first `/`, `?`, `#` or
 * (for `https:`) a backslash. A credential written with one of those characters unencoded (`https://TOKEN/rest@host/…`)
 * makes it read the start of the credential as the host — and the manager does the same (measured), so the host IS
 * the one contacted, but it is also a piece of a credential, and the line that names it stays in the session log.
 * The sign of such a URL is an `@` left outside the authority: in the path, the query or the fragment. When there
 * is one, the host is not said. The one `@` that is not a sign is the one that opens the scope of the entry's own
 * package (`/@scope/name/-/name-1.0.0.tgz`).
 */

/** Whether `url` has an `@` outside its credentials, other than the scope of `ownName` (the package the URL serves, when known). */
export function strayAt(url: URL, ownName?: string): boolean {
  let path = url.pathname;
  const slash = ownName === undefined ? -1 : ownName.indexOf('/');
  if (ownName !== undefined && ownName.startsWith('@') && slash > 1) {
    const scope = ownName.slice(0, slash).toLowerCase();
    const rest = ownName.slice(slash + 1).toLowerCase();
    // Every occurrence: Artifactory writes the scope twice (`/@scope/name/-/@scope/name-1.0.0.tgz`).
    for (const form of [`/${scope}/${rest}`, `/${scope}%2f${rest}`]) {
      for (let at = path.toLowerCase().indexOf(form); at >= 0; at = path.toLowerCase().indexOf(form)) {
        path = `${path.slice(0, at)}/${path.slice(at + form.length)}`;
      }
    }
  }
  return path.includes('@') || url.search.includes('@') || url.hash.includes('@');
}

/**
 * {@link strayAt} of a URL as WRITTEN (before the cut a reader makes at a `#`), with a `git+` prefix taken off. The
 * callers have parsed the text they cut it from, and a suffix after a `#` cannot make a URL unparsable — but the hooks
 * fail open, so text the parser does refuse must not throw from here: its host is then not said.
 */
export function writtenStrayAt(text: string, ownName?: string): boolean {
  try {
    return strayAt(new URL(text.startsWith('git+') ? text.slice(4) : text), ownName);
  } catch {
    return true;
  }
}

/** What ends a registry value whose cut-off comment held an `@` (see {@link withCommentAt}). */
const COMMENT_HOLDS_AT = '#@';

/**
 * A registry value that a reader cut at a comment (`#` or `;`), still as the reader cut it — the value is what decides
 * whether it is the public registry or another one, exactly as before — but, when the part cut off held an `@`, marked
 * so that no sentence names its host: `registry=https://TOKEN#rest@host/` is read by the manager as `https://TOKEN`,
 * and the comment may be the rest of a credential. The mark is a fragment, which every comparison of registries
 * ignores and which {@link strayAt} reads as an `@` outside the credentials.
 */
export function withCommentAt(value: string, cutOff: string): string {
  return cutOff.includes('@') ? `${value}${COMMENT_HOLDS_AT}` : value;
}
