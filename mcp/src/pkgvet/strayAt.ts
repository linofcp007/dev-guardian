/**
 * The one rule that decides whether a host READ from a URL of a project file may be said (install-vet: lockfile
 * sources, the project's default registry, a configured registry).
 *
 * A URL parser takes user information up to the LAST `@` of the authority, which ends at the first `/`, `?`, `#` or
 * (for `https:`) `\`. A credential written with one of those characters unencoded (`https://TOKEN/rest@host/…`)
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
    const lower = path.toLowerCase();
    for (const form of [`/${scope}/${rest}`, `/${scope}%2f${rest}`]) {
      const at = lower.indexOf(form);
      if (at >= 0) {
        path = `${path.slice(0, at)}/${path.slice(at + form.length)}`;
        break;
      }
    }
  }
  return path.includes('@') || url.search.includes('@') || url.hash.includes('@');
}

/**
 * {@link strayAt} of a URL as WRITTEN (before any cut a reader makes at a `#` or a comment), with a `git+` prefix
 * taken off. Text the parser rejects has a stray `@` when it holds any.
 */
export function writtenStrayAt(text: string, ownName?: string): boolean {
  try {
    return strayAt(new URL(text.startsWith('git+') ? text.slice(4) : text), ownName);
  } catch {
    return text.includes('@');
  }
}
