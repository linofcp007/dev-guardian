export function findUserLogged(id: string): unknown {
  try {
    return lookup(id);
  } catch (e) {
    console.error(e);
    return null;                                     // logged AND returns null — deliberate
  }
}

interface Result<T> {
  ok: boolean;
  value?: T;
  error?: string;
}

export function findUserTyped(id: string): Result<unknown> {
  try {
    return { ok: true, value: lookup(id) };
  } catch (e) {
    return { ok: false, error: String(e) };           // typed error result, not a bare null
  }
}

function lookup(id: string): unknown { return { id }; }
