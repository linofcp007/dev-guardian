interface User {
  id: string;
  name: string;
}

export function nameOf(users: User[], id: string): string {
  return users.find((u) => u.id === id).name;
}

// Block-bodied predicate -- the same Array#find, written the other way.
export function nameOfBlockBody(users: User[], id: string): string {
  return users.find((u) => { return u.id === id; }).name;
}

// Three-parameter predicate (element, index, array), which Array#find
// supports and which a single-named-metavariable arity would have excluded.
export function nameOfIndexedPredicate(users: User[], id: string): string {
  return users.find((u, i, all) => u.id === id && i < all.length).name;
}

// findLast (ES2023) has identical semantics and was invisible. Auditor's
// p09 FN-4.
export function lastNamed(users: User[], name: string): string {
  return users.findLast((u) => u.name === name).name;
}
