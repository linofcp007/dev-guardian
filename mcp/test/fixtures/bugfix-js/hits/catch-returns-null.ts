export function findUser(id: string): unknown {
  try { return lookup(id); } catch (e) { return null; }
}
export function findUserOrUndefined(id: string): unknown {
  try { return lookup(id); } catch (e) { return undefined; }
}
export function findAllUsers(id: string): unknown[] {
  try { return lookupAll(id); } catch (e) { return []; }
}

// Optional catch binding (ES2019), one per empty value. The rule knew only
// the bound form, so the shape modern TS actually writes -- `catch` with no
// parameter, because an unused one trips noUnusedLocals -- was invisible.
// Auditor's p03 FN-2.
export function findUserNoBinding(id: string): unknown {
  try { return lookup(id); } catch { return null; }
}
export function findUserOrUndefinedNoBinding(id: string): unknown {
  try { return lookup(id); } catch { return undefined; }
}
export function findAllUsersNoBinding(id: string): unknown[] {
  try { return lookupAll(id); } catch { return []; }
}

function lookup(id: string): unknown { return { id }; }
function lookupAll(id: string): unknown[] { return [{ id }]; }
