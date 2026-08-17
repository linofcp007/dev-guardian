export function findUser(id: string): unknown {
  try { return lookup(id); } catch (e) { return null; }
}
export function findUserOrUndefined(id: string): unknown {
  try { return lookup(id); } catch (e) { return undefined; }
}
export function findAllUsers(id: string): unknown[] {
  try { return lookupAll(id); } catch (e) { return []; }
}
function lookup(id: string): unknown { return { id }; }
function lookupAll(id: string): unknown[] { return [{ id }]; }
