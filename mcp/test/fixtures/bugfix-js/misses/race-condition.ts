export async function awaited(repo: { save(v: unknown): Promise<void> }): Promise<void> {
  await repo.save({ id: 1 });
}
export async function returned(repo: { save(v: unknown): Promise<void> }): Promise<void> {
  return repo.save({ id: 1 });
}
export async function deliberate(logger: { write(v: string): Promise<void> }): Promise<void> {
  logger.write('fire and forget');                  // NOT a mutating verb
}

// SYNC arrow, assignment form — must stay silent. This is the exact trap
// documented on the rule: a naive `pattern-inside: async (...) => { ... }`
// does not check "async" at all in this Semgrep version and would fire
// here too. If this ever starts firing, the widened arrow clause regressed
// to that trap.
export const syncArrowHandler = (repo: { save(v: unknown): Promise<void> }): void => {
  repo.save({ id: 1 });
};

// SYNC arrow, call-argument form — same trap, callback-argument shape.
app.post('/sync', (repo: { save(v: unknown): Promise<void> }) => {
  repo.save({ id: 1 });
});

// Verb-prefixed but not verb-EXACT — "saveAll" starts with "save" but is
// not `save`. Proves the metavariable-regex's trailing `$` anchor
// (bugfix-js.yml:134) is load-bearing: without it, `^(save|update|...)`
// would match "saveAll" too (mutation: drop the trailing `$`).
export async function bulkSave(a: { saveAll(v: unknown[]): Promise<void> }): Promise<void> {
  a.saveAll([1, 2, 3]);
}
