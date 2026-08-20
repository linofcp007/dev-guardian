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
// not `save`. Proves the verb-list metavariable-regex's trailing `$` anchor
// is load-bearing: without it, `^(save|update|...)` would match "saveAll"
// too (mutation: drop the trailing `$`).
//
// The receiver is `repo` on purpose, and that is not cosmetic. It used to
// be `a`, which stopped proving anything the moment the audit wave added
// the receiver-name constraint: `a` fails THAT check, so dropping the `$`
// anchor changed nothing and the mutation went undetected. Two heuristics
// in one rule can each hide the other's regression unless the near-miss
// clears every constraint but the one it is aimed at. Caught by ablating
// the anchor after the receiver clause landed, not by review.
export async function bulkSave(repo: { saveAll(v: unknown[]): Promise<void> }): Promise<void> {
  repo.saveAll([1, 2, 3]);
}
