export async function handler(repo: { save(v: unknown): Promise<void> }): Promise<string> {
  repo.save({ id: 1 });
  return 'ok';
}

// Assignment-form async arrow — the shape `async function $F(...) { ... }`
// alone cannot match (bugfix-rules-jsts fix wave; see the rule's own comment).
export const arrowHandler = async (repo: { save(v: unknown): Promise<void> }): Promise<void> => {
  repo.save({ id: 2 });
};

// Call-argument-form async arrow — the Express/NestJS/addEventListener
// callback shape named as the dominant real-world case in the fix wave.
app.post('/users', async (repo: { save(v: unknown): Promise<void> }) => {
  repo.save({ id: 3 });
});
