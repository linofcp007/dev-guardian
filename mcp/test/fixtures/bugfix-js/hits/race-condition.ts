export async function handler(repo: { save(v: unknown): Promise<void> }): Promise<string> {
  repo.save({ id: 1 });
  return 'ok';
}
