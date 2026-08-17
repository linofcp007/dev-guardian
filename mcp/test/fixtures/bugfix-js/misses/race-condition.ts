export async function awaited(repo: { save(v: unknown): Promise<void> }): Promise<void> {
  await repo.save({ id: 1 });
}
export async function returned(repo: { save(v: unknown): Promise<void> }): Promise<void> {
  return repo.save({ id: 1 });
}
export async function deliberate(logger: { write(v: string): Promise<void> }): Promise<void> {
  logger.write('fire and forget');                  // NOT a mutating verb
}
