export function trimmedApiUrlOptional(): string | undefined {
  return process.env.API_URL?.trim();
}

export function trimmedApiUrlFallback(): string {
  return (process.env.API_URL ?? '').trim();
}
