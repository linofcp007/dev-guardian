export function trimmedApiUrl(): string {
  return process.env.API_URL.trim();
}

// Bracket access — the form required whenever the key is dynamic or has a
// dash, and exactly as crash-prone. Auditor's p10 FN-6.
export function trimmedApiUrlBracket(): string {
  return process.env['API_URL'].trim();
}

// PROPERTY access, not a method call: `.length` on undefined throws just as
// hard as `.trim()` does, but the old pattern required a call. p10 FN-7.
export function apiUrlLength(): number {
  return process.env.API_URL.length;
}
