/**
 * `cli/dev-guardian.mjs` lives outside `mcp/` (repo root) and has no
 * declaration file, so `browserOpener.test.ts`'s
 * `await import('../../../../cli/dev-guardian.mjs')` hits TS7016.
 * `allowJs` was tried first (per this project's own preference for checking
 * real code over stubbing it) but it does not resolve cleanly here: the file
 * is outside `mcp/`, which is `tsconfig.test.json`'s `rootDir`, so allowing
 * JS just trades TS7016 for TS6059 ("File is not under 'rootDir'") — widening
 * `rootDir` to cover the whole repo would pull the rest of the untyped CLI
 * into this suite's checking, far beyond what this one test needs. A narrow
 * ambient declaration, scoped to the one export this test actually calls, is
 * the smaller and more honest fix.
 */
declare module '*/cli/dev-guardian.mjs' {
  export function resolveOpenerCommand(
    platform: string,
    target: string,
  ): { command: string; args: string[] };
  export function isNodeSqliteUnavailable(error: unknown): boolean;
  /** What the last-resort handler prints for `error`, and its exit code — fatalOutcome.test.ts. */
  export function fatalOutcome(error: unknown): { text: string; exitCode: number };
  /**
   * ci-init's template substitution — see ciInitRender.test.ts for why the
   * leftover-placeholder check needed its own coverage. `sections` turns the
   * template's `# {{#NAME}}` / `# {{^NAME}}` blocks on or off (`--attest`).
   */
  export function renderCiTemplate(
    text: string,
    vars: Record<string, string>,
    sections?: Record<string, boolean>,
  ): string;
}
