/**
 * Type declaration for `server.mjs`. Named `.d.mts` (not `.d.ts`) because
 * TypeScript's `NodeNext` module resolution looks for the `.mjs`-specific
 * declaration sibling. `mcp/test/**` is outside `tsconfig.json`'s `include`
 * (see its `exclude` list), so nothing in the build depends on this file —
 * it exists purely so an editor importing `server.mjs` from a `.ts` test
 * gets real types instead of an implicit `any`.
 */

export interface DastFixtureRequest {
  method: string;
  path: string;
}

export interface DastFixture {
  origin: string;
  close: () => Promise<void>;
  /** Live log, mutated in place — read it after the calls under test finish. */
  requests: DastFixtureRequest[];
}

export function start(): Promise<DastFixture>;
