/**
 * Narrowing a tool handler's `ToolResult` to its success payload, in one
 * place, with the runtime check the ad-hoc casts were silently skipping.
 *
 * ---- Why this exists -------------------------------------------------
 *
 * `ToolResult<T>` (`src/types.ts`) is a union:
 *
 *     ({ ok: true } & T) | { ok: false; error: DomainError }
 *
 * and every tool handler is declared as returning
 * `ToolResult<Record<string, unknown>>`. Tests want the concrete payload, so
 * they were written as:
 *
 *     const r = (await tool.handler(input, ctx)) as { scan_id: string };
 *
 * That has two problems, and the second is the one that bites.
 *
 * **It does not type-check.** `{ ok: true } & Record<string, unknown>` does
 * not sufficiently overlap `{ scan_id: string }`, so TypeScript rejects the
 * assertion (TS2352). Nobody noticed for the life of the repo because no
 * type checker ever ran over `test/` — `tsconfig.json` excludes it and
 * vitest transpiles through esbuild, which strips types without checking
 * them. `tsconfig.test.json` is what closed that, and these fifty errors are
 * what it found.
 *
 * (An earlier version of this comment credited that config with catching the
 * 1.7.0 `--config=${bugfixRules}` array-interpolation bug too. It does not:
 * `tsc` types every template interpolation as `string` regardless of the
 * operand, at any strictness. Measured, then corrected here.)
 *
 * **It also erases the `ok` discriminant.** A cast is not a check. If a
 * handler returned `{ ok: false, error: … }`, the assertion above still
 * succeeds, and the test then reads `undefined` off every property and fails
 * somewhere far from the cause, with a message that names the assertion
 * rather than the error the tool actually reported. Writing the cast through
 * `as unknown as` at each site would have silenced the compiler and kept
 * that second problem exactly as it was.
 *
 * So the narrowing lives here instead: one documented widening, and a real
 * `ok` assertion that fails loudly and quotes the domain error.
 */

import type { ToolResult } from '../../src/types.js';

/**
 * Asserts a handler result is the success branch and returns it typed as the
 * payload the caller expects.
 *
 * Use it in place of a bare `as` on a handler result:
 *
 *     const r = okResult<{ scan_id: string }>(await tool.handler(input, ctx));
 *
 * `T` is unchecked at runtime — the union's `ok` discriminant is all that can
 * be verified without a schema, and asserting the payload's shape is the
 * calling test's own job. What this guarantees is narrower and worth having:
 * the result really is the success branch, so a `false` result can no longer
 * masquerade as a payload full of `undefined`.
 *
 * For the deliberate failure path, do NOT use this — match on the union
 * directly, so the error branch stays type-checked:
 *
 *     const r = await tool.handler(input, ctx);
 *     expect(r.ok).toBe(false);
 *     if (r.ok) throw new Error('expected failure');
 *     expect(r.error.code).toBe('…');
 */
export function okResult<T>(result: ToolResult<Record<string, unknown>>): { ok: true } & T {
  if (!result.ok) {
    throw new Error(
      `expected a successful ToolResult, got ok:false — ${JSON.stringify(result.error)}`,
    );
  }
  // The only widening in the suite, and the reason it is confined here.
  return result as unknown as { ok: true } & T;
}
