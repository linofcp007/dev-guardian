/**
 * Folds: one listed tool for a family of tools, with the family's own names
 * kept as hidden aliases.
 *
 * `tools/list` is in the model's context in every session of a host that
 * loads it up front (Cursor, Windsurf, Copilot) and per search hit in Claude
 * Code. Ten WordPress tools, four .NET tools and a three-step LLM-scan
 * protocol each cost a full entry — a description, a title, a schema with
 * its own `project_path` — for what is one decision ("which WordPress
 * check?"). A fold lists one tool whose `modeKey` parameter (`check`, `mode`,
 * `kind`, `action`, `view`) picks the member, and runs that member's handler
 * with that member's own validation:
 *
 *   - every member name still answers `tools/call`, with its own schema —
 *     registered as before, `listed: false` — so a script, a saved prompt or
 *     a host permission written for the old name keeps working;
 *   - a fold that keeps a member's name (the head: `wp_audit`, `diff_scans`,
 *     …) makes that member the default mode, so every old call of the head
 *     is unchanged;
 *   - a parameter another mode takes is refused (`invalid_input`, naming
 *     what the mode takes), never ignored: the members are strict, and so is
 *     the fold;
 *   - a fold groups tools of one risk class only. Claude Code asks
 *     permission per tool name, so a read-only report never shares a name
 *     with a tool that installs, pushes or probes a live target, and the
 *     fold's annotations (`./annotations.ts`) must cover every member's:
 *     read-only only when all are, destructive or open-world when any is
 *     (`toolFolds.test.ts`).
 *
 * `FOLDS` lists the folds for the generated `docs/tools.md` and the tests.
 */

import { z, ZodDefault, ZodEnum, type ZodRawShape, type ZodTypeAny } from 'zod';
import type { ToolResult } from '../types.js';
import { registerToolModule, strictInputSchema, TOOLS, type ToolModule } from './index.js';

export interface FoldSpec {
  /** The listed name — a member's own name (the head) or a new one. */
  name: string;
  title: string;
  description: string;
  /** The parameter that picks the member. */
  modeKey: string;
  /** What each value of `modeKey` runs. */
  modeDescription: string;
  /** Value of `modeKey` → the member tool's name. */
  modes: Readonly<Record<string, string>>;
  /** Required when the fold keeps a member's name: that member's mode, used when `modeKey` is omitted. */
  defaultMode?: string;
  /** The fold's own description of a merged parameter, where the member's does not fit the family. */
  params?: Readonly<Record<string, string>>;
}

export interface FoldRecord {
  name: string;
  modeKey: string;
  modes: Readonly<Record<string, string>>;
  defaultMode?: string;
}

/** Every registered fold, in registration order. */
export const FOLDS: FoldRecord[] = [];

const WRAPPERS = new Set(['ZodOptional', 'ZodDefault', 'ZodNullable', 'ZodEffects']);

/** The type under the optional / default / nullable wrappers. */
function base(field: ZodTypeAny): ZodTypeAny {
  let cur = field;
  for (;;) {
    const def = cur._def as { typeName?: string; innerType?: ZodTypeAny; schema?: ZodTypeAny };
    if (def.typeName === undefined || !WRAPPERS.has(def.typeName)) return cur;
    const next = def.innerType ?? def.schema;
    if (next === undefined) return cur;
    cur = next;
  }
}

/**
 * A member's parameter as the fold lists it: optional (a mode decides what it
 * requires), and with no default — a default would put the key into every
 * call, and the mode that does not take it would then refuse the call. The
 * member's own parse applies its defaults.
 */
function asFoldParam(field: ZodTypeAny, description: string | undefined): ZodTypeAny {
  const inner = field instanceof ZodDefault ? (field.removeDefault() as ZodTypeAny) : field;
  const optional = inner.isOptional() ? inner : inner.optional();
  return description !== undefined ? optional.describe(description) : optional;
}

function invalid(message: string): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code: 'invalid_input', message } };
}

export function registerFold(spec: FoldSpec): ToolModule {
  const members = new Map<string, ToolModule>();
  for (const [mode, memberName] of Object.entries(spec.modes)) {
    const member = TOOLS.find((t) => t.name === memberName);
    if (member === undefined) throw new Error(`fold ${spec.name}: member '${memberName}' is not registered`);
    members.set(mode, member);
  }
  const modeValues = [...members.keys()];
  const [firstMode, ...otherModes] = modeValues;
  if (firstMode === undefined) throw new Error(`fold ${spec.name}: no modes`);
  const headIndex = TOOLS.findIndex((t) => t.name === spec.name);
  if (headIndex >= 0 && (spec.defaultMode === undefined || spec.modes[spec.defaultMode] !== spec.name)) {
    throw new Error(`fold ${spec.name} keeps a member's name, so that member must be its defaultMode`);
  }
  if (spec.defaultMode !== undefined && !members.has(spec.defaultMode)) {
    throw new Error(`fold ${spec.name}: defaultMode '${spec.defaultMode}' is not one of its modes`);
  }

  const modeField = z.enum([firstMode, ...otherModes]);
  const shape: ZodRawShape = {
    [spec.modeKey]: (spec.defaultMode !== undefined ? modeField.optional() : modeField).describe(spec.modeDescription),
  };
  for (const member of members.values()) {
    for (const [key, field] of Object.entries(member.inputSchema)) {
      if (key === spec.modeKey) throw new Error(`fold ${spec.name}: member ${member.name} already takes '${key}'`);
      const seen = shape[key];
      if (seen !== undefined) {
        const [a, b] = [base(seen), base(field)];
        const typeA = (a._def as { typeName?: string }).typeName;
        const typeB = (b._def as { typeName?: string }).typeName;
        const sameEnum =
          !(a instanceof ZodEnum) ||
          !(b instanceof ZodEnum) ||
          JSON.stringify(a.options) === JSON.stringify(b.options);
        if (typeA !== typeB || !sameEnum) {
          throw new Error(`fold ${spec.name}: '${key}' has different types in its members`);
        }
        continue;
      }
      shape[key] = asFoldParam(field, spec.params?.[key] ?? field.description);
    }
  }
  for (const key of Object.keys(spec.params ?? {})) {
    if (shape[key] === undefined) throw new Error(`fold ${spec.name}: no member takes '${key}'`);
  }

  const pick = (input: Record<string, unknown>): ToolModule | undefined => {
    const mode = input[spec.modeKey] ?? spec.defaultMode;
    return typeof mode === 'string' ? members.get(mode) : undefined;
  };

  const fold: ToolModule = {
    name: spec.name,
    title: spec.title,
    description: spec.description,
    inputSchema: shape,
    route: pick,
    handler: async (input, ctx, callMeta) => {
      const member = pick(input);
      const mode = String(input[spec.modeKey] ?? spec.defaultMode ?? '');
      if (member === undefined) {
        return invalid(`${spec.name} needs ${spec.modeKey}: one of ${modeValues.map((v) => `"${v}"`).join(', ')}`);
      }
      const rest = Object.fromEntries(
        Object.entries(input).filter(([key, value]) => key !== spec.modeKey && value !== undefined),
      );
      const takes = Object.keys(member.inputSchema);
      const foreign = Object.keys(rest).filter((key) => !takes.includes(key));
      if (foreign.length > 0) {
        return invalid(
          `${spec.name} {${spec.modeKey}: "${mode}"} does not take ${foreign.join(', ')}; ` +
            (takes.length > 0 ? `it takes ${takes.join(', ')}` : 'it takes no other parameter'),
        );
      }
      const parsed = await strictInputSchema(member).safeParseAsync(rest);
      if (!parsed.success) {
        const why = parsed.error.issues.map((i) => `${i.path.join('.') || 'input'}: ${i.message}`).join('; ');
        return invalid(`${spec.name} {${spec.modeKey}: "${mode}"}: ${why}`);
      }
      return member.handler(parsed.data, ctx, callMeta);
    },
  };

  // The head leaves the registry: the fold answers its name, and runs it as the default mode.
  if (headIndex >= 0) TOOLS.splice(headIndex, 1);
  for (const member of members.values()) {
    if (member.name !== spec.name) member.listed = false;
  }
  // Listed where the head, or the family's first member, was.
  const at = headIndex >= 0 ? headIndex : Math.min(...[...members.values()].map((m) => TOOLS.indexOf(m)));
  registerToolModule(fold);
  const added = TOOLS.pop();
  if (added !== undefined) TOOLS.splice(at, 0, added);

  FOLDS.push({
    name: spec.name,
    modeKey: spec.modeKey,
    modes: { ...spec.modes },
    ...(spec.defaultMode !== undefined ? { defaultMode: spec.defaultMode } : {}),
  });
  return fold;
}
