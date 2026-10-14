/**
 * The answer object in a model's reply text.
 *
 * A brief (prompts v5 on) asks for the working in a few lines of prose first
 * and ONE JSON object last, with nothing after it: deciding before writing the
 * object is what stopped the model committing to a verdict in the object's
 * first key and correcting itself after it (D-10, D-11). The sampling path
 * (`sampling.ts`) reads a client's reply with {@link finalAnswerObject}; the
 * eval harness (`test/evals/llmScan/driver.ts`) counts a final message's
 * objects with {@link jsonObjectsIn}, so the two agree on what an object is:
 * a non-empty JSON object, never a brace of quoted code.
 *
 * They differ on one case, on purpose. The working may quote a JSON value the
 * code handles — a request body such as `{"role":"admin"}`. The harness
 * counts it as a second object and refuses the answer (measured: 3 of 37 and
 * 4 of 40 runs of the golden hunt, v6 and v5, 2026-10-13, the same with both
 * prompts); the sampling path refuses only an earlier object that shares a
 * key with the last one — an answer and its correction — and otherwise takes
 * the object that ends the reply. The harness keeps its rule: it measures the
 * prompt, and a change there is a change of measurement conditions.
 */

type JsonObject = Record<string, unknown>;

interface Span {
  value: JsonObject;
  /** Index of its closing `}`. */
  end: number;
}

/** The index of the `}` that closes the `{` at `start`, skipping JSON strings; -1 when none does. */
function closingBrace(text: string, start: number): number {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let k = start; k < text.length; k += 1) {
    const c = text[k];
    if (inString) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') inString = false;
    } else if (c === '"') inString = true;
    else if (c === '{') depth += 1;
    else if (c === '}') {
      depth -= 1;
      if (depth === 0) return k;
    }
  }
  return -1;
}

const isObject = (v: unknown): v is JsonObject => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Every top-level JSON object in `text`, with where it ends; an empty `{}` is skipped. */
function objectSpans(text: string): Span[] {
  const out: Span[] = [];
  let i = text.indexOf('{');
  while (i !== -1) {
    const end = closingBrace(text, i);
    if (end !== -1) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(text.slice(i, end + 1)) as unknown;
      } catch {
        parsed = undefined;
      }
      if (isObject(parsed)) {
        if (Object.keys(parsed).length > 0) out.push({ value: parsed, end });
        i = text.indexOf('{', end + 1);
        continue;
      }
    }
    i = text.indexOf('{', i + 1);
  }
  return out;
}

/**
 * Every top-level JSON object in `text`, left to right; braces that do not
 * open one are skipped, and so is an empty `{}` — quoted code, never an answer.
 */
export function jsonObjectsIn(text: string): JsonObject[] {
  return objectSpans(text).map((s) => s.value);
}

/**
 * The object a reply ends with: prose may come before it and a code fence may
 * hold it, but nothing may follow it. Undefined for no object, for text after
 * the object, and for an earlier object that shares a key with it — an answer
 * and its correction: one submission, never a correction after it. An earlier
 * object with none of its keys is a value the working quotes, not an answer.
 */
export function finalAnswerObject(text: string): JsonObject | undefined {
  let body = text.trim();
  // A fence that closes the reply: its content takes its place.
  const close = /`{3}[ \t]*$/.exec(body);
  if (close !== null) {
    const open = close.index > 0 ? body.lastIndexOf('```', close.index - 1) : -1;
    if (open === -1) return undefined;
    const inner = body.slice(open + 3, close.index).replace(/^[A-Za-z]*[ \t]*\r?\n/, '');
    body = `${body.slice(0, open)}${inner}`.trim();
  }
  const spans = objectSpans(body);
  const last = spans[spans.length - 1];
  if (last === undefined || last.end !== body.length - 1) return undefined;
  const keys = Object.keys(last.value);
  const corrected = spans.slice(0, -1).some((s) => Object.keys(s.value).some((k) => keys.includes(k)));
  return corrected ? undefined : last.value;
}
