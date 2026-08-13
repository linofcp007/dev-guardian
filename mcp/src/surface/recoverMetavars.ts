/**
 * Rebuild the Semgrep metavariables that modern Semgrep refuses to emit.
 *
 * Semgrep changed behaviour between 1.95.0 and 1.120.1: unless the user has
 * run `semgrep login`, match content is redacted — `extra.metavars` is absent
 * entirely and `extra.lines` reads "requires login". `surface/extract.ts`
 * reads `extra.metavars.$PATH.abstract_content`, so on any current Semgrep
 * install `map_attack_surface` extracts zero routes while Semgrep happily
 * reports matches: nothing looks broken, and the snapshot says the
 * application exposes nothing. Requiring an account is not an option —
 * dev-guardian is 100% open-source and runs locally.
 *
 * What survives redaction is the position: `start.offset` / `end.offset`.
 * Slicing the file between them yields the exact matched source text, from
 * which the captures can be reconstructed.
 *
 * ---- Two kinds of span, and only one of them is scanned -----------------
 *
 * Scanning a span is sound only when it *starts at the construct that
 * matched*, because then the capture sits in it at a known place. Ten of the
 * thirteen route families are like that (express + its mount/import rules,
 * flask, fastapi, django, laravel, gin, net/http, spring, wp-rest,
 * aspnet-minimal) along with every `env` rule, and all of them are verified
 * capture-for-capture against Semgrep 1.86.0.
 *
 * The other three — actix, NestJS and ASP.NET attribute routes — have a pattern
 * that must swallow the decorated declaration in order to parse at all, so
 * their span can begin at a foreign attribute. Four successive attempts to
 * locate the route attribute inside such a span each FABRICATED routes: a
 * commented-out `// [HttpGet("/orders/legacy")]` between attributes became the
 * only reported endpoint while the live `/orders` never entered the inventory.
 * The general failure is that "is this text code, a comment, or a string" is
 * not local information, and the span starts mid-file.
 *
 * Those three now declare `focus-metavariable: $PATH`, which makes Semgrep
 * narrow the REPORTED RANGE to the metavariable's own range. The offsets then
 * point at the path literal itself, so recovery is "the span is the value" — no
 * anchoring, no argument parsing, nothing searched for. That is what makes the
 * defect structurally impossible rather than merely unobserved: a decoy cannot
 * be picked out of a span it is not in. Such a rule marks itself with
 * `metadata.guardian_focus: path` (see FOCUS_METADATA_KEY) and this module
 * reads that flag rather than inferring anything from the framework name — the
 * rule pack is the thing that knows whether it focused.
 *
 * The point of all this: coverage no longer depends on the Semgrep version, or
 * on being logged in. All thirteen families yield the same routes on 1.86.0
 * (real metavariables) and on 1.164.0 (redacted, rebuilt from offsets) —
 * measured over `mcp/test/fixtures/surface/apps/`, adversarial decoys included.
 *
 * A simplification deliberately NOT taken: the other ten families could be
 * focused too, which would make the scanner below redundant. They work, they
 * are verified slot-for-slot against 1.86.0, and several of them capture
 * $METHOD as a metavariable that focusing would discard — so re-opening ten
 * working families is not worth the uniformity today.
 *
 * Design: this module synthesizes into the *same shape the extractor already
 * reads* (`extra.metavars.$NAME.abstract_content`), so `extract.ts` — pure and
 * fully tested — needs no change at all. One new module, zero risk to code
 * that already passes.
 *
 * Pure: no filesystem, no process, no network. The caller supplies the source
 * text (see `tools/mapAttackSurface.ts`, which is already the impure layer).
 * It never throws: a file missing from the map, an offset past end-of-file, an
 * unparseable span all count as `unrecoverable` and the match is passed
 * through untouched.
 *
 * ---- Quoting is load-bearing -------------------------------------------
 *
 * Semgrep's `abstract_content` keeps the source quoting: a captured path
 * arrives as `'/items'`, while a computed one arrives as `self::NAMESPACE`.
 * That difference is precisely how `isLiteralPath` in `extract.ts` decides
 * whether a capture is a usable path or a code expression that must be flagged
 * `path_partial`. So every strategy below preserves the source quoting exactly
 * as it appears — adding a quote would fabricate a URL that exists nowhere,
 * stripping one would erase a route we can legitimately name.
 */

/** Source text of each file Semgrep reported, keyed by the `path` value verbatim. */
export type SourceMap = ReadonlyMap<string, string>;

export interface RecoveryOutcome {
  /** Semgrep JSON with synthesized `extra.metavars` where they were missing. */
  json: unknown;
  /** Matches that already had metavars and were left untouched. */
  intact: number;
  /** Matches whose metavars were successfully synthesized. */
  recovered: number;
  /** Matches that had no metavars and could not be recovered. */
  unrecoverable: number;
  /**
   * The `path` of every unrecoverable match whose `guardian_kind` is `route`,
   * in match order and with repeats — one entry per lost ROUTE, not per file.
   *
   * No rule family is refused any more, so this is now non-empty only for a
   * genuinely unreadable match: source that could not be read at all (absent
   * from the SourceMap), offsets past end-of-file, or a span that carries no
   * capture. Those are real losses and still must not read as "no routes here".
   *
   * Routes only, deliberately. `map_attack_surface` maps these to languages so
   * `coverage` can report "matched but unreadable" for exactly the languages it
   * happened in, and a CoverageEntry is a per-language *route* report: it sits
   * beside `routes_found`, and its sibling status `no_matches` means "no routes
   * matched". Letting a lost `env` or `import` match flip a language to
   * `unreadable` would say "routes here could not be read" when no route was
   * involved — safe in direction, but false. Those losses are not hidden: the
   * `unrecoverable` total above counts every kind and is what `tools_run`
   * reports.
   */
  unreadableRouteFiles: string[];
}

/** The shape `extract.ts`, `collectEnvVars` and `extractImports` all read. */
type Metavars = Record<string, { abstract_content: string }>;

/**
 * The `guardian_kind`s we know how to reconstruct. A match carrying no
 * `guardian_kind`, or one we have no strategy for, is left alone and counted
 * in *none* of the three totals: `extract.ts` ignores those matches anyway, so
 * calling them "unrecoverable" would manufacture a broken-toolchain signal out
 * of a rule pack that simply contains other rules.
 */
const RECOVERABLE_KINDS = new Set(['route', 'mount', 'import', 'env']);

export function recoverMetavars(semgrepJson: unknown, sources: SourceMap): RecoveryOutcome {
  const results = prop(semgrepJson, 'results');
  if (!isRecord(semgrepJson) || !Array.isArray(results)) {
    return {
      json: semgrepJson,
      intact: 0,
      recovered: 0,
      unrecoverable: 0,
      unreadableRouteFiles: [],
    };
  }

  // One encode per file, not one per match: a busy file can carry hundreds.
  const buffers = new Map<string, Buffer>();
  let intact = 0;
  let recovered = 0;
  let unrecoverable = 0;
  const unreadableRouteFiles: string[] = [];

  const rebuilt = results.map((raw) => {
    const extra = prop(raw, 'extra');
    const metadata = prop(extra, 'metadata');
    const kind = str(metadata, 'guardian_kind');
    if (kind === undefined || !RECOVERABLE_KINDS.has(kind)) return raw;

    // Real metavars are more precise than anything we can reconstruct — an
    // older Semgrep, or a logged-in one, must win.
    if (hasMetavars(extra)) {
      intact += 1;
      return raw;
    }

    const span = sliceSpan(raw, sources, buffers);
    const metavars = span === undefined ? undefined : synthesize(kind, span, metadata);
    if (metavars === undefined || !isRecord(raw)) {
      unrecoverable += 1;
      // Routes only — see the field's doc comment.
      const path = kind === 'route' ? str(raw, 'path') : undefined;
      if (path !== undefined) unreadableRouteFiles.push(path);
      return raw;
    }

    recovered += 1;
    return { ...raw, extra: { ...(isRecord(extra) ? extra : {}), metavars } };
  });

  return {
    json: { ...semgrepJson, results: rebuilt },
    intact,
    recovered,
    unrecoverable,
    unreadableRouteFiles,
  };
}

/**
 * The matched source text, sliced by BYTE offset.
 *
 * `offset` is a byte offset into the file; JavaScript string indices are
 * UTF-16 code units. Any non-ASCII character earlier in the file desyncs the
 * two, so a plain `text.slice(start, end)` silently returns the wrong span —
 * and a wrong span produces a confidently wrong route. Encode, then slice.
 */
function sliceSpan(
  raw: unknown,
  sources: SourceMap,
  buffers: Map<string, Buffer>,
): string | undefined {
  const path = str(raw, 'path');
  if (path === undefined) return undefined;

  const start = num(prop(raw, 'start'), 'offset');
  const end = num(prop(raw, 'end'), 'offset');
  if (start === undefined || end === undefined) return undefined;
  if (!Number.isInteger(start) || !Number.isInteger(end)) return undefined;
  if (start < 0 || end <= start) return undefined;

  const text = sources.get(path);
  if (text === undefined) return undefined;

  let buffer = buffers.get(path);
  if (buffer === undefined) {
    buffer = Buffer.from(text, 'utf8');
    buffers.set(path, buffer);
  }
  // Past end-of-file: the file changed under us, or the offsets are not what
  // we think they are. Either way, guessing is worse than reporting nothing.
  if (end > buffer.length) return undefined;

  const span = buffer.subarray(start, end).toString('utf8');
  return span.trim().length === 0 ? undefined : span;
}

function synthesize(kind: string, span: string, metadata: unknown): Metavars | undefined {
  switch (kind) {
    case 'route':
      return synthesizeRoute(span, metadata);
    case 'mount':
      return synthesizeMount(span);
    case 'import':
      return synthesizeImport(span, metadata);
    case 'env':
      return synthesizeEnv(span);
    default:
      return undefined;
  }
}

/**
 * The metadata key a rule sets to declare that it narrowed Semgrep's reported
 * range with `focus-metavariable`, and the only value this module acts on.
 *
 * Exported so `test/unit/surface/rulePack.test.ts` asserts the flag and the
 * `focus-metavariable` operator stay in lock-step across the two files: a rule
 * declaring one without the other fails the suite, in either direction. That
 * assertion is the successor to UNREADABLE_UNDER_REDACTION's, and it has no
 * fail-open default to guard — there is no list of frameworks any more, so an
 * unlisted framework has no wrong path to fall into.
 */
export const FOCUS_METADATA_KEY = 'guardian_focus';
export const FOCUS_PATH = 'path';

/* ---- route ---------------------------------------------------------------
 *
 * Captured shapes (Semgrep 1.164.0, multi-language fixture):
 *   app.get('/health', (req, res) => res.send('ok'))
 *   @app.route('/flask-route')
 *   http.HandleFunc("/go-route", handler)
 *   @GetMapping("/spring-route")
 *   get '/ruby-route', to: 'users#index'
 *   path(settings.ADMIN_URL, flask_route)
 *
 * Every one of those spans starts at the call or annotation that matched, so
 * the capture sits in it at a known place. A focused rule is the other kind and
 * is handled first, before any of the scanning below can touch it.
 */
function synthesizeRoute(span: string, metadata: unknown): Metavars | undefined {
  // The rule narrowed Semgrep's own reported range to $PATH, so the span IS the
  // capture — quotes and all, which is what `isLiteralPath` reads. Nothing is
  // searched for and nothing is lexed; Semgrep resolved the metavariable with a
  // real parser for the language, and a decoy elsewhere in the declaration is
  // not in this span to be found.
  //
  // This branch trusts the range, deliberately: validating it would mean
  // re-deriving what Semgrep already decided, which is the mistake the four
  // previous rounds made. Emitting the span verbatim — no trimming, no
  // repairing — is part of that. A range wider than the literal brings
  // whitespace, which `isLiteralPath` rejects; a range that ends INSIDE the
  // literal leaves the opening quote unmatched, which `stripQuotes` in
  // extract.ts now refuses to strip, so `CODE_TOKENS` rejects it too. Both land
  // as `path_partial` rather than as a confident prefix of a path we did not
  // finish reading. That is the whole safety argument for trusting the range:
  // every way it can be wrong degrades to incomplete, never to wrong.
  //
  // No $METHOD, ever: focusing discards every other capture, so a focused rule
  // declares `metadata.method` instead (the rule pack test pins that the three
  // focused families are one rule per verb). Reading a verb out of a bare path
  // literal would be pure invention.
  //
  // Checked before the wp-rest branch below, which is safe only because that
  // rule captures $NS and $ROUTE and binds no $PATH, so it can never carry this
  // flag. If wp-rest is ever reshaped to focus, this ordering must be revisited
  // — returning $PATH alone would silently drop its namespace.
  if (str(metadata, FOCUS_METADATA_KEY) === FOCUS_PATH) {
    return { $PATH: { abstract_content: span } };
  }

  const framework = str(metadata, 'framework');
  if (framework === 'wp-rest') return synthesizeNamespacedRoute(span);

  const declaredMethod = str(metadata, 'method');
  const path = routePath(span);
  if (path === undefined) return undefined;

  const metavars: Metavars = { $PATH: { abstract_content: path } };

  // $METHOD only when the rule declares no `metadata.method`. That flag is the
  // rule pack's own record of where the verb lives: a rule has to declare it
  // precisely because the verb is NOT in the callee but in the rule identity
  // (@GetMapping — see the routes.yml header). For those, synthesizing the
  // callee would be actively harmful: `GetMapping` is not a verb,
  // `normalizeMethod` returns ANY, and because extract.ts reads
  // `$METHOD ?? metadata.method` our guess would *override* the correct GET.
  if (declaredMethod === undefined) {
    const verb = calleeIdentifier(span);
    if (verb !== undefined) metavars['$METHOD'] = { abstract_content: verb };
  }
  return metavars;
}

/**
 * The path a route rule captured: the FIRST ARGUMENT of the registration
 * call, not merely the first string literal in the span.
 *
 * The distinction is load-bearing, and measured. Semgrep can report a span far
 * wider than the call that matched — an unfocused Rust attribute rule reports
 * the whole item, `#[get("/rust-route")]` *plus the function body* — and "first
 * string literal anywhere in the span" would happily pick a string out of that
 * body. Anchoring to the argument list keeps the capture where the rule bound
 * it.
 *
 * The pack's own attribute rules are focused now and never reach here, and no
 * user rule can: `map_attack_surface` runs `configs/semgrep/routes.yml` as its
 * single `--config` and discovers nothing else. (`register_custom_rules` does
 * not feed this scan — it records paths in `runtime_meta` for the SAST tools,
 * and as of today nothing reads them back, so it feeds no scan at all.) The
 * residual risk is an in-repo edit to that one file — a new declaration-
 * spanning family left unfocused — which is what the lock-step assertion in
 * `test/unit/surface/rulePack.test.ts` exists to stop.
 *
 * Two deliberate exits:
 *
 *   - No bracket at all → the first string literal. Ruby's route DSL takes no
 *     parentheses (`get '/users', to: '…'`), and that is the only shape in the
 *     pack where the path is not syntactically an argument.
 *   - A call whose argument list is empty → nothing. There was no argument to
 *     capture, so any value we produced would be invented. Semgrep 1.86.0
 *     agrees: for those spans it reports `metavars: {}`.
 *
 * When the first argument is not a string literal the path was a code
 * expression (`path(settings.ADMIN_URL, …)`, `@PostMapping(Paths.ORDERS)`). It
 * is returned *unquoted*, exactly as it reads in source, so `isLiteralPath`
 * rejects it and the route is kept but flagged `path_partial`. Dropping it
 * instead would erase real surface — the failure this design exists to prevent.
 */
function routePath(span: string): string | undefined {
  const args = argumentList(span);
  if (args !== undefined) return args[0];
  return findOpener(span) === undefined ? firstStringLiteral(span) : undefined;
}

/**
 * `register_rest_route($NS, $ROUTE, …)` — WordPress splits the namespace and
 * the route across two arguments (Semgrep cannot concatenate metavariables),
 * so both are captured verbatim, quotes included.
 *
 * `register_rest_route(self::NAMESPACE, '/computed', …)` is the dominant idiom
 * in real plugins and must survive as a `path_partial` route rather than
 * vanish — hence "verbatim": `self::NAMESPACE` stays unquoted so
 * `isLiteralPath` rejects it, and resolvers/wordpress.ts never fabricates
 * `/wp-json/self::NAMESPACE/items`.
 */
function synthesizeNamespacedRoute(span: string): Metavars | undefined {
  const args = argumentList(span);
  if (args === undefined) return undefined;
  const namespace = args[0];
  const route = args[1];
  if (namespace === undefined || route === undefined) return undefined;
  return {
    $NS: { abstract_content: namespace },
    $ROUTE: { abstract_content: route },
  };
}

/** `app.use('/api', usersRouter)` → the literal, then the next identifier. */
function synthesizeMount(span: string): Metavars | undefined {
  const literal = findStringLiteral(span);
  if (literal === undefined) return undefined;
  const router = IDENTIFIER.exec(span.slice(literal.end))?.[1];
  if (router === undefined) return undefined;
  return {
    $PREFIX: { abstract_content: literal.text },
    $ROUTER: { abstract_content: router },
  };
}

/* ---- import ---------------------------------------------------------------
 *
 * One synthesizer per stack, dispatched on `metadata.framework` — the same
 * field `extract.ts`'s route synthesis already reads for wp-rest. The eight
 * rules in `configs/semgrep/routes.yml` do not share a common span shape (a
 * quoted string, a dotted path, a `::`/`\`-separated one, a brace-delimited
 * group that Semgrep reports as a GROWING span — see the Go and Rust
 * synthesizers below), so one scanner cannot cover all of them the way the
 * route synthesizer's argument-position search does. Every synthesizer below
 * was designed against, and its shape verified byte-for-byte against, real
 * (non-redacted) Semgrep 1.86.0 output — see routes.yml's per-rule comments
 * for the measurements.
 */
function synthesizeImport(span: string, metadata: unknown): Metavars | undefined {
  switch (str(metadata, 'framework')) {
    case 'python':
      return synthesizePythonImport(span);
    case 'go':
      return synthesizeGoImport(span);
    case 'rust':
      return synthesizeRustImport(span);
    case 'php':
      return synthesizePhpImport(span);
    case 'java':
      return synthesizeJavaImport(span);
    case 'csharp':
      return synthesizeCsharpImport(span);
    case 'ruby':
      return synthesizeRubyImport(span);
    case 'esm':
    default:
      // `framework` is free text in a rule pack file a project owner can
      // edit; an unrecognised value degrades to the original (and still
      // default) ESM synthesizer rather than to `undefined`, so a typo in
      // `metadata.framework` loses precision instead of losing the match.
      return synthesizeEsmImport(span);
  }
}

/**
 * `import usersRouter from './routes/users'`,
 * `const usersRouter = require('./routes/users')`,
 * `import { usersRouter, ... } from './routes/users'` and
 * `import * as ns from './routes/users'`.
 *
 * $MODULE is emitted UNQUOTED, matching what a real (pre-redaction) run
 * reports — the rule pattern writes the quotes itself (`from "$MODULE"`), so
 * the capture binds the string contents. It matters: `resolveModuleFile` in
 * mapAttackSurface.ts tests `specifier.startsWith('.')`, and a leading quote
 * would silently disable mount resolution.
 *
 * The named-import and namespace-import branches were added alongside the
 * routes.yml rule that reads them (see that rule's comment for why a named
 * import binding several symbols still yields only the FIRST). Order matters
 * here only in that the namespace check must run before the bare-default
 * check: `import * as ns from "m"` would otherwise fail the default-import
 * regex (`*` is not an identifier character, so it already cannot match) but
 * checking the more specific shape first keeps the intent readable.
 */
function synthesizeEsmImport(span: string): Metavars | undefined {
  const literal = findStringLiteral(span);
  if (literal === undefined) return undefined;
  const module = stripQuotes(literal.text);
  if (module.length === 0) return undefined;

  const symbol =
    /\bimport\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s+from\b/.exec(span)?.[1] ??
    /\bimport\s*\{\s*([A-Za-z_$][\w$]*)/.exec(span)?.[1] ??
    /\bimport\s+([A-Za-z_$][\w$]*)\s+from\b/.exec(span)?.[1] ??
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/.exec(span)?.[1];
  if (symbol === undefined) return undefined;

  return {
    $SYMBOL: { abstract_content: symbol },
    $MODULE: { abstract_content: module },
  };
}

/**
 * `from pathlib import Path`, `from . import views`, `from .models import X`
 * and `import os`.
 *
 * `from $MODULE import $SYMBOL` covers every relative form for free — $MODULE
 * is simply whatever dotted/dotted-prefix text sits between `from` and
 * `import`, leading dots included, so `.`, `.models` and `..shared` all fall
 * out of the same regex. Multi-name imports
 * (`from fastapi import APIRouter, FastAPI`) yield the FIRST name only,
 * matching the real rule's own pattern-either limit (see routes.yml).
 *
 * `import $MODULE` (no `from`) binds $MODULE alone: Python's own semantics
 * say the bound name IS the module text, but there is no second, distinct
 * span in a bare import to capture separately as $SYMBOL, so — matching the
 * real rule exactly — none is bound. A dotted bare import (`import os.path`)
 * is out of scope: real Semgrep 1.86.0 measured that shape as matching the
 * OTHER alternative instead ($MODULE="os", $SYMBOL="path", as if it read
 * "from os import path"), a Semgrep matching quirk this function does not
 * attempt to reproduce — not required by the rule pack's own minimum form
 * list, and not present in the fixture.
 */
function synthesizePythonImport(span: string): Metavars | undefined {
  const trimmed = span.trim();

  const fromMatch = /^from\s+(\.*[\w.]*)\s+import\s+([A-Za-z_]\w*)/.exec(trimmed);
  const fromModule = fromMatch?.[1];
  const fromSymbol = fromMatch?.[2];
  if (fromModule !== undefined && fromModule.length > 0 && fromSymbol !== undefined) {
    return {
      $MODULE: { abstract_content: fromModule },
      $SYMBOL: { abstract_content: fromSymbol },
    };
  }

  const bareModule = /^import\s+([\w.]+)/.exec(trimmed)?.[1];
  if (bareModule === undefined || bareModule.length === 0) return undefined;
  return { $MODULE: { abstract_content: bareModule } };
}

/**
 * `import "net/http"`, `import myjson "encoding/json"`, and both forms again
 * inside a grouped `import ( ... )` block.
 *
 * Measured on 1.164.0: Semgrep's reported span for a grouped-block match
 * GROWS with each match rather than tightly bounding one spec — the first
 * spec's span is `import (\n\t"fmt"`, the second is
 * `import (\n\t"fmt"\n\t"os"`, and so on, always starting at `import (` and
 * ending just past the CURRENT spec. Taking the first string literal in the
 * span (the pattern every other synthesizer in this file uses) would
 * therefore recover `"fmt"` for every one of the four specs in
 * go-api/main.go's block. This synthesizer takes the LAST string literal
 * instead, which is correct for both shapes: a single (non-grouped) import's
 * span holds exactly one literal, so "last" and "only" coincide.
 *
 * The identifier immediately before that literal, if any, is the alias
 * (`myjson` in `import myjson "encoding/json"`). For an unaliased spec the
 * preceding token is either the `import` keyword itself (single form) or a
 * bracket/previous-literal's closing quote (grouped form) — neither is a
 * bindable identifier, so $SYMBOL is correctly left unbound, matching what
 * Go's own syntax makes available: an unaliased import's local package name
 * lives in the TARGET package's own source, not in the importing statement.
 */
function synthesizeGoImport(span: string): Metavars | undefined {
  const literals = allStringLiterals(span);
  const last = literals[literals.length - 1];
  if (last === undefined) return undefined;
  const module = stripQuotes(last.text);
  if (module.length === 0) return undefined;

  const metavars: Metavars = { $MODULE: { abstract_content: module } };
  const before = span.slice(0, last.start);
  const alias = /([A-Za-z_]\w*)\s*$/.exec(before)?.[1];
  if (alias !== undefined && alias !== 'import') {
    metavars['$SYMBOL'] = { abstract_content: alias };
  }
  return metavars;
}

/**
 * `use crate::models::User;` and, one match per item, `use actix_web::{web,
 * App, HttpServer};`.
 *
 * Grouped spans grow exactly the way Go's do (measured on 1.164.0): the first
 * item's span is `use actix_web::{web`, the second is
 * `use actix_web::{web, App`, and so on — always starting at `use $MODULE::{`
 * and ending just past the CURRENT item. Splitting the text after `{` on
 * commas and taking the LAST piece recovers the current item for every span
 * in the sequence; taking the first would recover `web` four times over.
 *
 * The single-item form has no brace at all, so it takes the other branch:
 * split on the LAST `::` into $MODULE (everything before) and $SYMBOL
 * (everything after). When $MODULE itself spans more than one segment
 * (`crate::models`), the `::` separators inside it are replaced with a single
 * space to match Semgrep's own `abstract_content` rendering for a
 * multi-segment path capture — measured, not a choice made here (see the
 * rule's comment in routes.yml).
 */
function synthesizeRustImport(span: string): Metavars | undefined {
  const trimmed = span.replace(/;\s*$/, '').trim();
  const braceIdx = trimmed.indexOf('{');

  if (braceIdx !== -1) {
    const modulePath = trimmed.slice(0, braceIdx).replace(/^use\s+/, '').replace(/::\s*$/, '');
    const items = trimmed
      .slice(braceIdx + 1)
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
    const symbol = items[items.length - 1];
    if (modulePath.length === 0 || symbol === undefined || symbol.length === 0) return undefined;
    return {
      $MODULE: { abstract_content: modulePath.replace(/::/g, ' ') },
      $SYMBOL: { abstract_content: symbol },
    };
  }

  const withoutKeyword = trimmed.replace(/^use\s+/, '');
  const lastSep = withoutKeyword.lastIndexOf('::');
  if (lastSep === -1) return undefined;
  const modulePath = withoutKeyword.slice(0, lastSep);
  const symbol = withoutKeyword.slice(lastSep + 2);
  if (modulePath.length === 0 || symbol.length === 0) return undefined;
  return {
    $MODULE: { abstract_content: modulePath.replace(/::/g, ' ') },
    $SYMBOL: { abstract_content: symbol },
  };
}

/**
 * `use App\Http\Controllers\OrderController;` — splits at the LAST `\`, the
 * class name becomes $SYMBOL and the namespace prefix becomes $MODULE, its
 * own internal `\` separators replaced with a single space to match
 * Semgrep's own `abstract_content` rendering for a multi-segment capture
 * (`App Http Controllers`, not `App\Http\Controllers`) — measured, not a
 * choice made here.
 */
function synthesizePhpImport(span: string): Metavars | undefined {
  const trimmed = span.replace(/;\s*$/, '').trim();
  const path = /^use\s+(\S+)$/.exec(trimmed)?.[1];
  if (path === undefined) return undefined;

  const lastSep = path.lastIndexOf('\\');
  if (lastSep === -1) return undefined;
  const modulePath = path.slice(0, lastSep);
  const symbol = path.slice(lastSep + 1);
  if (modulePath.length === 0 || symbol.length === 0) return undefined;
  return {
    $MODULE: { abstract_content: modulePath.replace(/\\/g, ' ') },
    $SYMBOL: { abstract_content: symbol },
  };
}

/**
 * `import java.util.List;`, `import static java.util.Collections.emptyList;`
 * and `import com.example.util.*;`.
 *
 * No $SYMBOL for any of the three — see the rule's comment in routes.yml for
 * why a two-metavariable split was tried and abandoned (it mis-split the
 * wildcard form). $MODULE is the qualified name verbatim, `static ` stripped
 * from the front and a trailing `.*` stripped from the back before joining —
 * the on-demand `.*` is not part of the qualified-name node Semgrep binds, so
 * `import com.example.util.*;` recovers the same $MODULE
 * (`com example util`) a real run reports, not `com example util *`. Internal
 * `.` separators become a single space, matching Semgrep's own
 * `abstract_content` rendering for a multi-segment capture — measured, not a
 * choice made here.
 */
function synthesizeJavaImport(span: string): Metavars | undefined {
  const trimmed = span.replace(/;\s*$/, '').trim();
  const match = /^import\s+(static\s+)?(.+)$/.exec(trimmed);
  const path = match?.[2];
  if (path === undefined) return undefined;

  const qualifiedName = path.trim().replace(/\.\*$/, '');
  if (qualifiedName.length === 0) return undefined;
  return { $MODULE: { abstract_content: qualifiedName.replace(/\./g, ' ') } };
}

/**
 * `using System.Collections.Generic;` (plain) and
 * `using Json = System.Text.Json.JsonSerializer;` (aliased).
 *
 * Measured on 1.164.0: the plain form's span includes the trailing `;`; the
 * aliased form's does not. Both are handled by trimming an optional trailing
 * `;` up front rather than relying on either shape.
 *
 * Plain `using` binds $MODULE only — see the rule's comment in routes.yml for
 * why a `$MODULE.$SYMBOL`-shaped split was tried and abandoned (it split at
 * the FIRST segment instead of the last, backwards relative to
 * PHP/Java/Rust). Aliased `using` gives a real, distinct $SYMBOL for free:
 * the alias IS the bound name, no split needed. Either way, when $MODULE
 * spans more than one segment its internal `.` separators become a single
 * space, matching Semgrep's own `abstract_content` rendering for a
 * multi-segment capture — measured, not a choice made here.
 */
function synthesizeCsharpImport(span: string): Metavars | undefined {
  const trimmed = span.replace(/;\s*$/, '').trim();

  const aliasMatch = /^using\s+([A-Za-z_]\w*)\s*=\s*(.+)$/.exec(trimmed);
  const aliasSymbol = aliasMatch?.[1];
  const aliasModule = aliasMatch?.[2];
  if (aliasSymbol !== undefined && aliasModule !== undefined && aliasModule.length > 0) {
    return {
      $SYMBOL: { abstract_content: aliasSymbol },
      $MODULE: { abstract_content: aliasModule.replace(/\./g, ' ') },
    };
  }

  const plainModule = /^using\s+(.+)$/.exec(trimmed)?.[1];
  if (plainModule === undefined || plainModule.length === 0) return undefined;
  return { $MODULE: { abstract_content: plainModule.replace(/\./g, ' ') } };
}

/**
 * `require "net/http"`, `require_relative "./user"` and `load "tasks.rb"`.
 *
 * $MODULE only: none of the three Ruby forms binds a local name — that is
 * Ruby's own semantics (`require` runs the file; it does not introduce a
 * scoped identifier the way an `import` or `use` statement does), not a gap
 * in this synthesizer. The span holds exactly one string literal, so the
 * same first-literal scan every other synthesizer in this file uses is
 * already correct here — no Go/Rust-style "last literal" handling is needed
 * because there is nothing else in the span to compete with it.
 */
function synthesizeRubyImport(span: string): Metavars | undefined {
  const literal = findStringLiteral(span);
  if (literal === undefined) return undefined;
  const module = stripQuotes(literal.text);
  if (module.length === 0) return undefined;
  return { $MODULE: { abstract_content: module } };
}

/**
 * `process.env.API_KEY` → `API_KEY` (unquoted, as the real run reports it);
 * `os.environ['DATABASE_URL']` / `getenv('SECRET_KEY')` /
 * `Environment.GetEnvironmentVariable("X")` → the first argument, quotes kept.
 * `collectEnvVars` strips quotes either way, so both forms land as one name.
 */
function synthesizeEnv(span: string): Metavars | undefined {
  const arg = firstArgument(span);
  if (arg !== undefined) return { $NAME: { abstract_content: arg } };
  const member = /\.([A-Za-z_$][\w$]*)\s*$/.exec(span.trim())?.[1];
  if (member === undefined) return undefined;
  return { $NAME: { abstract_content: member } };
}

/* ---- span scanning -------------------------------------------------------
 *
 * Deliberately a scanner, not a parser: it has to cope with nine languages
 * from one code path, and every strategy above degrades to `unrecoverable`
 * rather than to a wrong answer. It tracks exactly two things — string
 * literals (so a comma or bracket inside one is not punctuation) and bracket
 * depth.
 */

const IDENTIFIER = /([A-Za-z_$][\w$]*)/;
const CLOSERS: Record<string, string> = { '(': ')', '[': ']', '{': '}' };

function isQuote(ch: string): boolean {
  return ch === "'" || ch === '"' || ch === '`';
}

/** Index just past the closing quote of the literal starting at `start`. */
function skipString(text: string, start: number): number {
  const quote = text[start];
  let i = start + 1;
  while (i < text.length) {
    const ch = text[i];
    if (ch === undefined) break;
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === quote) return i + 1;
    i += 1;
  }
  return text.length;
}

interface Literal {
  /** The literal WITH its quotes — the quoting is what extract.ts reads. */
  text: string;
  /** Index just past the closing quote. */
  end: number;
}

function findStringLiteral(span: string, from = 0): Literal | undefined {
  let i = from;
  while (i < span.length) {
    const ch = span[i];
    if (ch === undefined) break;
    if (isQuote(ch)) {
      const end = skipString(span, i);
      return { text: span.slice(i, end), end };
    }
    i += 1;
  }
  return undefined;
}

function firstStringLiteral(span: string): string | undefined {
  return findStringLiteral(span)?.text;
}

/**
 * Every string literal in the span, in source order, each tagged with its
 * own start index — `findStringLiteral` only reports where a literal ENDS,
 * which is enough to keep scanning past it but not enough to know where the
 * one just found begins. `synthesizeGoImport` needs the start of the LAST
 * literal to find what (if anything) immediately precedes it.
 */
function allStringLiterals(span: string): Array<Literal & { start: number }> {
  const out: Array<Literal & { start: number }> = [];
  let from = 0;
  while (from < span.length) {
    const found = findStringLiteral(span, from);
    if (found === undefined) break;
    out.push({ ...found, start: found.end - found.text.length });
    from = found.end;
  }
  return out;
}

/**
 * Where the argument list starts: the first `(`, or the first `[` when the
 * span has no parentheses at all (`process.env['DB_URL']`, `$_ENV['KEY']`).
 * Preferring `(` is what makes an attribute span work — `#[get("/x")]` and
 * `[HttpGet("/x")]` both open with a bracket that is not the argument list.
 */
function findOpener(span: string): number | undefined {
  let bracket = -1;
  let i = 0;
  while (i < span.length) {
    const ch = span[i];
    if (ch === undefined) break;
    if (isQuote(ch)) {
      i = skipString(span, i);
      continue;
    }
    if (ch === '(') return i;
    if (ch === '[' && bracket < 0) bracket = i;
    i += 1;
  }
  return bracket >= 0 ? bracket : undefined;
}

/** Index of the bracket closing the one at `open`, or undefined if unbalanced. */
function matchingClose(span: string, open: number): number | undefined {
  const stack: string[] = [];
  let i = open;
  while (i < span.length) {
    const ch = span[i];
    if (ch === undefined) break;
    if (isQuote(ch)) {
      i = skipString(span, i);
      continue;
    }
    const closer = CLOSERS[ch];
    if (closer !== undefined) {
      stack.push(closer);
      i += 1;
      continue;
    }
    if (ch === ')' || ch === ']' || ch === '}') {
      const expected = stack.pop();
      if (expected !== ch) return undefined;
      if (stack.length === 0) return i;
    }
    i += 1;
  }
  return undefined;
}

/** Split at top-level commas — not those inside quotes, brackets or parens. */
function splitTopLevel(inner: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  let i = 0;
  while (i < inner.length) {
    const ch = inner[i];
    if (ch === undefined) break;
    if (isQuote(ch)) {
      i = skipString(inner, i);
      continue;
    }
    if (CLOSERS[ch] !== undefined) depth += 1;
    else if (ch === ')' || ch === ']' || ch === '}') depth -= 1;
    else if (ch === ',' && depth === 0) {
      parts.push(inner.slice(start, i).trim());
      start = i + 1;
    }
    i += 1;
  }
  parts.push(inner.slice(start).trim());
  return parts.filter((part) => part.length > 0);
}

/** The arguments of the bracket that opens at `open`. */
function argumentsAt(span: string, open: number): string[] | undefined {
  const close = matchingClose(span, open);
  if (close === undefined) return undefined;
  const args = splitTopLevel(span.slice(open + 1, close));
  return args.length > 0 ? args : undefined;
}

function argumentList(span: string): string[] | undefined {
  const open = findOpener(span);
  if (open === undefined) return undefined;
  return argumentsAt(span, open);
}

function firstArgument(span: string): string | undefined {
  return argumentList(span)?.[0];
}

/**
 * The verb when it lives in the callee: the identifier immediately before the
 * `(` that opens the matched call — `app.get(` → `get`, `Route::get(` → `get`,
 * `r.GET(` → `GET`, `app.MapGet(` → `MapGet`. `normalizeMethod` in extract.ts
 * handles case and the ASP.NET `Map*` form, so the raw identifier is emitted.
 *
 * Ruby's route DSL has no parentheses at all (`get '/users', to: '…'`), so the
 * leading word of the span is the fallback — without it every Rails route
 * would degrade to ANY, since that rule declares no `metadata.method`.
 */
function calleeIdentifier(span: string): string | undefined {
  const open = findOpener(span);
  if (open !== undefined && span[open] === '(') {
    const callee = /([A-Za-z_$][\w$]*)\s*$/.exec(span.slice(0, open))?.[1];
    if (callee !== undefined) return callee;
  }
  return /^\s*([A-Za-z_][\w]*)\s+['"`]/.exec(span)?.[1];
}

function stripQuotes(value: string): string {
  return value.replace(/^['"`]|['"`]$/g, '');
}

/* ---- structural accessors (same shape as extract.ts's, kept local so the
   two modules stay independently readable) ---- */

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function prop(value: unknown, key: string): unknown {
  if (value === null || typeof value !== 'object') return undefined;
  return (value as Record<string, unknown>)[key];
}

function str(value: unknown, key: string): string | undefined {
  const v = prop(value, key);
  return typeof v === 'string' ? v : undefined;
}

function num(value: unknown, key: string): number | undefined {
  const v = prop(value, key);
  return typeof v === 'number' ? v : undefined;
}

/** An empty `metavars: {}` counts as missing — there is nothing to preserve. */
function hasMetavars(extra: unknown): boolean {
  const metavars = prop(extra, 'metavars');
  if (!isRecord(metavars)) return false;
  return Object.keys(metavars).length > 0;
}
