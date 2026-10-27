/**
 * Resolve a Spring or ASP.NET method route against its class-level prefix.
 *
 *   @RestController @RequestMapping("/api/orders") class OrderController {
 *     @GetMapping("/list") …                         →  GET /api/orders/list
 *
 * No route rule can bind both halves: each is focused on the METHOD's literal
 * (`configs/semgrep/routes.yml`, "Class-level prefixes"). So the class is
 * described by separate `guardian_kind: scope` matches — its range, whether it
 * is a handler, the prefix literal, the names the ASP.NET tokens need — and
 * this module joins them to a route by byte offset, inside the one file. It is
 * the class-level counterpart of resolvers/node.ts, which joins a mount to a
 * router through an import: a prefix is never a route of its own, only the
 * thing that completes one.
 *
 * The rule is the module's whole contract: a path is returned only when every
 * fact it rests on was read, and `undefined` — the route stays `path_partial`
 * at the path it names — whenever one was not. A missing fact must cost a
 * probe, never send one to a URL that exists nowhere: a route left without its
 * prefix reads as resolved and is wrong, which is the one outcome this whole
 * pipeline is built to refuse (extract.ts's header).
 *
 * Pure: facts and routes in, a path out. extract.ts builds both from the
 * Semgrep JSON and applies its own literal test to whatever comes back.
 */

/** The `guardian_scope` roles a `scope` rule declares, in configs/semgrep/routes.yml. */
export const SCOPE_ROLES = ['type', 'handler', 'inherits', 'prefix', 'class-name', 'method', 'method-name'] as const;
export type ScopeRole = (typeof SCOPE_ROLES)[number];

/** The roles whose rule is focused, so the match binds a value: `$PATH` for a prefix, `$NAME` for a name. */
export const VALUE_ROLES: ReadonlySet<ScopeRole> = new Set<ScopeRole>(['prefix', 'class-name', 'method-name']);

export interface ScopeFact {
  role: ScopeRole;
  framework: string;
  file: string;
  /** Semgrep's byte offsets. A fact without them cannot be placed. */
  start: number | undefined;
  end: number | undefined;
  /**
   * A `prefix`: the string literal's content, quotes removed. A name: the
   * identifier. Undefined when the rule bound something else — a constant
   * (`Paths.ORDERS`), an array, an interpolation — or nothing readable.
   */
  value: string | undefined;
}

/** The join a route rule asks for, by its `guardian_class_prefix` value (extract.ts CLASS_PREFIX_KEY). */
export type ClassPrefixStyle = 'spring' | 'aspnet';

export interface ClassRoute {
  style: ClassPrefixStyle;
  framework: string;
  file: string;
  /** Start of the route's reported range: its path literal, or a bare annotation's declaration. */
  offset: number | undefined;
  /**
   * The method's own path: a string literal's content, `''` for an annotation
   * with no path. Undefined when it is not one literal, so there is nothing a
   * prefix could complete.
   */
  own: string | undefined;
}

interface Range {
  readonly start: number;
  readonly end: number;
}

interface Placed extends Range {
  readonly value: string | undefined;
}

/** The facts of one framework in one file. */
interface FileScopes {
  types: Range[];
  handlers: Range[];
  inherits: Range[];
  prefixes: Placed[];
  classNames: Placed[];
  methods: Range[];
  methodNames: Placed[];
  /**
   * A class-level fact that could not be placed: no offsets, or a prefix or
   * class name inside no type the boundary rule reported. Every route that
   * would need one is then partial — a prefix we cannot attribute is exactly a
   * prefix we might be leaving off.
   */
  unsure: boolean;
}

type ScopeIndex = ReadonlyMap<string, FileScopes>;

const NO_SCOPES: FileScopes = {
  types: [], handlers: [], inherits: [], prefixes: [], classNames: [], methods: [], methodNames: [], unsure: false,
};

function scopeKey(file: string, framework: string): string {
  return `${framework}\u0000${file}`;
}

/** Group the facts by file and framework, once per extraction. */
export function indexScopes(facts: readonly ScopeFact[]): ScopeIndex {
  const index = new Map<string, FileScopes>();
  for (const fact of facts) {
    const key = scopeKey(fact.file, fact.framework);
    let scopes = index.get(key);
    if (scopes === undefined) {
      scopes = { types: [], handlers: [], inherits: [], prefixes: [], classNames: [], methods: [], methodNames: [], unsure: false };
      index.set(key, scopes);
    }
    if (fact.start === undefined || fact.end === undefined) {
      // A method or method-name fact that cannot be placed only fails to pair,
      // and an `[action]` that finds no pair is partial on its own. Any other
      // one could be the boundary or the prefix a route's answer depends on.
      if (fact.role !== 'method' && fact.role !== 'method-name') scopes.unsure = true;
      continue;
    }
    const range = { start: fact.start, end: fact.end };
    const placed = { ...range, value: fact.value };
    switch (fact.role) {
      case 'type': scopes.types.push(range); break;
      case 'handler': scopes.handlers.push(range); break;
      case 'inherits': scopes.inherits.push(range); break;
      case 'prefix': scopes.prefixes.push(placed); break;
      case 'class-name': scopes.classNames.push(placed); break;
      case 'method': scopes.methods.push(range); break;
      case 'method-name': scopes.methodNames.push(placed); break;
    }
  }
  for (const scopes of index.values()) {
    const orphan = [...scopes.prefixes, ...scopes.classNames].some((f) => innermost(scopes.types, f.start) === undefined);
    if (orphan) scopes.unsure = true;
  }
  return index;
}

/**
 * The served path of a class-prefixed route, or undefined when it cannot be
 * known from the facts — the caller keeps the route partial at its own path.
 */
export function classRoutePath(route: ClassRoute, index: ScopeIndex): string | undefined {
  if (route.offset === undefined || route.own === undefined) return undefined;
  // A file with no fact at all still resolves what needs none: an ASP.NET
  // path rooted with `/` ignores every class route, and was resolved before
  // any of this existed.
  const scopes = index.get(scopeKey(route.file, route.framework)) ?? NO_SCOPES;
  return route.style === 'spring'
    ? springPath(route.offset, route.own, scopes)
    : aspnetPath(route.offset, route.own, scopes);
}

/* ---- Spring ------------------------------------------------------------ */

/**
 * Spring serves a mapping only from a handler, and joins that handler's own
 * type-level @RequestMapping to it (`AnnotatedElementUtils.findMergedAnnotation`
 * — the class's own first, then its supertypes'). So: the route's innermost
 * type must be a handler; its one prefix, if it has one, must be a literal;
 * with none, it must have no supertype that could carry one.
 */
function springPath(offset: number, own: string, scopes: FileScopes): string | undefined {
  if (scopes.unsure) return undefined;
  const type = innermost(scopes.types, offset);
  if (type === undefined || !sameRange(scopes.handlers, type)) return undefined;
  const prefixes = scopes.prefixes.filter((p) => innermost(scopes.types, p.start) === type);
  if (prefixes.length > 1) return undefined;
  const prefix = prefixes[0];
  if (prefix === undefined) {
    // A bare mapping with no prefix at all maps the empty pattern, whose
    // matching is Spring-version-specific; not a path to hand a probe.
    if (sameRange(scopes.inherits, type) || own === '') return undefined;
    return springJoin('', own);
  }
  // A wildcard prefix combines by pattern (`/hotels/*` + `/booking` is
  // `/hotels/booking`), not by concatenation, and is no URL either way.
  if (prefix.value === undefined || /[*?]/.test(prefix.value)) return undefined;
  return springJoin(prefix.value, own);
}

/**
 * `PathPattern.combine` / `AntPathMatcher.combine` for two literal patterns:
 * each gets the leading slash Spring prepends (`initFullPathPattern`), an
 * empty side yields the other, and a slash on both sides of the seam is kept
 * once.
 */
function springJoin(prefix: string, own: string): string | undefined {
  const lead = (p: string): string => (p === '' || p.startsWith('/') ? p : `/${p}`);
  const left = lead(prefix);
  const right = lead(own);
  if (left === '') return right === '' ? undefined : right;
  if (right === '') return left;
  return left.endsWith('/') ? `${left}${right.slice(1)}` : `${left}${right}`;
}

/* ---- ASP.NET ----------------------------------------------------------- */

/**
 * A method template starting with `/` or `~/` overrides the controller's
 * route; any other is appended to the controller's OWN `[Route]` — exactly
 * one, on a concrete class (the prefix rule excludes abstract ones). Tokens
 * are replaced after the join, as `AttributeRouteModel` does.
 */
function aspnetPath(offset: number, own: string, scopes: FileScopes): string | undefined {
  const type = innermost(scopes.types, offset);
  let template: string;
  if (isOverridePattern(own)) {
    template = own;
  } else {
    if (scopes.unsure || type === undefined) return undefined;
    const prefixes = scopes.prefixes.filter((p) => innermost(scopes.types, p.start) === type);
    const prefix = prefixes.length === 1 ? prefixes[0] : undefined;
    if (prefix?.value === undefined) return undefined;
    template = combineTemplates(prefix.value, own);
  }
  const cleaned = cleanTemplate(template);
  // `//` is the one combination CleanTemplate leaves alone, as invalid.
  if (cleaned === undefined) return undefined;
  const replaced = replaceTokens(cleaned, {
    controller: () => controllerName(type, scopes),
    action: () => actionName(offset, scopes),
  });
  return replaced === undefined ? undefined : `/${replaced}`;
}

function isOverridePattern(template: string): boolean {
  return template.startsWith('/') || template.startsWith('~/');
}

/** `AttributeRouteModel.CombineCore`, for a method template that is present. */
function combineTemplates(prefix: string, own: string): string {
  if (prefix === '' || prefix === '/' || prefix === '~/') return own;
  return prefix.endsWith('/') ? `${prefix}${own}` : `${prefix}/${own}`;
}

/** `AttributeRouteModel.CleanTemplate`: no leading `/` or `~/`, no trailing `/`. */
function cleanTemplate(template: string): string | undefined {
  if (template === '//') return undefined;
  const start = template.startsWith('/') ? 1 : template.startsWith('~/') ? 2 : 0;
  const body = template.slice(start);
  return body.endsWith('/') ? body.slice(0, -1) : body;
}

/**
 * `[controller]` and `[action]` (token names are case-insensitive, as route
 * values are). Any other token — `[area]`, whose value is an `[Area]`
 * attribute this pack does not read — and an escaped `[[` / `]]` leave the
 * template unresolved.
 */
function replaceTokens(
  template: string,
  values: { controller: () => string | undefined; action: () => string | undefined },
): string | undefined {
  if (/\[\[|\]\]/.test(template)) return undefined;
  let unresolved = false;
  const replaced = template.replace(/\[([^[\]]*)\]/g, (_token, name: string) => {
    const token = name.toLowerCase();
    const value = token === 'controller' ? values.controller() : token === 'action' ? values.action() : undefined;
    if (value === undefined || value === '') unresolved = true;
    return value ?? '';
  });
  if (unresolved || /[[\]]/.test(replaced)) return undefined;
  return replaced;
}

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** `ControllerModel.ControllerName`: the class name less a `Controller` suffix, matched ignoring case. */
function controllerName(type: Range | undefined, scopes: FileScopes): string | undefined {
  if (scopes.unsure || type === undefined) return undefined;
  const names = scopes.classNames.filter((n) => innermost(scopes.types, n.start) === type);
  const name = names.length === 1 ? names[0]?.value : undefined;
  if (name === undefined || !IDENTIFIER.test(name)) return undefined;
  return /controller$/i.test(name) ? name.slice(0, -'Controller'.length) : name;
}

/**
 * The action name: the method's, less an `Async` suffix — matched exactly,
 * as `SuppressAsyncSuffixInActionNames` (true by default since ASP.NET Core
 * 3.0) does. A method with `[ActionName]` reports no `method` range, so its
 * route finds none here.
 */
function actionName(offset: number, scopes: FileScopes): string | undefined {
  const method = innermost(scopes.methods, offset);
  if (method === undefined) return undefined;
  const names = scopes.methodNames.filter((n) => innermost(scopes.methods, n.start) === method);
  const name = names.length === 1 ? names[0]?.value : undefined;
  if (name === undefined || !IDENTIFIER.test(name)) return undefined;
  return name.endsWith('Async') ? name.slice(0, -'Async'.length) : name;
}

/* ---- geometry ---------------------------------------------------------- */

/**
 * The narrowest range holding `offset`. Ranges of declarations nest or are
 * disjoint, so the narrowest is the one that starts last; a range starting AT
 * the offset holds it (a bare annotation's match begins where its method's
 * range does — measured byte-identical on Semgrep 1.182.0).
 */
function innermost<T extends Range>(ranges: readonly T[], offset: number): T | undefined {
  let best: T | undefined;
  for (const range of ranges) {
    if (range.start > offset || offset >= range.end) continue;
    if (best === undefined || range.start > best.start || (range.start === best.start && range.end < best.end)) {
      best = range;
    }
  }
  return best;
}

function sameRange(ranges: readonly Range[], target: Range): boolean {
  return ranges.some((r) => r.start === target.start && r.end === target.end);
}
