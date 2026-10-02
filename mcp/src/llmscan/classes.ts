/**
 * The closed list of vulnerability classes a hunt finding may name
 * (US-2.AC-3). A finding whose `class` is not one of these is rejected, never
 * filed under a guess: the list is what the eval graders' class families and
 * the report's grouping key on, so an open vocabulary would let a model invent
 * a class nothing downstream recognises.
 *
 * Stable kebab-case ids — they are stored (as the `rule_id` of an `llm-hunt`
 * finding) and must never be renamed; add a class, never repurpose one.
 */

export const HUNT_CLASSES = [
  // Injection families
  'sql-injection',
  'nosql-injection',
  'command-injection',
  'code-injection',
  'template-injection',
  'ldap-injection',
  'xpath-injection',
  'header-injection',
  'xxe',
  'xss',
  // Server-side request and file access
  'ssrf',
  'path-traversal',
  'open-redirect',
  // Who may do what
  'broken-access-control',
  'mass-assignment',
  'authentication',
  'csrf',
  // Data
  'sensitive-data-exposure',
  'secrets',
  'crypto-weakness',
  'deserialization',
  // Behaviour
  'business-logic',
  'dos',
  'misconfiguration',
] as const;

export type HuntClass = (typeof HUNT_CLASSES)[number];

/** D-3: the classes whose finding is stored as `high`; every other class is `medium`. Verification never changes it. */
const HIGH_SEVERITY_CLASSES: ReadonlySet<HuntClass> = new Set<HuntClass>([
  'sql-injection',
  'nosql-injection',
  'command-injection',
  'code-injection',
  'template-injection',
  'deserialization',
  'xxe',
  'ssrf',
  'path-traversal',
  'broken-access-control',
  'authentication',
  'secrets',
]);

export const huntSeverity = (cls: HuntClass): 'high' | 'medium' => (HIGH_SEVERITY_CLASSES.has(cls) ? 'high' : 'medium');
