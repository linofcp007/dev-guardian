// Near-misses for the JS/TS rules. Every line is correct code that resembles
// the bug closely enough that a sloppier version of the rule would flag it.

// js-insecure-randomness is `Math.random()`, a CALL. A reference to the
// function without calling it is not a use of the value, and this is silent
// BECAUSE of the parentheses — change the pattern to `Math.random` and it
// fires. The crypto call below is the correct replacement the message names.
export const generator = Math.random;
export function secureToken() {
  return crypto.getRandomValues(new Uint8Array(16));
}

// js-document-write pins the receiver. A `write` on anything else — a stream, a
// mock, a wrapper called `doc` — is a different API. Silent BECAUSE of the
// `document.` qualifier: `$O.write($X)` would flag all three.
export function pipe(stream, chunk, doc, name) {
  stream.write(chunk);
  doc.write(name);
  process.stdout.write(name);
}

// js-eval-of-user-input matches the identifiers `eval` and `Function` as AST
// nodes, not as substrings of a name. Silent BECAUSE semgrep matches the tree;
// a grep-based rule would flag every line here.
export function score(input) {
  return evalScore(input) + reevaluate(input);
}
export function build(source) {
  return new FunctionFactory(source);
}

// The safe counterparts of the two output rules.
export function hydrate(element, input) {
  element.textContent = JSON.parse(input).label;
}
