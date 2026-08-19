// Hits for three of the four JS/TS rules. The fourth, js-dangerouslySetInnerHTML,
// needs JSX and lives in View.jsx.
//
// `new Function('a', 'b', body)` is here in its THREE-argument form on purpose.
// The rule shipped as `new Function($X)`, which matches only the one-argument
// call — and the one-argument call is the rare one. The canonical use of the
// Function constructor names its parameters first and passes the body last, so
// the shape the rule was written for was the shape real code least often has.
// Measured against the old pattern: 0 findings on this line.

export function runUserCode(source) {
  return eval(source);
}

export function compile(body) {
  return new Function('a', 'b', body);
}

export function sessionToken() {
  return Math.random().toString(36).slice(2);
}

export function render(name) {
  document.write(name);
  document.writeln(name);
}
