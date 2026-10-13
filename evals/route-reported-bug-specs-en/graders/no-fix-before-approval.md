---
type: regex
target: trace
match: not_contains
pattern: '"name":"(?:Write|Edit|MultiEdit)","input":\{"file_path":"[^"]*cart\.js"'
---
In dev-spec-driven's bugfix flow the fix waits for the approved `bug.md` and a failing regression test; no human
approves inside one run, so `src/cart.js` is not edited.
