export function readsPastEnd(items: number[]): void {
  for (let i = 0; i <= items.length; i++) { console.log(items[i]); }
}

// The SAME bug one pair of braces away, and silent until this wave: the
// old pattern required a block body (`... ) { ... }`), so a braceless
// single-statement body was invisible. Auditor's p04 FN-1, isolated in
// iso/i1.ts [F].
export function readsPastEndBraceless(items: number[]): void {
  for (let i = 0; i <= items.length; i++) console.log(items[i]);
}
