/**
 * Every suppression example the prose shows names its rule and gives the
 * reason (review 1, R1-DG-IZ-4). An agent copies the example it reads, and a
 * bare one is what `guardian-suppressions` reports: a `# nosec`-shaped
 * example, the same in docs/hooks.md, the router's dev-spec-driven reference
 * or the question the shell guard asks, survived every test (the guard's only
 * through the dist drift), and the bug pack's coverage reference said "with a
 * reason" next to a directive that named no rule.
 *
 * Held by property over every file of the prose surface (`proseFiles()`: the
 * skills, commands, docs, host rules, READMEs and the prose strings of
 * `mcp/src`, the CLI and the hooks), with the pass's own reader as the judge
 * — and that reader read both ways here: it takes the documented forms as
 * complete, and reports the bare directive. How a span is picked and judged:
 * `suppressionExamples.ts`.
 *
 * No directive is written in this file: each is built, since a test source
 * holding a bare one would be a real suppression on dev-guardian's own
 * branches (docs/maintainers/architecture.md).
 */

import { describe, expect, it } from 'vitest';
import { proseFiles } from './pluginDocs.js';
import { examplesIn, exampleProblems, judge, proseUnits, sentences } from './suppressionExamples.js';

const NOSEC = ['no', 'sec'].join('');
const SEMGREP_WORD = ['no', 'semgrep'].join('');
const BANDIT = `# ${NOSEC} <id>  # <reason>`;
const SEMGREP = `${SEMGREP_WORD}: <rule> -- <reason>`;
const BARE = `# ${NOSEC}`;

/** The problems of one file's text. */
const problemsOf = (rel: string, text: string): string[] => exampleProblems([{ rel, text }]);

describe("the pass's reader judges an example both ways", () => {
  it('takes the documented forms as complete: each names its rule and gives the reason', () => {
    for (const span of [SEMGREP, BANDIT, `// ${SEMGREP}`, `# ${NOSEC} B602  # <reason>`, `#${NOSEC} G304 -- <reason>`, `${SEMGREP_WORD}: <regla> -- <motivo>`]) {
      expect(judge(span), span).toEqual({ complete: true, why: '' });
    }
  });

  it('reports the bare directive, and holds a rule alone, a reason alone and a form no scanner reads to what they lack', () => {
    expect(judge(BARE).why).toBe('names no rule and gives no reason');
    expect(judge(SEMGREP_WORD).why).toBe('names no rule and gives no reason');
    expect(judge(`# ${NOSEC} B602`).why).toBe('gives no reason');
    expect(judge(`${SEMGREP_WORD}: <rule>`).why).toBe('gives no reason');
    expect(judge(`# ${NOSEC}  # <reason>`).why).toBe('names no rule');
    expect(judge(`${SEMGREP_WORD} -- <reason>`).why).toBe('names no rule');
    // Semgrep reads a blank-led directive only: this one suppresses nothing, so it is no example either.
    expect(judge(`//${SEMGREP}`).why).toBe('is read by no scanner dev-guardian runs');
  });
});

describe('the sentences that offer a form, and those that only name one', () => {
  it('a sentence that asks for the reason, or shows one complete form, offers every form it shows', () => {
    expect(problemsOf('a.md', `Suppress it inline with a reason (\`${BARE}\`).`)).toHaveLength(1);
    expect(problemsOf('a.md', `Suppress it where its scanner reads it (\`${SEMGREP}\`, \`${BARE}\`).`)).toHaveLength(1);
    expect(problemsOf('a.md', `Otherwise \`// ${SEMGREP_WORD}\` with a reason.`)).toHaveLength(1);
    expect(problemsOf('a.md', `Suppress it inline with a reason (\`${SEMGREP}\`, \`${BANDIT}\`).`)).toEqual([]);
  });

  // Review 2 (R2-DG-HZ-2): only the English "with a reason" asked for one, so "Suprima-o com um motivo (`# nosec`)"
  // offered nothing and its bare form passed.
  it('a Portuguese or Spanish sentence that asks for the reason offers its forms too; one that says "without" offers none', () => {
    expect(problemsOf('a.md', `Suprima-o com um motivo (\`${BARE}\`).`)).toHaveLength(1);
    expect(problemsOf('a.md', `Suprima-o com uma razão (\`${BARE}\`).`)).toHaveLength(1);
    expect(problemsOf('a.md', `Suprímelo con un motivo (\`${BARE}\`).`)).toHaveLength(1);
    expect(problemsOf('a.md', `Suprímelo con una razón (\`${BARE}\`).`)).toHaveLength(1);
    expect(problemsOf('a.md', `Suprima-o com um motivo (\`${SEMGREP_WORD}: <regra> -- <motivo>\`).`)).toEqual([]);
    // The READMEs' own sentences that name what is reported.
    expect(problemsOf('a.md', `Uma supressão nova sem razão (um \`${SEMGREP_WORD}\` ou \`${BARE}\` sem mais) é reportada.`)).toEqual([]);
    expect(problemsOf('a.md', `Una supresión nueva sin motivo (un \`${SEMGREP_WORD}\` o \`${BARE}\` sin más) se informa.`)).toEqual([]);
  });

  it('a sentence that names the bare forms offers none; a sentence ends at its period, a block at a blank line', () => {
    expect(problemsOf('a.md', `A new suppression with no reason (a bare \`${SEMGREP_WORD}\` or \`${BARE}\`) is reported.`)).toEqual([]);
    expect(problemsOf('a.md', `A directive naming its rule (\`${SEMGREP_WORD}: <rule-id>\`, \`# ${NOSEC} B602\`) is counted.`)).toEqual([]);
    expect(problemsOf('a.md', `Suppress it inline with a reason (\`${SEMGREP}\`). The pass reports a bare \`${BARE}\`.`)).toEqual([]);
    expect(problemsOf('a.md', `Suppress it inline with a reason (\`${SEMGREP}\`)\n\nA bare \`${BARE}\` is reported`)).toEqual([]);
    expect(sentences('One `a. b` here. Two.').map((s) => s.spans)).toEqual([['a. b'], []]);
    // A span keeps its blanks (the form shown is the form copied); a line end inside it reads as one blank.
    expect(sentences('Write `x  y` or `p\n  q`.')[0]?.spans).toEqual(['x  y', 'p q']);
  });

  it('a fenced block is not read; a source file is read by its strings, the pieces a `+` joins as one, a template cooked', () => {
    expect(problemsOf('a.md', `\`\`\`text\nSuppress it with a reason (\`${BARE}\`).\n\`\`\``)).toEqual([]);
    expect(problemsOf('a.ts', `const a = 'Suppress it inline with a reason ' +\n  '(\`${BARE}\`).';`)).toHaveLength(1);
    expect(problemsOf('a.mjs', `const b = \`Suppress it with a reason (\\\`${BARE}\\\`) in \${where}.\`;`)).toHaveLength(1);
    expect(problemsOf('a.ts', `const c = \`Suppress it with a reason (\\\`${BARE}\\\`).\`;`)).toHaveLength(1);
    // A comment is not a string.
    expect(problemsOf('a.ts', `// Suppress it with a reason (\`${BARE}\`).\nconst d = 1;`)).toEqual([]);
    expect(proseUnits('a.ts', "const e = 'x' + y + 'z';")).toEqual(['x${…}z']);
    // A hole is read too: a string inside it is prose of its own.
    expect(problemsOf('a.ts', `const f = \`Note: \${ok ? '' : 'Suppress it with a reason (\`${BARE}\`).'}\`;`)).toHaveLength(1);
  });
});

describe('every `nosec` / `nosemgrep` example in the prose names its rule and gives the reason', () => {
  const files = proseFiles();
  const examples = examplesIn(files);

  it('finds the examples where the prose shows them (a reader that finds none fails here)', () => {
    const where = new Set(examples.map((x) => x.rel));
    for (const rel of [
      'docs/ci.md',
      'docs/hooks.md',
      'skills/guardian/references/dev-spec.md',
      'skills/guardian-bugfix/references/coverage.md',
      'host-rules/AGENTS.md',
      'README.md',
      // R2-DG-HZ-2: the other two READMEs show one too (`<regra> -- <motivo>`, `<regla> -- <motivo>`).
      'README.pt-PT.md',
      'README.es.md',
      'cli/dev-guardian.mjs',
      'mcp/src/hooks/bashGuard.ts',
      'mcp/src/hostsetup/rulesTemplate.ts',
    ]) {
      expect(where.has(rel), rel).toBe(true);
    }
  });

  it('each one is complete', () => {
    expect(exampleProblems(files)).toEqual([]);
  });
});
