/**
 * `pkgvet/mayInstall.ts` — the install hook's gate before it loads the vetting
 * modules (review 8, item 17). It may say yes to a command that installs
 * nothing (then the full parse decides); it must never say no to one
 * `parseInstallCommands` reads an install from — that command would go
 * unvetted. Held against every string literal of the install parser's own
 * tests and the hook's, and a seeded random walk over installer spellings.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { assessBashCommand } from '../../../src/hooks/bashGuard.js';
import { mayInstall } from '../../../src/pkgvet/mayInstall.js';
import { parseInstallCommands } from '../../../src/pkgvet/parseCommand.js';

const here = dirname(fileURLToPath(import.meta.url));

/** Whether the parser finds a package to vet in `command`, read by either shell. */
const installs = (command: string): boolean =>
  (['bash', 'powershell'] as const).some((shell) => parseInstallCommands(command, { shell }).some((c) => c.packages.length > 0));

/** The string literals of a test file — '…', "…" and `…` without interpolation — as a corpus of commands. */
function literalsOf(file: string): string[] {
  const text = readFileSync(file, 'utf8');
  const out: string[] = [];
  for (const m of text.matchAll(/'((?:[^'\\\n]|\\.){3,400})'|"((?:[^"\\\n]|\\.){3,400})"|`([^`$\\]{3,400})`/g)) {
    const raw = m[1] ?? m[2] ?? m[3] ?? '';
    out.push(raw.replace(/\\(.)/g, '$1'));
  }
  return out;
}

describe('mayInstall', () => {
  const corpus = [
    ...literalsOf(join(here, 'parseCommand.test.ts')),
    ...literalsOf(join(here, 'hookDecision.test.ts')),
    ...literalsOf(join(here, '..', '..', 'e2e', 'hooksPkgVet.test.ts')),
  ];

  it('never says no to a command the install parser reads an install from (the parser and the hooks’ test corpora)', () => {
    let installing = 0;
    for (const command of corpus) {
      if (!installs(command)) continue;
      installing += 1;
      expect({ command, gate: mayInstall(command) }).toEqual({ command, gate: true });
    }
    expect(installing).toBeGreaterThan(100);
  });

  it('nor on a random walk over installer spellings', () => {
    const heads = [
      'npm', 'npm.cmd', 'NPM', 'n\\pm', '"npm"', 'pnpm', 'yarn', 'bun', 'bunx', 'npx', 'pnpx', 'pip', 'pip3', 'pip3.12',
      'python -m pip', 'py -3 -m pip', 'uv', 'uvx', 'pipx', 'poetry', 'composer', 'php composer.phar', 'dotnet',
      '/usr/local/bin/npm', 'C:\\Python312\\Scripts\\pip.exe', '.venv/bin/pip', 'sudo pip', 'env X=1 npm',
    ];
    const subs = ['i', 'install', 'add', 'require', 'add package', 'pip install', 'tool install', 'x', 'dlx', 'exec', 'run'];
    const pkgs = ['left-pad', 'requests', 'zz-evil', '@scope/pkg', 'Newtonsoft.Json', 'monolog/monolog'];
    const glue = ['', 'cd app && ', 'echo hi; ', 'true || '];
    let seed = 7;
    const rnd = (n: number): number => {
      seed = (seed * 1103515245 + 12345) % 2147483648;
      return seed % n;
    };
    let installing = 0;
    for (let k = 0; k < 3000; k += 1) {
      const command = `${glue[rnd(glue.length)] ?? ''}${heads[rnd(heads.length)] ?? ''} ${subs[rnd(subs.length)] ?? ''} ${pkgs[rnd(pkgs.length)] ?? ''}`;
      if (!installs(command)) continue;
      installing += 1;
      expect({ command, gate: mayInstall(command) }).toEqual({ command, gate: true });
    }
    expect(installing).toBeGreaterThan(300);
  });

  // Review of 3.3.0: the hook also vets the scripts a command hands a shell
  // (`BashAssessment.scripts`), and gates each one on its own text — which may
  // be base64 the outer command never spells.
  it('never says no to a nested script the shell guard hands the vetting', () => {
    const outer = [
      "bash -c 'npm i zz-evil'",
      'cmd //c npm i zz-evil',
      "echo 'npx zz-evil' | sh",
      "cat <<'EOF' | bash\npip install zz-evil\nEOF",
      `pwsh -EncodedCommand ${Buffer.from('npm i zz-evil', 'utf16le').toString('base64')}`,
      `echo ${Buffer.from('pnpm add zz-evil').toString('base64')} | base64 -d | sh`,
    ];
    let installing = 0;
    for (const command of outer) {
      for (const shell of ['bash', 'powershell'] as const) {
        const scripts = assessBashCommand(command, { shell }).scripts ?? [];
        for (const script of scripts) {
          if (!parseInstallCommands(script.text, { shell: script.shell }).some((c) => c.packages.length > 0)) continue;
          installing += 1;
          expect({ script: script.text, gate: mayInstall(script.text) }).toEqual({ script: script.text, gate: true });
        }
      }
    }
    expect(installing).toBeGreaterThanOrEqual(outer.length);
  });

  it.each(['git status', 'ls -la src', 'echo "npm-ish" > notes.txt', 'node dist/server.js', 'cat package-lock.json', 'rm -rf node_modules'])(
    '%s is not an install: the vetting modules are not loaded',
    (command) => {
      expect(mayInstall(command)).toBe(false);
    },
  );
});
