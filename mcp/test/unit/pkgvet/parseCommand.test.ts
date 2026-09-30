import { describe, expect, it } from 'vitest';

import { parseInstallCommands, parsePackageSpec } from '../../../src/pkgvet/parseCommand.js';
import type { PackageSpec, PkgEcosystem } from '../../../src/pkgvet/types.js';
import { expectLinear, PERF_STRICT } from '../../helpers/timing.js';

/** `[name, range?]` pairs of every package the command would have vetted. */
function vetted(command: string): Array<[string, string | undefined]> {
  return parseInstallCommands(command).flatMap((c) => c.packages.map((p): [string, string | undefined] => [p.name, p.range]));
}

function ecosystems(command: string): PkgEcosystem[] {
  return parseInstallCommands(command).map((c) => c.ecosystem);
}

describe('parseInstallCommands — which commands are install commands', () => {
  it.each([
    ['npm install left-pad', 'npm'],
    ['npm i left-pad', 'npm'],
    ['npm add left-pad', 'npm'],
    ['pnpm add left-pad', 'npm'],
    ['yarn add left-pad', 'npm'],
    ['bun add left-pad', 'npm'],
    ['pip install requests', 'pypi'],
    ['pip3 install requests', 'pypi'],
    ['python -m pip install requests', 'pypi'],
    ['python3 -m pip install requests', 'pypi'],
    ['uv add requests', 'pypi'],
    ['uv pip install requests', 'pypi'],
    ['poetry add requests', 'pypi'],
    ['composer require monolog/monolog', 'packagist'],
    ['dotnet add package Newtonsoft.Json', 'nuget'],
  ])('%s -> %s', (command, eco) => {
    expect(ecosystems(command)).toEqual([eco]);
  });

  it('ignores commands that install nothing by name', () => {
    expect(parseInstallCommands('npm run build')).toEqual([]);
    expect(parseInstallCommands('npm test')).toEqual([]);
    expect(parseInstallCommands('pip list')).toEqual([]);
    expect(parseInstallCommands('git commit -m "npm install evil"')).toEqual([]);
    expect(parseInstallCommands('echo npm install evil')).toEqual([]);
  });

  it('bare `npm install` and `pip install -r req.txt` vet nothing', () => {
    expect(vetted('npm install')).toEqual([]);
    expect(vetted('npm ci')).toEqual([]);
    expect(vetted('pip install -r requirements.txt')).toEqual([]);
    const r = parseInstallCommands('pip install -r requirements.txt');
    expect(r[0]?.skipped).toEqual([{ raw: 'requirements.txt', reason: expect.stringMatching(/requirements file/) }]);
  });

  it('finds install commands behind separators, pipes and runners', () => {
    expect(vetted('cd app && npm install express; pip install flask')).toEqual([
      ['express', undefined],
      ['flask', undefined],
    ]);
    expect(vetted('sudo -E npm install -g typescript')).toEqual([['typescript', undefined]]);
    expect(vetted('NODE_ENV=dev npm i lodash')).toEqual([['lodash', undefined]]);
    expect(vetted('env CI=1 yarn add react')).toEqual([['react', undefined]]);
  });

  it('handles yarn global / workspace forms', () => {
    expect(vetted('yarn global add serve')).toEqual([['serve', undefined]]);
    expect(vetted('yarn workspace web add react-dom')).toEqual([['react-dom', undefined]]);
  });
});

describe('parseInstallCommands — npm specs and flags', () => {
  it('parses versions, ranges, tags and scopes', () => {
    expect(vetted('npm install name@1.2.3 @scope/name@^1 other@next plain')).toEqual([
      ['name', '1.2.3'],
      ['@scope/name', '^1'],
      ['other', 'next'],
      ['plain', undefined],
    ]);
    expect(vetted('npm i "react@>=18 <19"')).toEqual([['react', '>=18 <19']]);
  });

  it('vets the REAL package behind an npm: alias', () => {
    expect(vetted('npm install my-lodash@npm:lodash@^4')).toEqual([['lodash', '^4']]);
  });

  it('skips flags, and the values of flags that take one', () => {
    expect(vetted('npm install -D -E --save-dev typescript')).toEqual([['typescript', undefined]]);
    expect(vetted('npm install --prefix ./sub --tag beta -w pkg-a lodash')).toEqual([['lodash', undefined]]);
    expect(vetted('npm install --registry https://npm.example.com lodash')).toEqual([['lodash', undefined]]);
    expect(vetted('pnpm --filter web add -D vitest')).toEqual([['vitest', undefined]]);
    expect(vetted('pnpm add -w -D vitest')).toEqual([['vitest', undefined]]);
  });

  it('an unknown long flag conservatively swallows the next word rather than vetting it', () => {
    expect(vetted('npm install --some-new-flag value lodash')).toEqual([['lodash', undefined]]);
  });

  it('records a registry given on the command line', () => {
    expect(parseInstallCommands('npm install --registry https://npm.example.com lodash')[0]?.customRegistry).toBe(
      'https://npm.example.com',
    );
    expect(parseInstallCommands('npm install --registry=https://npm.example.com lodash')[0]?.customRegistry).toBe(
      'https://npm.example.com',
    );
  });

  it('never looks up paths, tarballs, URLs, git or protocol specs', () => {
    const cmd =
      'npm install ./local ../up /abs/pkg C:\\\\win\\\\pkg . pkg.tgz https://x.io/p.tgz git+https://github.com/a/b.git github:a/b a/b ws@workspace:* f@file:../f l@link:../l';
    expect(vetted(cmd)).toEqual([]);
    const skipped = parseInstallCommands(cmd)[0]?.skipped ?? [];
    expect(skipped).toHaveLength(13);
  });

  it('skips words carrying shell expansion — the value is not knowable', () => {
    expect(vetted('npm install $PKG "${OTHER}" lodash')).toEqual([['lodash', undefined]]);
  });
});

describe('parseInstallCommands — Python specs and flags', () => {
  it('parses PEP 508 names with extras, versions and markers', () => {
    expect(vetted('pip install requests==2.31.0 "uvicorn[standard]>=0.20" flask Django~=4.2')).toEqual([
      ['requests', '==2.31.0'],
      ['uvicorn', '>=0.20'],
      ['flask', undefined],
      ['Django', '~=4.2'],
    ]);
    expect(vetted('pip install "numpy>=1.20; python_version>=\'3.8\'"')).toEqual([['numpy', '>=1.20']]);
  });

  it('skips -e / -r / -c and every flag value, and paths / URLs / archives', () => {
    expect(vetted('pip install -e . -r req.txt -c constraints.txt -t ./vendor --upgrade requests')).toEqual([
      ['requests', undefined],
    ]);
    expect(vetted('pip install ./pkg dist/x-1.0-py3-none-any.whl x.tar.gz git+https://github.com/a/b.git https://x.io/y.zip')).toEqual([]);
    expect(vetted('pip install "pkg @ https://x.io/pkg.whl"')).toEqual([]);
  });

  it('records -i / --index-url / --extra-index-url / --no-index as a custom registry', () => {
    expect(parseInstallCommands('pip install -i https://pypi.example.com/simple requests')[0]?.customRegistry).toBe(
      'https://pypi.example.com/simple',
    );
    expect(parseInstallCommands('pip install --extra-index-url https://x/simple requests')[0]?.customRegistry).toBe(
      'https://x/simple',
    );
    expect(parseInstallCommands('pip install --no-index --find-links ./wheels requests')[0]?.customRegistry).toBeDefined();
  });

  it('poetry add accepts name@constraint', () => {
    expect(vetted('poetry add requests@^2.31 pendulum@latest --group dev')).toEqual([
      ['requests', '^2.31'],
      ['pendulum', undefined],
    ]);
  });

  it('uv add / uv pip install', () => {
    expect(vetted('uv add --dev pytest "httpx>=0.27"')).toEqual([
      ['pytest', undefined],
      ['httpx', '>=0.27'],
    ]);
    expect(vetted('uv pip install -r req.txt rich')).toEqual([['rich', undefined]]);
  });
});

describe('parseInstallCommands — Composer and NuGet', () => {
  it('composer: vendor/pkg with :, = or a separate constraint word; platform packages skipped', () => {
    expect(vetted('composer require monolog/monolog:^3.0 guzzlehttp/guzzle "^7.0" --dev php ext-json symfony/console=6.4.*')).toEqual([
      ['monolog/monolog', '^3.0'],
      ['guzzlehttp/guzzle', '^7.0'],
      ['symfony/console', '6.4.*'],
    ]);
  });

  it('dotnet add [project] package X --version V, with --source recorded', () => {
    expect(vetted('dotnet add package Newtonsoft.Json --version 13.0.3')).toEqual([['Newtonsoft.Json', '13.0.3']]);
    expect(vetted('dotnet add src/App.csproj package Serilog -v 3.1.1')).toEqual([['Serilog', '3.1.1']]);
    expect(parseInstallCommands('dotnet add package Acme.Internal -s https://nuget.acme.local/v3/index.json')[0]?.customRegistry).toBe(
      'https://nuget.acme.local/v3/index.json',
    );
  });

  it('dotnet add reference is not a package install', () => {
    expect(parseInstallCommands('dotnet add reference ../Lib/Lib.csproj')).toEqual([]);
  });
});

describe('parsePackageSpec (tool input)', () => {
  const ok = (eco: PkgEcosystem, raw: string): PackageSpec => {
    const r = parsePackageSpec(eco, raw);
    if (!('name' in r)) throw new Error(`expected a package, got skipped: ${r.reason}`);
    return r;
  };

  it('accepts name and name@version in every ecosystem', () => {
    expect(ok('npm', 'express@4.18.2')).toMatchObject({ name: 'express', range: '4.18.2' });
    expect(ok('npm', '@types/node')).toMatchObject({ name: '@types/node' });
    expect(ok('pypi', 'requests@2.31.0')).toMatchObject({ name: 'requests', range: '2.31.0' });
    expect(ok('pypi', 'requests==2.31.0')).toMatchObject({ name: 'requests', range: '==2.31.0' });
    expect(ok('packagist', 'monolog/monolog@3.5.0')).toMatchObject({ name: 'monolog/monolog', range: '3.5.0' });
    expect(ok('packagist', 'monolog/monolog:^3')).toMatchObject({ name: 'monolog/monolog', range: '^3' });
    expect(ok('nuget', 'Newtonsoft.Json@13.0.3')).toMatchObject({ name: 'Newtonsoft.Json', range: '13.0.3' });
  });

  it('rejects things that are not a package name, with a reason', () => {
    expect(parsePackageSpec('npm', './local')).toEqual({ raw: './local', reason: expect.any(String) });
    expect(parsePackageSpec('packagist', 'monolog')).toEqual({ raw: 'monolog', reason: expect.any(String) });
    expect(parsePackageSpec('pypi', 'not a name')).toEqual({ raw: 'not a name', reason: expect.any(String) });
  });
});

// ─────────────────────────────── fix round 1 (review of Task 16)

function uncertain(command: string): string[] {
  return parseInstallCommands(command).flatMap((c) => c.uncertain);
}

describe('C1 — flag values are never vetted as names', () => {
  it.each([
    ['pip install -qr req.txt', [], 'req.txt'],
    ['pip install -Ur requirements.txt requests', [['requests', undefined]], 'requirements.txt'],
    ['pip install -qc constraints.txt flask', [['flask', undefined]], 'constraints.txt'],
    ['pip install -qe . flask', [['flask', undefined]], '.'],
    ['uv pip install -qr req.txt rich', [['rich', undefined]], 'req.txt'],
    ['pip install -rreq.txt', [], 'req.txt'],
  ] as Array<[string, Array<[string, string | undefined]>, string]>)(
    '%s: a short-flag cluster ending in a value flag consumes the next word',
    (command, expected, reported) => {
      expect(vetted(command)).toEqual(expected);
      expect(parseInstallCommands(command)[0]?.skipped.map((s) => s.raw)).toContain(reported);
      // Round 2: -r/-c/-e/-i/-f/-t are not on the confident-shape allowlist.
      expect(uncertain(command)).not.toEqual([]);
    },
  );

  it('pip -qi / -qf: the consumed word is a registry', () => {
    expect(vetted('pip install -qi https://pypi.acme.local/simple requests')).toEqual([['requests', undefined]]);
    expect(parseInstallCommands('pip install -qi https://pypi.acme.local/simple requests')[0]?.customRegistry).toBe(
      'https://pypi.acme.local/simple',
    );
    expect(parseInstallCommands('pip install -qf ./wheels requests')[0]?.customRegistry).toBe('./wheels');
  });

  it('pip -t / -qt: the target directory is not a package', () => {
    expect(vetted('pip install -qt ./vendor requests')).toEqual([['requests', undefined]]);
  });

  it('yarn --mode takes a value', () => {
    expect(vetted('yarn add --mode update-lockfile react')).toEqual([['react', undefined]]);
  });

  it('npm -C is --prefix, and takes a value', () => {
    expect(vetted('npm install -C ./sub lodash')).toEqual([['lodash', undefined]]);
  });

  it('poetry --optional takes a value', () => {
    expect(vetted('poetry add --optional extra1 requests')).toEqual([['requests', undefined]]);
  });

  it('pnpm --allow-build takes a value', () => {
    expect(vetted('pnpm add --allow-build esbuild vite')).toEqual([['vite', undefined]]);
  });

  it('an unknown flag makes the parse uncertain (the general net)', () => {
    expect(uncertain('npm install --some-new-flag value lodash').join(' ')).toMatch(/--some-new-flag/);
    expect(uncertain('pip install -Z requests').join(' ')).toMatch(/-Z/);
    expect(uncertain('pip install -qZ requests').join(' ')).toMatch(/-Z/);
  });

  it('known flags keep the parse confident', () => {
    expect(uncertain('npm install -D -E --save-dev typescript')).toEqual([]);
    expect(uncertain('pip install --upgrade --user -q requests')).toEqual([]);
  });
});

describe('ruling (b) — an inline environment assignment makes every install uncertain', () => {
  it.each([
    'NPM_CONFIG_REGISTRY=https://npm.acme.local npm install foo',
    'env NPM_CONFIG_REGISTRY=https://npm.acme.local npm install foo',
    'export PIP_INDEX_URL=https://pypi.acme.local/simple && pip install foo',
    '$env:NPM_CONFIG_REGISTRY="https://npm.acme.local"; npm install foo',
    'npm install foo && FOO=1 true',
  ])('%s', (command) => {
    expect(uncertain(command).join(' ')).toMatch(/environment/);
  });

  it('`set -e` is a shell option, not an assignment (round 2: still not ONE statement)', () => {
    expect(uncertain('set -e && npm install foo').join(' ')).not.toMatch(/environment/);
    expect(uncertain('set -e && npm install foo').join(' ')).toMatch(/single/);
  });
});

describe('ruling (c) — a directory change before or in the install makes it uncertain', () => {
  it.each([
    ['cd packages/web && npm install foo', /directory/],
    ['pushd api; pip install foo', /directory/],
    ['Set-Location ..\\app; npm install foo', /directory/],
    ['Push-Location app; npm install foo', /directory/],
    ['npm install --prefix ./sub foo', /--prefix/],
    ['npm install -C ./sub foo', /-C/],
    ['pnpm -C ./web add foo', /-C/],
    ['pnpm add --dir ./web foo', /--dir/],
    ['yarn --cwd ./web add foo', /--cwd/],
    ['composer -d ./api require acme/foo', /-d/],
    ['composer require --working-dir=./api acme/foo', /--working-dir/],
    ['uv add --directory ./svc foo', /--directory/],
    ['uv add --project ./svc foo', /--project/],
    ['dotnet add src/App.csproj package Foo', /project/],
  ] as Array<[string, RegExp]>)('%s', (command, why) => {
    expect(uncertain(command).join(' ')).toMatch(why);
  });

  it('a cd AFTER the install is not a directory change for it (round 2: still not ONE statement)', () => {
    expect(uncertain('npm install foo && cd dist').join(' ')).not.toMatch(/directory change earlier/);
    expect(uncertain('npm install foo && cd dist').join(' ')).toMatch(/single/);
  });
});

describe('ruling (f) / I2 — workspace context makes it uncertain', () => {
  it.each([
    'pnpm add --workspace @acme/ui',
    'yarn workspace web add @acme/ui',
    'npm install @acme/ui -w apps/web',
    'pnpm --filter web add @acme/ui',
  ])('%s', (command) => {
    expect(uncertain(command).join(' ')).toMatch(/workspace/);
  });
});

// ─────────────────────────────── fix round 2 — the confident-shape ALLOWLIST

describe('round 2 — a missing name is deny-eligible only for ONE plain install statement', () => {
  it.each([
    'npm i react-super-hallucinated-utils-zz',
    'npm install -D hallucinated-zz-pkg',
    'npm i --save-dev --save-exact hallucinated-zz-pkg',
    'npm i -DE hallucinated-zz-pkg',
    'pnpm add -E hallucinated-zz-pkg',
    'yarn add --dev hallucinated-zz-pkg',
    'bun add -d hallucinated-zz-pkg',
    'pip install reqeusts',
    'pip3 install -U --user hallucinated-zz-pkg',
    'python -m pip install -q hallucinated-zz-pkg',
    'python3 -m pip install hallucinated-zz-pkg',
    'uv add --dev hallucinated-zz-pkg',
    'uv add --group lint hallucinated-zz-pkg',
    'uv pip install -q hallucinated-zz-pkg',
    'poetry add --group dev hallucinated-zz-pkg',
    'poetry add --optional extra1 hallucinated-zz-pkg',
    'composer require zzvendor/notapkg',
    'composer require --dev zzvendor/notapkg',
    'dotnet add package Acme.Totally.Missing.Pkg',
    'dotnet add package Acme.Totally.Missing.Pkg --version 1.0.0 --prerelease',
    'pip install requests  # for http calls',
    'pip install requests <# for http calls #>',
  ])('confident: %s', (command) => {
    expect(uncertain(command)).toEqual([]);
  });

  it.each([
    ['cd x && npm i foo', /single/],
    ['npm i foo; npm i bar', /single/],
    ['npm i foo || true', /single/],
    ['npm i foo | tee log', /single/],
    ['npm i foo &', /single/],
    ['npm i foo\nnpm i bar', /single/],
    ['(npm i foo)', /single/],
    ['npm i $(cat pkgs.txt) foo', /single/],
    ['npm i `cat pkgs.txt` foo', /single/],
    ['npm i "$PKG" foo', /single/],
    ['sudo npm i foo', /not a plain/],
    ['env npm i foo', /not a plain/],
    ['NPM_CONFIG_REGISTRY=https://npm.corp npm i foo', /not a plain/],
    ['.venv/bin/pip install foo', /not a plain/],
    ['C:/tools/npm.cmd i foo', /not a plain/],
    ['npm --userconfig ./corp.npmrc install foo', /allowlist|not a plain/],
    ['npm install --globalconfig ./g.npmrc foo', /--globalconfig/],
    ['npm install --registry https://npm.corp foo', /--registry/],
    ['uv add --config-file ./uv.toml foo', /--config-file/],
    ['bun add -c ./bunfig.toml foo', /-c/],
    ['bun add --config ./bunfig.toml foo', /--config/],
    ['pip install --extra-index-url https://pypi.corp/simple -i https://pypi.org/simple foo', /--extra-index-url|-i/],
    ['dotnet add package Corp.Lib -s https://nuget.corp/v3/index.json -s https://api.nuget.org/v3/index.json', /-s/],
    ['dotnet add src/App.csproj package Foo', /not a plain/],
    ['pip install -r req.txt foo', /-r/],
    ['npm i foo > log.txt', /single/],
  ] as Array<[string, RegExp]>)('not confident: %s', (command, why) => {
    const reasons = uncertain(command);
    expect(reasons).not.toEqual([]);
    expect(reasons.join(' ')).toMatch(why);
  });
});

describe('round 2 — unquoted comments are stripped before anything is vetted', () => {
  it('`# …` to end of line', () => {
    expect(vetted('pip install requests  # for http calls')).toEqual([['requests', undefined]]);
    expect(vetted('npm i lodash # comment\nnpm i zod')).toEqual([
      ['lodash', undefined],
      ['zod', undefined],
    ]);
  });

  it('PowerShell <# … #>', () => {
    expect(vetted('pip install requests <# for http calls #>')).toEqual([['requests', undefined]]);
  });

  it('a # inside a word or inside quotes is not a comment', () => {
    expect(vetted('npm i "foo#bar" lodash')).toEqual([['lodash', undefined]]);
    expect(vetted('npm i user/repo#main lodash')).toEqual([['lodash', undefined]]);
  });

  it('uv --compile-bytecode is a boolean flag', () => {
    expect(vetted('uv add --compile-bytecode httpx')).toEqual([['httpx', undefined]]);
    expect(vetted('uv pip install --compile-bytecode httpx')).toEqual([['httpx', undefined]]);
  });

  it('every registry on the command line is kept, not only the last', () => {
    const c = parseInstallCommands(
      'dotnet add package Corp.Lib -s https://nuget.corp/v3/index.json -s https://api.nuget.org/v3/index.json',
    )[0];
    expect(c?.registries).toEqual(['https://nuget.corp/v3/index.json', 'https://api.nuget.org/v3/index.json']);
  });
});

describe('M3 / M5', () => {
  it('SSH-style git specs are not names', () => {
    expect(vetted('npm install git@github.com:user/repo.git')).toEqual([]);
    expect(parseInstallCommands('npm install git@github.com:user/repo.git')[0]?.skipped[0]?.reason).toMatch(/git|VCS/i);
    // …while an npm alias is still an alias.
    expect(vetted('npm install my-lodash@npm:lodash@^4')).toEqual([['lodash', '^4']]);
  });

  it('bun i <pkg> and bun install <pkg> are installs; the bare forms vet nothing', () => {
    expect(vetted('bun i zod')).toEqual([['zod', undefined]]);
    expect(vetted('bun install zod')).toEqual([['zod', undefined]]);
    expect(vetted('bun install')).toEqual([]);
    expect(vetted('bun i')).toEqual([]);
  });
});

// Follow-up Part Y (item 5). Every row below says what is vetted and whether a
// missing name may be DENIED (`confident`). The rule these protect: a shape
// added to vetting may only ever add a MALICIOUS deny — a missing-name deny
// stays reserved for ONE plain install statement.
describe('Part Y — edge shapes, one table', () => {
  type Row = [label: string, command: string, shell: 'bash' | 'powershell', names: string[], confident: boolean];
  const rows: Row[] = [
    // `--no-update` / `--no-restore` defer the lookup the command would make,
    // so they no longer count as a plain install.
    ['composer --no-update', 'composer require zzvendor/notapkg --no-update', 'bash', ['zzvendor/notapkg'], false],
    ['dotnet --no-restore', 'dotnet add package Acme.Missing.Pkg --no-restore', 'bash', ['Acme.Missing.Pkg'], false],
    ['dotnet -n', 'dotnet add package Acme.Missing.Pkg -n', 'bash', ['Acme.Missing.Pkg'], false],
    ['composer --dev (still plain)', 'composer require --dev zzvendor/notapkg', 'bash', ['zzvendor/notapkg'], true],
    // `2>&1`, `--`, `=`-joined flags
    ['2>&1', 'npm i hallucinated-zz-pkg 2>&1', 'bash', ['hallucinated-zz-pkg'], false],
    ['--', 'npm i -- hallucinated-zz-pkg', 'bash', ['hallucinated-zz-pkg'], false],
    ['=-joined allowlisted value flag', 'uv add --group=dev hallucinated-zz-pkg', 'bash', ['hallucinated-zz-pkg'], true],
    ['=-joined registry', 'pip install --index-url=https://pypi.corp/simple corp-lib', 'bash', ['corp-lib'], false],
    ['=-joined npm registry', 'npm i --registry=https://npm.corp corp-lib', 'bash', ['corp-lib'], false],
    // how the executable is spelled
    ['npm.cmd', 'npm.cmd i hallucinated-zz-pkg', 'bash', ['hallucinated-zz-pkg'], false],
    ['upper-case NPM', 'NPM i hallucinated-zz-pkg', 'bash', ['hallucinated-zz-pkg'], false],
    ['`! npm i`', '! npm i hallucinated-zz-pkg', 'bash', ['hallucinated-zz-pkg'], false],
    // line endings
    ['a trailing CRLF', 'npm i hallucinated-zz-pkg\r\n', 'bash', ['hallucinated-zz-pkg'], true],
    ['CRLF between two installs', 'npm i a-zz-pkg\r\nnpm i b-zz-pkg', 'bash', ['a-zz-pkg', 'b-zz-pkg'], false],
    // NBSP is no separator to bash — `npm i<NBSP>x` runs nothing — but it is to PowerShell.
    ['NBSP, bash', 'npm i\u00a0hallucinated-zz-pkg', 'bash', [], false],
    ['NBSP, PowerShell', 'npm i\u00a0hallucinated-zz-pkg', 'powershell', ['hallucinated-zz-pkg'], false],
    // PowerShell hands a native command each element of `a,b` as its own argument.
    ['comma list, PowerShell', 'npm i lodash,evil-zz-pkg', 'powershell', ['lodash', 'evil-zz-pkg'], false],
    ['comma list, bash (one invalid word)', 'npm i lodash,evil-zz-pkg', 'bash', [], false],
    // A backtick-newline continues a PowerShell line.
    ['backtick continuation, PowerShell', 'npm i lodash `\n  evil-zz-pkg', 'powershell', ['lodash', 'evil-zz-pkg'], false],
    ['backtick continuation, PowerShell CRLF', 'npm i lodash `\r\n  evil-zz-pkg', 'powershell', ['lodash', 'evil-zz-pkg'], false],
    // `''` inside '…' is one literal quote to PowerShell; to bash, two quoted
    // spans. Both readings are vetted, and neither is a plain install.
    ["'' escape, PowerShell", "npm i 'it''s' evil-zz-pkg", 'powershell', ['its', 'evil-zz-pkg'], false],
    ["adjacent '…''…' spans are never plain", "npm i 'hallucinated''-zz-pkg'", 'bash', ['hallucinated-zz-pkg'], false],
    // A backslash is literal in PowerShell, so `"x\"` ends at that quote; to
    // bash it escapes the quote, and the rest of the line is one word.
    ['a backslash before a closing ", PowerShell', 'npm i "x\\" evil-zz-pkg', 'powershell', ['evil-zz-pkg'], false],
    ['a backslash before a closing ", bash', 'npm i "x\\" evil-zz-pkg', 'bash', [], false],
    // A PowerShell install with none of that is exactly what it was.
    ['plain, PowerShell', 'npm i hallucinated-zz-pkg', 'powershell', ['hallucinated-zz-pkg'], true],
  ];

  it.each(rows)('%s', (_label, command, shell, names, confident) => {
    const cmds = parseInstallCommands(command, { shell });
    expect(cmds.flatMap((c) => c.packages.map((p) => p.name)).sort()).toEqual([...names].sort());
    if (names.length > 0) expect(cmds.every((c) => c.packages.length === 0 || c.uncertain.length === 0)).toBe(confident);
  });

  it('a package only the PowerShell reading finds is never deny-eligible for a missing name', () => {
    const cmds = parseInstallCommands('npm i hallucinated-zz-pkg,other-zz-pkg', { shell: 'powershell' }).filter(
      (c) => c.packages.length > 0,
    );
    expect(cmds.length).toBeGreaterThan(0);
    for (const c of cmds) expect(c.uncertain.join(' ')).toMatch(/PowerShell/);
  });

  it('a package both readings find is vetted once', () => {
    expect(parseInstallCommands('npm i lodash `\n  zod', { shell: 'powershell' }).flatMap((c) => c.packages.map((p) => p.name))).toEqual([
      'lodash',
      'zod',
    ]);
  });
});

// Fix round 3: the PowerShell environment check restarted `[^;\n]*` at every
// `Set-Item` / `New-Item` — quadratic on every command the hook sees.
// Review 3.0, R7-I2: this was "250 KB parses in well under 1 s" — a bound that
// measured the machine and failed the coverage run. The defect is a shape, so
// the assertion is a ratio (test/helpers/timing.ts): eight times as long
// (875 against 7 000 cmdlets, 8 KB against 63 KB) must cost under 22.6 times
// as much. At 4x the Set-Item shape read 11 for the defect, under its bound
// of 12; and at the original 250 KB the defect takes 14 s — a vitest timeout,
// not an assertion. The absolute bound runs only with GUARDIAN_PERF_STRICT=1.
describe('parseInstallCommands — linear on the shapes that were not', () => {
  const shapes: Array<[string, (n: number) => string]> = [
    ['Set-Item', (n) => 'Set-Item '.repeat(n)],
    ['New-Item', (n) => 'New-Item '.repeat(n)],
    ['New-Item … then an install', (n) => `${'New-Item '.repeat(n)}; npm i lodash`],
  ];
  const parseBoth = (command: string): void => {
    parseInstallCommands(command, { shell: 'bash' });
    parseInstallCommands(command, { shell: 'powershell' });
  };
  it.each(shapes)('%s: eight times as long costs well under 22.6 times as much', (label, make) => {
    expectLinear(label, (n) => parseBoth(make(n)), 875);
  }, 120_000);
  it.runIf(PERF_STRICT).each(shapes)('250 KB of %s parses in well under 1 s (GUARDIAN_PERF_STRICT=1)', (_label, make) => {
    const command = make(28_000);
    const t0 = performance.now();
    parseBoth(command);
    expect(performance.now() - t0).toBeLessThan(1000);
  });

  it('the environment check still sees Set-Item Env: and New-Item env: in a statement', () => {
    for (const command of [
      'Set-Item Env:NPM_CONFIG_REGISTRY https://npm.corp; npm i x',
      'New-Item -Path env:PIP_INDEX_URL -Value https://x; pip install y',
    ]) {
      expect(parseInstallCommands(command).flatMap((c) => c.uncertain).join(' ')).toMatch(/environment/);
    }
  });
});

// Review of 3.0.0, P1: the launchers that download a package and run it were
// not vetted at all, while `npm i -g` of the same name was denied.
describe('parseInstallCommands — launchers that download and run a package (review P1)', () => {
  it.each([
    ['npx -y create-vite-zz my-app --template react', 'npm', [['create-vite-zz', undefined]]],
    ['npx --yes cowsay@1.5.0 hello', 'npm', [['cowsay', '1.5.0']]],
    ['npx -p typescript -p ts-node-zz tsc --version', 'npm', [['typescript', undefined], ['ts-node-zz', undefined]]],
    ['npx --package=@scope/tool-zz tool-zz run', 'npm', [['@scope/tool-zz', undefined]]],
    ['pnpx create-next-app-zz app', 'npm', [['create-next-app-zz', undefined]]],
    ['npm exec -- cowsay-zz hi', 'npm', [['cowsay-zz', undefined]]],
    ['npm exec --yes cowsay-zz -- hi', 'npm', [['cowsay-zz', undefined]]],
    ['npm x cowsay-zz', 'npm', [['cowsay-zz', undefined]]],
    ['pnpm dlx create-next-app@14 app', 'npm', [['create-next-app', '14']]],
    ['pnpm --package=cowsay-zz dlx cowsay hi', 'npm', [['cowsay-zz', undefined]]],
    ['yarn dlx some-pkg-zz --flag', 'npm', [['some-pkg-zz', undefined]]],
    ['yarn dlx -p pkg-a-zz -p pkg-b-zz cmd', 'npm', [['pkg-a-zz', undefined], ['pkg-b-zz', undefined]]],
    ['bunx cowsay-zz hi', 'npm', [['cowsay-zz', undefined]]],
    ['bun x cowsay-zz hi', 'npm', [['cowsay-zz', undefined]]],
    ['uvx ruff-zz check .', 'pypi', [['ruff-zz', undefined]]],
    ['uvx ruff-zz@0.6.0 check .', 'pypi', [['ruff-zz', '0.6.0']]],
    ['uvx --from httpie-zz http GET example.com', 'pypi', [['httpie-zz', undefined]]],
    ['uvx --with requests-zz ruff-zz check', 'pypi', [['requests-zz', undefined], ['ruff-zz', undefined]]],
    ['uv tool run black-zz .', 'pypi', [['black-zz', undefined]]],
    ['uv tool install ruff-zz', 'pypi', [['ruff-zz', undefined]]],
    ['uv tool install ruff-zz --with plugin-zz', 'pypi', [['ruff-zz', undefined], ['plugin-zz', undefined]]],
    ['pipx install poetry-zz', 'pypi', [['poetry-zz', undefined]]],
    ['pipx install tool-a-zz tool-b-zz', 'pypi', [['tool-a-zz', undefined], ['tool-b-zz', undefined]]],
    ['pipx run cowsay-zz moo', 'pypi', [['cowsay-zz', undefined]]],
    ['pipx run --spec httpie-zz http GET example.com', 'pypi', [['httpie-zz', undefined]]],
  ] as const)('%s', (command, eco, expected) => {
    const parsed = parseInstallCommands(command);
    expect(parsed.map((c) => c.ecosystem)).toEqual(parsed.map(() => eco));
    expect(
      parsed
        .flatMap((c) => c.packages.map((p): [string, string | undefined] => [p.name, p.range]))
        .sort((a, b) => a[0].localeCompare(b[0])),
    ).toEqual([...expected].map(([n, r]) => [n, r]).sort((a, b) => (a[0] ?? '').localeCompare(b[0] ?? '')));
  });

  it.each([
    'npx -y create-vite-zz my-app --template react',
    'npm exec cowsay-zz',
    'pnpm dlx cowsay-zz',
    'yarn dlx cowsay-zz',
    'bunx cowsay-zz',
    'uvx ruff-zz check .',
    'uv tool install ruff-zz',
    'pipx install poetry-zz',
    'pipx run cowsay-zz moo',
  ])('%s has the confident shape: a missing name may be denied', (command) => {
    expect(uncertain(command)).toEqual([]);
  });

  it.each([
    ['npx -p typescript tsc', /-p/],
    ['uvx --from httpie-zz http', /--from/],
    ['pipx install --pip-args="--index-url https://corp" tool-zz', /pip-args/],
    ['npx --registry https://npm.corp tool-zz', /registry|--registry/],
  ])('%s is not confident', (command, why) => {
    expect(uncertain(command).join(' ')).toMatch(why);
  });

  it.each([
    'npx -c "echo hi"',
    'npx --no-install eslint .',
    'npx --offline eslint .',
    'npx ./scripts/build.js',
    'uvx ./tool',
    'npm exec',
    'pipx list',
    'uv tool list',
    'pnpm dlx',
    'npx',
  ])('%s fetches nothing named: nothing to vet', (command) => {
    expect(parseInstallCommands(command).flatMap((c) => c.packages)).toEqual([]);
  });

  it('a registry named on a launcher counts, as on an install', () => {
    expect(parseInstallCommands('npx --registry https://npm.corp tool-zz')[0]?.registries).toEqual(['https://npm.corp']);
    expect(parseInstallCommands('uvx --index https://pypi.corp/simple tool-zz')[0]?.registries).toEqual(['https://pypi.corp/simple']);
  });

  // The runner prefix is read with its own options, as the shell guard reads
  // it: a table shared by every runner made `sudo -n` swallow the `npm`.
  it.each(['sudo -n npm install left-pad', 'sudo -i npm i left-pad', 'env -i npm i left-pad', 'sudo -u ci -- npx -y left-pad'])(
    '%s is still an install of left-pad',
    (command) => {
      expect(parseInstallCommands(command).flatMap((c) => c.packages.map((p) => p.name))).toEqual(['left-pad']);
    },
  );

  it('npx / npm exec / bunx run a locally installed bin first: the command says so', () => {
    for (const command of ['npx eslint .', 'npm exec eslint', 'bunx eslint', 'bun x eslint']) {
      expect(parseInstallCommands(command)[0]?.localFirst).toBe(true);
    }
    for (const command of ['pnpm dlx eslint', 'yarn dlx eslint', 'uvx ruff', 'pipx run ruff']) {
      expect(parseInstallCommands(command)[0]?.localFirst).toBeUndefined();
    }
  });
});
