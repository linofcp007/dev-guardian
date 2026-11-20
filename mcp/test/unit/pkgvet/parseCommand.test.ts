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

  it('the word after an unknown long flag may be its value: it is vetted as a candidate package, and so is the next one', () => {
    expect(vetted('npm install --some-new-flag value lodash')).toEqual([
      ['value', undefined],
      ['lodash', undefined],
    ]);
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

// 2026-10-24: `pip install -q "semgrep==1.182.0" 2>&1 | tail -5` warned that a package `2`
// was not on the registry — PEP 508 reads `2>&1` as `2` at a version `>&1`.
describe('parseInstallCommands — a redirection is never a package', () => {
  it.each([
    ['pip install -q "semgrep==1.182.0" 2>&1 | tail -5', [['semgrep', '==1.182.0']]],
    ['pipx install "zizmor==1.31.1" >/dev/null 2>&1', [['zizmor', '==1.31.1']]],
    ['pip install requests 2> err.log', [['requests', undefined]]],
    ['pip install requests > out.log', [['requests', undefined]]],
    ['pip install requests &>all.log', [['requests', undefined]]],
    ['npm install left-pad 2>/dev/null', [['left-pad', undefined]]],
    ['pip install requests < /dev/null', [['requests', undefined]]],
    ['pip install "flask>2"', [['flask', '>2']]],
  ])('%j vets %j', (command, expected) => expect(vetted(command)).toEqual(expected));
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

// Review 8, extra item: where a launcher runs, so the hook looks for the
// installed bin there (`cd mcp && npx vitest run`).
describe('workdir — the directory changes before a command, in order', () => {
  const workdir = (command: string, shell: 'bash' | 'powershell' = 'bash'): unknown =>
    parseInstallCommands(command, { shell }).map((c) => c.workdir);

  it.each([
    ['cd mcp && npx vitest run', [['mcp']]],
    ['cd mcp; cd test && npx vitest', [['mcp', 'test']]],
    ['cd -P ../web && npm i foo', [['../web']]],
    ['pushd api && npx eslint .', [['api']]],
    ['cd.. && npx eslint', [['..']]],
    ["cd /d 'C:\\work' && npx eslint", [['C:\\work']]],
    ["cd '/c/work' && npx eslint", [['/c/work']]],
    ['cd ~/proj && npx eslint', [['~/proj']]],
  ] as Array<[string, unknown]>)('%s', (command, expected) => {
    expect(workdir(command)).toEqual(expected);
  });

  it('PowerShell: Set-Location / sl, with or without -Path', () => {
    expect(workdir('Set-Location -Path web; npx eslint', 'powershell')).toEqual([['web']]);
    expect(workdir('sl web; npx eslint', 'powershell')).toEqual([['web']]);
  });

  it.each(['cd "$DIR" && npx eslint', 'cd `pwd` && npx eslint', 'cd - && npx eslint', 'cd && npx eslint', 'popd && npx eslint', 'cd %TEMP% && npx eslint', 'cd a b && npx eslint'])(
    '%s — a move that cannot be read is null',
    (command) => {
      expect(workdir(command)).toEqual([null]);
    },
  );

  it('an unreadable move stays unreadable: a later cd is relative to an unknown place', () => {
    expect(workdir('cd "$X" && cd web && npx eslint')).toEqual([null]);
  });

  it('no directory change: absent', () => {
    expect(parseInstallCommands('npx vitest run')[0]).not.toHaveProperty('workdir');
    expect(parseInstallCommands('npx vitest && cd dist')[0]).not.toHaveProperty('workdir');
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
  it.each([
    'sudo -n npm install left-pad',
    'sudo -i npm i left-pad',
    'env -i npm i left-pad',
    'sudo -u ci -- npx -y left-pad',
    'flock -w 5 /tmp/ci.lock npm i left-pad',
    'runuser -u ci -- npm i left-pad',
  ])(
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

// ───────────────── install-vet-manifest-install — the command installs what a manifest says

/** The manifest each install command of the line reads, in order (`undefined` for a by-name install). */
function manifests(command: string, shell: 'bash' | 'powershell' = 'bash'): unknown[] {
  return parseInstallCommands(command, { shell }).map((c) => c.manifest);
}

describe('manifest installs — a command that installs what a manifest says', () => {
  it.each([
    'npm install',
    'npm i',
    'npm in',
    'npm ci',
    'npm clean-install',
    'npm ic',
    'npm install-clean',
    'npm install-test',
    'npm it',
    'npm install-ci-test',
    'npm cit',
    'pnpm install',
    'pnpm i',
    'yarn',
    'yarn install',
    'yarn install --immutable',
    'yarn --frozen-lockfile',
    'bun install',
    'bun i',
    'npm ci --ignore-scripts',
    'npm install --no-audit --no-fund',
    'sudo npm ci',
    'env CI=1 npm ci',
  ])('T-01 %s reads the package.json where it runs and names no package', (command) => {
    const found = parseInstallCommands(command);
    expect(found.map((c) => c.manifest)).toEqual([{ kind: 'package-json' }]);
    expect(found.flatMap((c) => c.packages)).toEqual([]);
    expect(found[0]?.ecosystem).toBe('npm');
  });

  it('T-01 from the PowerShell tool too, once; two of them on one line; and the directory a cd moved it to', () => {
    expect(manifests('npm ci', 'powershell')).toEqual([{ kind: 'package-json' }]);
    expect(manifests('npm ci; pnpm install')).toEqual([{ kind: 'package-json' }, { kind: 'package-json' }]);
    const [moved] = parseInstallCommands('cd web && pnpm install --frozen-lockfile');
    expect(moved?.manifest).toEqual({ kind: 'package-json' });
    expect(moved?.workdir).toEqual(['web']);
  });

  it('T-02 pip -r names its requirement files, in order, beside the packages on the line', () => {
    const [c] = parseInstallCommands('pip install -r a.txt -r reqs/b.txt requests');
    expect(c?.manifest).toEqual({ kind: 'requirements', files: ['a.txt', 'reqs/b.txt'] });
    expect(c?.packages.map((p) => p.name)).toEqual(['requests']);
    expect(c?.ecosystem).toBe('pypi');
  });

  it.each<[string, string[]]>([
    ['pip install -r requirements.txt', ['requirements.txt']],
    ['pip install --requirement a.txt', ['a.txt']],
    ['pip install --requirement=a.txt', ['a.txt']],
    ['pip3 install -r a.txt', ['a.txt']],
    ['python -m pip install -r a.txt', ['a.txt']],
    ['uv pip install -r a.txt -r b.txt', ['a.txt', 'b.txt']],
    ['pip install --upgrade -r "my reqs.txt"', ['my reqs.txt']],
  ])('T-02 %s', (command, files) => {
    expect(manifests(command)).toEqual([{ kind: 'requirements', files }]);
  });

  it.each([
    'npm install -g',
    'npm i --global',
    'yarn global add serve',
    'yarn build',
    'yarn --version',
    'yarn -v',
    'yarn --help',
    'npm run install',
    'npm test',
    'pip install requests',
    'pip install -c constraints.txt requests',
    'pip download -r a.txt',
    'echo npm ci',
    'git commit -m "npm ci"',
  ])('T-03 %s is no manifest install', (command) => {
    expect(manifests(command).filter((m) => m !== undefined)).toEqual([]);
  });

  // These were "no manifest install" until install-vet-named-install-manifest: an install that names a package installs
  // the project's manifest too, unless it is global for certain.
  it.each(['npm i ./pkg.tgz', 'npm install express', 'pnpm add left-pad', 'bun add left-pad', 'bun install left-pad'])(
    'T-03 %s names a package (or a file) and reads the manifest of the directory too',
    (command) => {
      expect(manifests(command)).toEqual([{ kind: 'package-json' }]);
    },
  );

  it('T-04 a manifest install in a script the command hands a shell is one too', () => {
    const script = (text: string): Array<{ text: string; shell: 'bash' }> => [{ text, shell: 'bash' }];
    expect(parseInstallCommands("bash -c 'npm ci'", { nested: script('npm ci') }).map((c) => c.manifest)).toEqual([{ kind: 'package-json' }]);
    expect(
      parseInstallCommands('cmd /c "pip install -r r.txt"', { nested: script('pip install -r r.txt') }).map((c) => c.manifest),
    ).toEqual([{ kind: 'requirements', files: ['r.txt'] }]);
    expect(parseInstallCommands("echo 'yarn install' | sh", { nested: script('yarn install') }).map((c) => c.manifest)).toEqual([
      { kind: 'package-json' },
    ]);
    // Where a nested install runs is not known once the outer command moved.
    const moved = parseInstallCommands("cd web && bash -c 'npm ci'", { nested: script('npm ci') });
    expect(moved.map((c) => [c.manifest, c.workdir])).toEqual([[{ kind: 'package-json' }, null]]);
  });
});

// ───────────────── install-vet-pnpm-install-named — `pnpm install <pkg>` is a by-name install

describe('pnpm install with a package name is a `pnpm add` (install-vet-pnpm-install-named)', () => {
  it.each<[string, Array<[string, string | undefined]>]>([
    ['pnpm install crossenv', [['crossenv', undefined]]],
    ['pnpm i crossenv', [['crossenv', undefined]]],
    ['pnpm i -D crossenv@1', [['crossenv', '1']]],
    ['pnpm --filter web install left-pad', [['left-pad', undefined]]],
    ['pnpm install left-pad is-number', [['left-pad', undefined], ['is-number', undefined]]],
  ])('T-01 %s names its packages and reads the manifest too (install-vet-named-install-manifest)', (command, packages) => {
    const found = parseInstallCommands(command);
    expect(found).toHaveLength(1);
    expect(vetted(command)).toEqual(packages);
    expect(found[0]?.manifest).toEqual({ kind: 'package-json' });
    expect(found[0]?.ecosystem).toBe('npm');
    expect(found[0]?.manager).toBe('pnpm');
  });

  it.each([
    ['pnpm install foo', 'pnpm add foo'],
    ['pnpm i foo@1.2.3', 'pnpm add foo@1.2.3'],
    ['pnpm -C ./web install foo', 'pnpm -C ./web add foo'],
    ['pnpm install --dir ./web foo', 'pnpm add --dir ./web foo'],
    ['pnpm --filter web i @acme/ui', 'pnpm --filter web add @acme/ui'],
    ['pnpm install -w @acme/ui', 'pnpm add -w @acme/ui'],
    ['pnpm i --registry https://npm.example.test foo', 'pnpm add --registry https://npm.example.test foo'],
    ['pnpm install ./local.tgz', 'pnpm add ./local.tgz'],
  ])('T-01 %s is read exactly as %s', (install, add) => {
    // Everything the decision reads — the packages, what was skipped, the registries, and above all `uncertain`:
    // empty for both, or a missing name would be denied for `pnpm add` and only warned of for `pnpm install`.
    expect(parseInstallCommands(install)).toHaveLength(1);
    expect(parseInstallCommands(install)).toEqual(parseInstallCommands(add));
  });

  it.each(['pnpm install', 'pnpm i', 'pnpm install --frozen-lockfile', 'pnpm i -D', 'pnpm install --filter web', 'pnpm i --ignore-scripts', 'pnpm -C ./web install'])(
    'T-02 %s is still the manifest install, with no package',
    (command) => {
      const found = parseInstallCommands(command);
      expect(found.map((c) => c.manifest)).toEqual([{ kind: 'package-json' }]);
      expect(found.flatMap((c) => c.packages)).toEqual([]);
    },
  );

  // install-vet-update-verbs: `pnpm update <name>` now installs the manifest (the name selects a dependency, no package is vetted).
  it('T-02 pnpm add is read as before; pnpm install-test is still no install command, and pnpm update names no package', () => {
    expect(vetted('pnpm add left-pad')).toEqual([['left-pad', undefined]]);
    expect(manifests('pnpm add left-pad')).toEqual([{ kind: 'package-json' }]);
    expect(parseInstallCommands('pnpm install-test left-pad')).toEqual([]);
    expect(parseInstallCommands('pnpm it left-pad')).toEqual([]);
    expect(vetted('pnpm update left-pad')).toEqual([]);
    expect(manifests('pnpm update left-pad')).toEqual([{ kind: 'package-json' }]);
    expect(parseInstallCommands('pnpm install -g')).toHaveLength(1);
    expect(manifests('pnpm install -g')).toEqual([undefined]);
  });
});

// ───────────────── pkgvet-archive-like-name — the file endings are the package manager's, not one list for all

describe('pkgvet-archive-like-name', () => {
  /** Every ending a manager of the measured table may read as a file, and a few it never does. */
  const ALL_ENDINGS = [
    '.tgz', '.tar.gz', '.tar', '.zip', '.whl', '.egg', '.nupkg', '.tar.bz2', '.tar.xz', '.tbz', '.txz', '.tlz', '.tar.lz', '.tar.lzma', '.tar.zst',
  ];
  const NPM_FILES = ['.tgz', '.tar.gz', '.tar'];
  const PIP_FILES = ['.zip', '.whl', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tar.xz', '.txz', '.tlz', '.tar.lz', '.tar.lzma'];
  const UV_FILES = ['.zip', '.whl', '.tgz', '.tar.gz', '.tar'];
  const POETRY_FILES = PIP_FILES.filter((e) => e !== '.whl');
  /** What the OLD single list already skipped: the part of the measured table a protection test can hold on HEAD. */
  const OLD_LIST = ['.tgz', '.tar', '.tar.gz', '.tar.bz2', '.tar.xz', '.zip', '.whl', '.egg', '.nupkg'];

  /** The word is a name of this ecosystem, vetted, and nothing about it is skipped or uncertain. */
  function expectName(command: string, name: string): void {
    const cmds = parseInstallCommands(command);
    expect(
      cmds.map((c) => ({ command, packages: c.packages.map((p) => [p.name, p.range]), skipped: c.skipped, uncertain: c.uncertain })),
      command,
    ).toEqual([{ command, packages: [[name, undefined]], skipped: [], uncertain: [] }]);
  }

  /** The word is an archive file for this manager: not vetted, skipped with its reason, nothing said. */
  function expectFile(command: string, word: string): void {
    const cmds = parseInstallCommands(command);
    expect(
      cmds.map((c) => ({ command, packages: c.packages.map((p) => p.name), skipped: c.skipped.map((s) => [s.raw, s.reason]) })),
      command,
    ).toEqual([{ command, packages: [], skipped: [[word, 'archive file — not looked up']] }]);
  }

  /** The names each manager of the table reads from the registry: every ending that is not one of its files. */
  const NAME_CASES: Array<[string, string[]]> = [
    ['npm install', ALL_ENDINGS.filter((e) => !NPM_FILES.includes(e))],
    ['pnpm add', ALL_ENDINGS],
    ['pnpm install', ALL_ENDINGS],
    ['yarn add', ALL_ENDINGS],
    ['bun add', ALL_ENDINGS.filter((e) => !NPM_FILES.includes(e))],
    ['npx', ALL_ENDINGS.filter((e) => !NPM_FILES.includes(e))],
    ['npm exec', ALL_ENDINGS.filter((e) => !NPM_FILES.includes(e))],
    ['bunx', ALL_ENDINGS.filter((e) => !NPM_FILES.includes(e))],
    ['pnpm dlx', ALL_ENDINGS],
    ['yarn dlx', ALL_ENDINGS],
    ['pip install', ALL_ENDINGS.filter((e) => !PIP_FILES.includes(e))],
    ['uv add', ALL_ENDINGS.filter((e) => !UV_FILES.includes(e))],
    ['uv pip install', ALL_ENDINGS.filter((e) => !UV_FILES.includes(e))],
    ['uvx', ALL_ENDINGS.filter((e) => !UV_FILES.includes(e))],
    ['uv tool install', ALL_ENDINGS.filter((e) => !UV_FILES.includes(e))],
    ['poetry add', ALL_ENDINGS.filter((e) => !POETRY_FILES.includes(e))],
  ];

  it('T-02 a bare word that ends like an archive but is a name for its manager is a package, vetted with no reason said', () => {
    for (const [prefix, endings] of NAME_CASES) {
      for (const ending of endings) expectName(`${prefix} thing${ending}`, `thing${ending}`);
    }
  });

  it('T-02 the examples of the plan: lodash.zip, a scoped name for npm, and every launcher', () => {
    expectName('npm install lodash.zip', 'lodash.zip');
    expectName('npm install @s/y.tgz', '@s/y.tgz');
    expectName('npm install @s/y.tar.gz', '@s/y.tar.gz');
    expectName('pnpm add x.tgz', 'x.tgz');
    expectName('pnpm add @s/y.tar', '@s/y.tar');
    expectName('yarn add x.tar', 'x.tar');
    expectName('bun add x.zip', 'x.zip');
    expectName('pip install x.egg', 'x.egg');
    expectName('uv add x.tar.bz2', 'x.tar.bz2');
    expectName('uv pip install x.tbz', 'x.tbz');
    expectName('poetry add x.whl', 'x.whl');
    expectName('npx x.zip', 'x.zip');
    expectName('pnpm dlx x.tgz', 'x.tgz');
    expectName('yarn dlx x.tgz', 'x.tgz');
    expectName('bunx x.zip', 'x.zip');
    expectName('uvx x.egg', 'x.egg');
    expectName('uv tool install x.tar.xz', 'x.tar.xz');
  });

  it('T-02 the endings of pip and poetry that the old list lacked are files for them: skipped, not vetted', () => {
    for (const ending of ['.tbz', '.txz', '.tlz', '.tar.lz', '.tar.lzma']) {
      expectFile(`pip install thing${ending}`, `thing${ending}`);
      expectFile(`poetry add thing${ending}`, `thing${ending}`);
    }
  });

  it('T-02 a short flag the manager takes no value for leaves the next word in a package position: it is a name, and the command is uncertain', () => {
    const cases: Array<[string, string[]]> = [
      ['npm install -r reqs.zip somepkg', ['flag -r is not on the confident-shape allowlist', 'unknown flag -r']],
      ['pnpm add -r reqs.zip somepkg', ['flag -r is not on the confident-shape allowlist']],
    ];
    for (const [command, uncertain] of cases) {
      const cmds = parseInstallCommands(command);
      expect(
        cmds.map((c) => ({ command, packages: c.packages.map((p) => p.name), skipped: c.skipped, uncertain: c.uncertain })),
        command,
      ).toEqual([{ command, packages: ['reqs.zip', 'somepkg'], skipped: [], uncertain }]);
    }
  });

  const FILE_CASES: Array<[string, string[], boolean]> = [
    ['npm install', NPM_FILES, false],
    ['npx', NPM_FILES, false],
    ['bun add', NPM_FILES, true],
    ['bunx', NPM_FILES, true],
    ['pip install', PIP_FILES, false],
    ['uv add', UV_FILES, false],
    ['uv pip install', UV_FILES, false],
    ['uvx', UV_FILES, false],
    ['uv tool install', UV_FILES, false],
    ['poetry add', POETRY_FILES, false],
  ];

  it('T-03 an ending the manager reads as a file stays skipped as an archive file, with no package (the measured endings the old list already held)', () => {
    for (const [prefix, endings, scoped] of FILE_CASES) {
      for (const ending of endings.filter((e) => OLD_LIST.includes(e))) {
        expectFile(`${prefix} thing${ending}`, `thing${ending}`);
        if (scoped) expectFile(`${prefix} @s/thing${ending}`, `@s/thing${ending}`);
      }
    }
  });

  it('T-03 `npm i pkg.tgz` names a file: it is not looked up by name, and the manifest of the directory is read (install-vet-named-install-manifest)', () => {
    for (const command of ['npm i pkg.tgz', 'npm install pkg.tar.gz', 'npm install ./pkg.tgz', 'bun add pkg.tgz']) {
      const cmds = parseInstallCommands(command);
      expect(cmds.map((c) => c.manifest), command).toEqual([{ kind: 'package-json' }]);
    }
  });

  it('T-04 a manager that was not measured: the archive-like word is a package AND the command says why it is uncertain', () => {
    const cases: Array<[string, string]> = [
      ['pipx install x.zip', 'x.zip'],
      ['pipx run x.whl', 'x.whl'],
      ['composer require v/p.zip', 'v/p.zip'],
      ['dotnet add package X.Y.zip', 'X.Y.zip'],
    ];
    for (const [command, name] of cases) {
      const cmds = parseInstallCommands(command);
      expect(cmds.map((c) => c.packages.map((p) => p.name)), command).toEqual([[name]]);
      expect(cmds.map((c) => c.skipped), command).toEqual([[]]);
      const why = cmds[0]?.uncertain ?? [];
      expect(
        why.some((r) => r.toLowerCase().includes('archive')),
        `${command}: a reason in uncertain mentions the archive-like ending, got ${JSON.stringify(why)}`,
      ).toBe(true);
    }
  });

  it('T-04 without an archive-like ending the same commands are uncertain exactly as before', () => {
    for (const command of ['pipx install thing', 'pipx run thing', 'composer require v/pkg', 'dotnet add package Some.Pkg']) {
      expect(parseInstallCommands(command).map((c) => c.uncertain), command).toEqual([[]]);
    }
  });

  /** A command's result as one line — a format for the table below, never an expectation computed at run time. */
  function summarize(command: string): string {
    return parseInstallCommands(command)
      .map((c) => {
        const parts = [`${c.manager}/${c.ecosystem}`];
        if (c.packages.length > 0) parts.push(`P ${c.packages.map((p) => p.name + (p.range === undefined ? '' : `@${p.range}`)).join(' ')}`);
        if (c.skipped.length > 0) parts.push(`S ${c.skipped.map((s) => `${s.raw} => ${s.reason}`).join(' ; ')}`);
        if (c.uncertain.length > 0) parts.push(`U ${c.uncertain.join(' ; ')}`);
        if (c.manifest !== undefined) parts.push(`M ${JSON.stringify(c.manifest)}`);
        if (c.prefixed === true) parts.push('prefixed');
        if (c.customRegistry !== undefined) parts.push(`R ${c.customRegistry}`);
        return parts.join(' | ');
      })
      .join(' || ');
  }

  /**
   * What `parseInstallCommands` gave for each of these commands at c4d7ebd4 (the tree before the fix), written out by
   * hand from one run of it: words with no archive ending — names, versions, paths, URLs, git, protocols — and flag
   * values (`-r reqs.zip`, `--prefix x.tar`) whose archive-like text is no package.
   */
  const BEFORE: ReadonlyArray<readonly [string, string]> = [
    // Not here: `name@x.tgz` and `x@npm:…` for the npm family: no longer "as before", T-10 holds them.
    // Not here: `-r reqs.zip` / `-c cons.whl` for a manager whose table takes no value for `-r` / `-c` (npm, pnpm, yarn, bun, the launchers, poetry's `-c`, pipx, composer, dotnet): the word is then in a package position (see the T-02 test below).
    ["npm install left-pad", "npm/npm | P left-pad | M {\"kind\":\"package-json\"}"],
    ["npm install left-pad@1.3.0", "npm/npm | P left-pad@1.3.0 | M {\"kind\":\"package-json\"}"],
    ["npm install @scope/pkg@^2", "npm/npm | P @scope/pkg@^2 | M {\"kind\":\"package-json\"}"],
    ["npm install v/pkg", "npm/npm | S v/pkg => GitHub shorthand (user/repo) — not looked up | M {\"kind\":\"package-json\"}"],
    ["npm install ./x.tgz", "npm/npm | S ./x.tgz => local path — not looked up | M {\"kind\":\"package-json\"}"],
    ["npm install \"C:\\x.zip\"", "npm/npm | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes) | M {\"kind\":\"package-json\"}"],
    ["npm install /abs/z.tar.gz", "npm/npm | S /abs/z.tar.gz => local path — not looked up | M {\"kind\":\"package-json\"}"],
    ["npm install https://h/x.zip", "npm/npm | S https://h/x.zip => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["npm install git+https://h/r.git", "npm/npm | S git+https://h/r.git => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["npm install github:u/r", "npm/npm | S github:u/r => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["npm install file:../x.tgz", "npm/npm | S file:../x.tgz => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["npm install workspace:*", "npm/npm | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes) | M {\"kind\":\"package-json\"}"],
    ["npm install lodash.zip@4.2.0", "npm/npm | P lodash.zip@4.2.0 | M {\"kind\":\"package-json\"}"],
    ["npm install thing.egg@1.0", "npm/npm | P thing.egg@1.0 | M {\"kind\":\"package-json\"}"],
    ["npm install --prefix x.tar somepkg", "npm/npm | P somepkg | U flag --prefix is not on the confident-shape allowlist ; directory changed by --prefix | M {\"kind\":\"package-json\"} | prefixed"],
    ["npm install --registry https://r.example/x.zip somepkg", "npm/npm | P somepkg | U flag --registry is not on the confident-shape allowlist | M {\"kind\":\"package-json\"} | R https://r.example/x.zip"],
    ["npm install -e ./pkg.tgz somepkg", "npm/npm | P somepkg | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e | M {\"kind\":\"package-json\"}"],
    ["pnpm add left-pad", "pnpm/npm | P left-pad | M {\"kind\":\"package-json\"}"],
    ["pnpm add left-pad@1.3.0", "pnpm/npm | P left-pad@1.3.0 | M {\"kind\":\"package-json\"}"],
    ["pnpm add @scope/pkg@^2", "pnpm/npm | P @scope/pkg@^2 | M {\"kind\":\"package-json\"}"],
    ["pnpm add v/pkg", "pnpm/npm | S v/pkg => GitHub shorthand (user/repo) — not looked up | M {\"kind\":\"package-json\"}"],
    ["pnpm add ./x.tgz", "pnpm/npm | S ./x.tgz => local path — not looked up | M {\"kind\":\"package-json\"}"],
    ["pnpm add \"C:\\x.zip\"", "pnpm/npm | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes) | M {\"kind\":\"package-json\"}"],
    ["pnpm add /abs/z.tar.gz", "pnpm/npm | S /abs/z.tar.gz => local path — not looked up | M {\"kind\":\"package-json\"}"],
    ["pnpm add https://h/x.zip", "pnpm/npm | S https://h/x.zip => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["pnpm add git+https://h/r.git", "pnpm/npm | S git+https://h/r.git => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["pnpm add github:u/r", "pnpm/npm | S github:u/r => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["pnpm add file:../x.tgz", "pnpm/npm | S file:../x.tgz => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["pnpm add workspace:*", "pnpm/npm | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes) | M {\"kind\":\"package-json\"}"],
    ["pnpm add lodash.zip@4.2.0", "pnpm/npm | P lodash.zip@4.2.0 | M {\"kind\":\"package-json\"}"],
    ["pnpm add thing.egg@1.0", "pnpm/npm | P thing.egg@1.0 | M {\"kind\":\"package-json\"}"],
    ["pnpm add --prefix x.tar somepkg", "pnpm/npm | P x.tar somepkg | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix | M {\"kind\":\"package-json\"}"],
    ["pnpm add --registry https://r.example/x.zip somepkg", "pnpm/npm | P somepkg | U flag --registry is not on the confident-shape allowlist | M {\"kind\":\"package-json\"} | R https://r.example/x.zip"],
    ["pnpm add -e ./pkg.tgz somepkg", "pnpm/npm | P somepkg | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e | M {\"kind\":\"package-json\"}"],
    ["yarn add left-pad", "yarn/npm | P left-pad | M {\"kind\":\"package-json\"}"],
    ["yarn add left-pad@1.3.0", "yarn/npm | P left-pad@1.3.0 | M {\"kind\":\"package-json\"}"],
    ["yarn add @scope/pkg@^2", "yarn/npm | P @scope/pkg@^2 | M {\"kind\":\"package-json\"}"],
    ["yarn add v/pkg", "yarn/npm | S v/pkg => GitHub shorthand (user/repo) — not looked up | M {\"kind\":\"package-json\"}"],
    ["yarn add ./x.tgz", "yarn/npm | S ./x.tgz => local path — not looked up | M {\"kind\":\"package-json\"}"],
    ["yarn add \"C:\\x.zip\"", "yarn/npm | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes) | M {\"kind\":\"package-json\"}"],
    ["yarn add /abs/z.tar.gz", "yarn/npm | S /abs/z.tar.gz => local path — not looked up | M {\"kind\":\"package-json\"}"],
    ["yarn add https://h/x.zip", "yarn/npm | S https://h/x.zip => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["yarn add git+https://h/r.git", "yarn/npm | S git+https://h/r.git => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["yarn add github:u/r", "yarn/npm | S github:u/r => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["yarn add file:../x.tgz", "yarn/npm | S file:../x.tgz => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["yarn add workspace:*", "yarn/npm | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes) | M {\"kind\":\"package-json\"}"],
    ["yarn add lodash.zip@4.2.0", "yarn/npm | P lodash.zip@4.2.0 | M {\"kind\":\"package-json\"}"],
    ["yarn add thing.egg@1.0", "yarn/npm | P thing.egg@1.0 | M {\"kind\":\"package-json\"}"],
    ["yarn add --prefix x.tar somepkg", "yarn/npm | P x.tar somepkg | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix | M {\"kind\":\"package-json\"}"],
    ["yarn add --registry https://r.example/x.zip somepkg", "yarn/npm | P somepkg | U flag --registry is not on the confident-shape allowlist | M {\"kind\":\"package-json\"} | R https://r.example/x.zip"],
    ["yarn add -e ./pkg.tgz somepkg", "yarn/npm | P somepkg | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e | M {\"kind\":\"package-json\"}"],
    ["bun add left-pad", "bun/npm | P left-pad | M {\"kind\":\"package-json\"}"],
    ["bun add left-pad@1.3.0", "bun/npm | P left-pad@1.3.0 | M {\"kind\":\"package-json\"}"],
    ["bun add @scope/pkg@^2", "bun/npm | P @scope/pkg@^2 | M {\"kind\":\"package-json\"}"],
    ["bun add v/pkg", "bun/npm | S v/pkg => GitHub shorthand (user/repo) — not looked up | M {\"kind\":\"package-json\"}"],
    ["bun add ./x.tgz", "bun/npm | S ./x.tgz => local path — not looked up | M {\"kind\":\"package-json\"}"],
    ["bun add \"C:\\x.zip\"", "bun/npm | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes) | M {\"kind\":\"package-json\"}"],
    ["bun add /abs/z.tar.gz", "bun/npm | S /abs/z.tar.gz => local path — not looked up | M {\"kind\":\"package-json\"}"],
    ["bun add https://h/x.zip", "bun/npm | S https://h/x.zip => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["bun add git+https://h/r.git", "bun/npm | S git+https://h/r.git => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["bun add github:u/r", "bun/npm | S github:u/r => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["bun add file:../x.tgz", "bun/npm | S file:../x.tgz => URL / VCS / protocol spec — not looked up | M {\"kind\":\"package-json\"}"],
    ["bun add workspace:*", "bun/npm | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes) | M {\"kind\":\"package-json\"}"],
    ["bun add lodash.zip@4.2.0", "bun/npm | P lodash.zip@4.2.0 | M {\"kind\":\"package-json\"}"],
    ["bun add thing.egg@1.0", "bun/npm | P thing.egg@1.0 | M {\"kind\":\"package-json\"}"],
    ["bun add --prefix x.tar somepkg", "bun/npm | P somepkg | S x.tar => archive file — not looked up | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix | M {\"kind\":\"package-json\"}"],
    ["bun add --registry https://r.example/x.zip somepkg", "bun/npm | P somepkg | U flag --registry is not on the confident-shape allowlist | M {\"kind\":\"package-json\"} | R https://r.example/x.zip"],
    ["bun add -c cons.whl somepkg", "bun/npm | P somepkg | U flag -c is not on the confident-shape allowlist | M {\"kind\":\"package-json\"}"],
    ["bun add -e ./pkg.tgz somepkg", "bun/npm | P somepkg | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e | M {\"kind\":\"package-json\"}"],
    ["pip install left-pad", "pip/pypi | P left-pad"],
    ["pip install left-pad@1.3.0", "pip/pypi | P left-pad@1.3.0"],
    ["pip install @scope/pkg@^2", "pip/pypi | S @scope/pkg@^2 => local path — not looked up"],
    ["pip install v/pkg", "pip/pypi | S v/pkg => local path — not looked up"],
    ["pip install ./x.tgz", "pip/pypi | S ./x.tgz => local path — not looked up"],
    ["pip install \"C:\\x.zip\"", "pip/pypi | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["pip install /abs/z.tar.gz", "pip/pypi | S /abs/z.tar.gz => local path — not looked up"],
    ["pip install https://h/x.zip", "pip/pypi | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["pip install git+https://h/r.git", "pip/pypi | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["pip install github:u/r", "pip/pypi | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["pip install file:../x.tgz", "pip/pypi | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["pip install workspace:*", "pip/pypi | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["pip install foo@bar.tgz", "pip/pypi | S foo@bar.tgz => archive file — not looked up"],
    ["pip install lodash.zip@4.2.0", "pip/pypi | P lodash.zip@4.2.0"],
    ["pip install thing.egg@1.0", "pip/pypi | P thing.egg@1.0"],
    ["pip install -r reqs.zip somepkg", "pip/pypi | P somepkg | S reqs.zip => requirements file (-r) — read as a manifest, not as a package name | U flag -r is not on the confident-shape allowlist | M {\"kind\":\"requirements\",\"files\":[\"reqs.zip\"]}"],
    ["pip install --prefix x.tar somepkg", "pip/pypi | P somepkg | U flag --prefix is not on the confident-shape allowlist"],
    ["pip install --registry https://r.example/x.zip somepkg", "pip/pypi | P somepkg | S https://r.example/x.zip => URL / VCS / protocol spec — not looked up | U flag --registry is not on the confident-shape allowlist ; unknown flag --registry"],
    ["pip install -c cons.whl somepkg", "pip/pypi | P somepkg | S cons.whl => constraints file (-c) — not vetted | U flag -c is not on the confident-shape allowlist"],
    ["pip install -e ./pkg.tgz somepkg", "pip/pypi | P somepkg | S ./pkg.tgz => editable install (-e) — local or VCS source, not looked up | U flag -e is not on the confident-shape allowlist"],
    ["uv add left-pad", "uv/pypi | P left-pad"],
    ["uv add left-pad@1.3.0", "uv/pypi | P left-pad@1.3.0"],
    ["uv add @scope/pkg@^2", "uv/pypi | S @scope/pkg@^2 => local path — not looked up"],
    ["uv add v/pkg", "uv/pypi | S v/pkg => local path — not looked up"],
    ["uv add ./x.tgz", "uv/pypi | S ./x.tgz => local path — not looked up"],
    ["uv add \"C:\\x.zip\"", "uv/pypi | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["uv add /abs/z.tar.gz", "uv/pypi | S /abs/z.tar.gz => local path — not looked up"],
    ["uv add https://h/x.zip", "uv/pypi | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["uv add git+https://h/r.git", "uv/pypi | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["uv add github:u/r", "uv/pypi | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["uv add file:../x.tgz", "uv/pypi | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["uv add workspace:*", "uv/pypi | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["uv add foo@bar.tgz", "uv/pypi | S foo@bar.tgz => archive file — not looked up"],
    ["uv add lodash.zip@4.2.0", "uv/pypi | P lodash.zip@4.2.0"],
    ["uv add thing.egg@1.0", "uv/pypi | P thing.egg@1.0"],
    ["uv add -r reqs.zip somepkg", "uv/pypi | P somepkg | S reqs.zip => requirements file (-r) — its contents are not vetted | U flag -r is not on the confident-shape allowlist"],
    ["uv add --prefix x.tar somepkg", "uv/pypi | P somepkg | S x.tar => archive file — not looked up | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix"],
    ["uv add --registry https://r.example/x.zip somepkg", "uv/pypi | P somepkg | S https://r.example/x.zip => URL / VCS / protocol spec — not looked up | U flag --registry is not on the confident-shape allowlist ; unknown flag --registry"],
    ["uv add -c cons.whl somepkg", "uv/pypi | P somepkg | U flag -c is not on the confident-shape allowlist"],
    ["uv add -e ./pkg.tgz somepkg", "uv/pypi | P somepkg | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e"],
    ["uv pip install left-pad", "uv-pip/pypi | P left-pad"],
    ["uv pip install left-pad@1.3.0", "uv-pip/pypi | P left-pad@1.3.0"],
    ["uv pip install @scope/pkg@^2", "uv-pip/pypi | S @scope/pkg@^2 => local path — not looked up"],
    ["uv pip install v/pkg", "uv-pip/pypi | S v/pkg => local path — not looked up"],
    ["uv pip install ./x.tgz", "uv-pip/pypi | S ./x.tgz => local path — not looked up"],
    ["uv pip install \"C:\\x.zip\"", "uv-pip/pypi | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["uv pip install /abs/z.tar.gz", "uv-pip/pypi | S /abs/z.tar.gz => local path — not looked up"],
    ["uv pip install https://h/x.zip", "uv-pip/pypi | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["uv pip install git+https://h/r.git", "uv-pip/pypi | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["uv pip install github:u/r", "uv-pip/pypi | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["uv pip install file:../x.tgz", "uv-pip/pypi | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["uv pip install workspace:*", "uv-pip/pypi | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["uv pip install foo@bar.tgz", "uv-pip/pypi | S foo@bar.tgz => archive file — not looked up"],
    ["uv pip install lodash.zip@4.2.0", "uv-pip/pypi | P lodash.zip@4.2.0"],
    ["uv pip install thing.egg@1.0", "uv-pip/pypi | P thing.egg@1.0"],
    ["uv pip install -r reqs.zip somepkg", "uv-pip/pypi | P somepkg | S reqs.zip => requirements file (-r) — read as a manifest, not as a package name | U flag -r is not on the confident-shape allowlist | M {\"kind\":\"requirements\",\"files\":[\"reqs.zip\"]}"],
    ["uv pip install --prefix x.tar somepkg", "uv-pip/pypi | P somepkg | U flag --prefix is not on the confident-shape allowlist"],
    ["uv pip install --registry https://r.example/x.zip somepkg", "uv-pip/pypi | P somepkg | S https://r.example/x.zip => URL / VCS / protocol spec — not looked up | U flag --registry is not on the confident-shape allowlist ; unknown flag --registry"],
    ["uv pip install -c cons.whl somepkg", "uv-pip/pypi | P somepkg | S cons.whl => constraints file (-c) — not vetted | U flag -c is not on the confident-shape allowlist"],
    ["uv pip install -e ./pkg.tgz somepkg", "uv-pip/pypi | P somepkg | S ./pkg.tgz => editable install (-e) — local or VCS source, not looked up | U flag -e is not on the confident-shape allowlist"],
    ["poetry add left-pad", "poetry/pypi | P left-pad"],
    ["poetry add left-pad@1.3.0", "poetry/pypi | P left-pad@1.3.0"],
    ["poetry add @scope/pkg@^2", "poetry/pypi | S @scope/pkg@^2 => local path — not looked up"],
    ["poetry add v/pkg", "poetry/pypi | S v/pkg => local path — not looked up"],
    ["poetry add ./x.tgz", "poetry/pypi | S ./x.tgz => local path — not looked up"],
    ["poetry add \"C:\\x.zip\"", "poetry/pypi | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["poetry add /abs/z.tar.gz", "poetry/pypi | S /abs/z.tar.gz => local path — not looked up"],
    ["poetry add https://h/x.zip", "poetry/pypi | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["poetry add git+https://h/r.git", "poetry/pypi | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["poetry add github:u/r", "poetry/pypi | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["poetry add file:../x.tgz", "poetry/pypi | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["poetry add workspace:*", "poetry/pypi | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["poetry add foo@bar.tgz", "poetry/pypi | S foo@bar.tgz => archive file — not looked up"],
    ["poetry add lodash.zip@4.2.0", "poetry/pypi | P lodash.zip@4.2.0"],
    ["poetry add thing.egg@1.0", "poetry/pypi | P thing.egg@1.0"],
    ["poetry add -r reqs.zip somepkg", "poetry/pypi | P somepkg | S reqs.zip => archive file — not looked up | U flag -r is not on the confident-shape allowlist ; unknown flag -r"],
    ["poetry add --prefix x.tar somepkg", "poetry/pypi | P somepkg | S x.tar => archive file — not looked up | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix"],
    ["poetry add --registry https://r.example/x.zip somepkg", "poetry/pypi | P somepkg | S https://r.example/x.zip => URL / VCS / protocol spec — not looked up | U flag --registry is not on the confident-shape allowlist ; unknown flag --registry"],
    ["poetry add -e ./pkg.tgz somepkg", "poetry/pypi | P somepkg | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist"],
    ["npx left-pad", "npx/npm | P left-pad"],
    ["npx left-pad@1.3.0", "npx/npm | P left-pad@1.3.0"],
    ["npx @scope/pkg@^2", "npx/npm | P @scope/pkg@^2"],
    ["npx v/pkg", "npx/npm | S v/pkg => GitHub shorthand (user/repo) — not looked up"],
    ["npx ./x.tgz", "npx/npm | S ./x.tgz => local path — not looked up"],
    ["npx \"C:\\x.zip\"", "npx/npm | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["npx /abs/z.tar.gz", "npx/npm | S /abs/z.tar.gz => local path — not looked up"],
    ["npx https://h/x.zip", "npx/npm | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["npx git+https://h/r.git", "npx/npm | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["npx github:u/r", "npx/npm | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["npx file:../x.tgz", "npx/npm | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["npx workspace:*", "npx/npm | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["npx lodash.zip@4.2.0", "npx/npm | P lodash.zip@4.2.0"],
    ["npx thing.egg@1.0", "npx/npm | P thing.egg@1.0"],
    ["npx --prefix x.tar somepkg", "npx/npm | P somepkg | U flag --prefix is not on the confident-shape allowlist | prefixed"],
    ["npx --registry https://r.example/x.zip somepkg", "npx/npm | P somepkg | U flag --registry is not on the confident-shape allowlist | R https://r.example/x.zip"],
    ["npx -c cons.whl somepkg", "npx/npm | U flag -c is not on the confident-shape allowlist"],
    ["npx -e ./pkg.tgz somepkg", "npx/npm | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e"],
    ["pnpm dlx left-pad", "pnpm/npm | P left-pad"],
    ["pnpm dlx left-pad@1.3.0", "pnpm/npm | P left-pad@1.3.0"],
    ["pnpm dlx @scope/pkg@^2", "pnpm/npm | P @scope/pkg@^2"],
    ["pnpm dlx v/pkg", "pnpm/npm | S v/pkg => GitHub shorthand (user/repo) — not looked up"],
    ["pnpm dlx ./x.tgz", "pnpm/npm | S ./x.tgz => local path — not looked up"],
    ["pnpm dlx \"C:\\x.zip\"", "pnpm/npm | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["pnpm dlx /abs/z.tar.gz", "pnpm/npm | S /abs/z.tar.gz => local path — not looked up"],
    ["pnpm dlx https://h/x.zip", "pnpm/npm | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["pnpm dlx git+https://h/r.git", "pnpm/npm | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["pnpm dlx github:u/r", "pnpm/npm | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["pnpm dlx file:../x.tgz", "pnpm/npm | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["pnpm dlx workspace:*", "pnpm/npm | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["pnpm dlx lodash.zip@4.2.0", "pnpm/npm | P lodash.zip@4.2.0"],
    ["pnpm dlx thing.egg@1.0", "pnpm/npm | P thing.egg@1.0"],
    ["pnpm dlx --prefix x.tar somepkg", "pnpm/npm | P x.tar somepkg | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix"],
    ["pnpm dlx --registry https://r.example/x.zip somepkg", "pnpm/npm | P somepkg | U flag --registry is not on the confident-shape allowlist | R https://r.example/x.zip"],
    ["pnpm dlx -c cons.whl somepkg", "pnpm/npm | U flag -c is not on the confident-shape allowlist"],
    ["pnpm dlx -e ./pkg.tgz somepkg", "pnpm/npm | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e"],
    ["yarn dlx left-pad", "yarn/npm | P left-pad"],
    ["yarn dlx left-pad@1.3.0", "yarn/npm | P left-pad@1.3.0"],
    ["yarn dlx @scope/pkg@^2", "yarn/npm | P @scope/pkg@^2"],
    ["yarn dlx v/pkg", "yarn/npm | S v/pkg => GitHub shorthand (user/repo) — not looked up"],
    ["yarn dlx ./x.tgz", "yarn/npm | S ./x.tgz => local path — not looked up"],
    ["yarn dlx \"C:\\x.zip\"", "yarn/npm | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["yarn dlx /abs/z.tar.gz", "yarn/npm | S /abs/z.tar.gz => local path — not looked up"],
    ["yarn dlx https://h/x.zip", "yarn/npm | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["yarn dlx git+https://h/r.git", "yarn/npm | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["yarn dlx github:u/r", "yarn/npm | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["yarn dlx file:../x.tgz", "yarn/npm | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["yarn dlx workspace:*", "yarn/npm | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["yarn dlx lodash.zip@4.2.0", "yarn/npm | P lodash.zip@4.2.0"],
    ["yarn dlx thing.egg@1.0", "yarn/npm | P thing.egg@1.0"],
    ["yarn dlx --prefix x.tar somepkg", "yarn/npm | P x.tar somepkg | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix"],
    ["yarn dlx --registry https://r.example/x.zip somepkg", "yarn/npm | P somepkg | S https://r.example/x.zip => URL / VCS / protocol spec — not looked up | U flag --registry is not on the confident-shape allowlist ; unknown flag --registry"],
    ["yarn dlx -e ./pkg.tgz somepkg", "yarn/npm | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e"],
    ["bunx left-pad", "bun/npm | P left-pad"],
    ["bunx left-pad@1.3.0", "bun/npm | P left-pad@1.3.0"],
    ["bunx @scope/pkg@^2", "bun/npm | P @scope/pkg@^2"],
    ["bunx v/pkg", "bun/npm | S v/pkg => GitHub shorthand (user/repo) — not looked up"],
    ["bunx ./x.tgz", "bun/npm | S ./x.tgz => local path — not looked up"],
    ["bunx \"C:\\x.zip\"", "bun/npm | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["bunx /abs/z.tar.gz", "bun/npm | S /abs/z.tar.gz => local path — not looked up"],
    ["bunx https://h/x.zip", "bun/npm | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["bunx git+https://h/r.git", "bun/npm | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["bunx github:u/r", "bun/npm | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["bunx file:../x.tgz", "bun/npm | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["bunx workspace:*", "bun/npm | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["bunx lodash.zip@4.2.0", "bun/npm | P lodash.zip@4.2.0"],
    ["bunx thing.egg@1.0", "bun/npm | P thing.egg@1.0"],
    ["bunx --prefix x.tar somepkg", "bun/npm | P somepkg | S x.tar => archive file — not looked up | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix"],
    ["bunx --registry https://r.example/x.zip somepkg", "bun/npm | P somepkg | S https://r.example/x.zip => URL / VCS / protocol spec — not looked up | U flag --registry is not on the confident-shape allowlist ; unknown flag --registry"],
    ["bunx -e ./pkg.tgz somepkg", "bun/npm | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e"],
    ["uvx left-pad", "uv/pypi | P left-pad"],
    ["uvx left-pad@1.3.0", "uv/pypi | P left-pad@1.3.0"],
    ["uvx @scope/pkg@^2", "uv/pypi | S @scope/pkg@^2 => local path — not looked up"],
    ["uvx v/pkg", "uv/pypi | S v/pkg => local path — not looked up"],
    ["uvx ./x.tgz", "uv/pypi | S ./x.tgz => local path — not looked up"],
    ["uvx \"C:\\x.zip\"", "uv/pypi | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["uvx /abs/z.tar.gz", "uv/pypi | S /abs/z.tar.gz => local path — not looked up"],
    ["uvx https://h/x.zip", "uv/pypi | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["uvx git+https://h/r.git", "uv/pypi | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["uvx github:u/r", "uv/pypi | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["uvx file:../x.tgz", "uv/pypi | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["uvx workspace:*", "uv/pypi | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["uvx foo@bar.tgz", "uv/pypi | S foo@bar.tgz => archive file — not looked up"],
    ["uvx lodash.zip@4.2.0", "uv/pypi | P lodash.zip@4.2.0"],
    ["uvx thing.egg@1.0", "uv/pypi | P thing.egg@1.0"],
    ["uvx -r reqs.zip somepkg", "uv/pypi | S reqs.zip => archive file — not looked up | U flag -r is not on the confident-shape allowlist ; unknown flag -r"],
    ["uvx --prefix x.tar somepkg", "uv/pypi | P somepkg | S x.tar => archive file — not looked up | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix"],
    ["uvx --registry https://r.example/x.zip somepkg", "uv/pypi | P somepkg | S https://r.example/x.zip => URL / VCS / protocol spec — not looked up | U flag --registry is not on the confident-shape allowlist ; unknown flag --registry"],
    ["uvx -c cons.whl somepkg", "uv/pypi | S cons.whl => archive file — not looked up | U flag -c is not on the confident-shape allowlist ; unknown flag -c"],
    ["uvx -e ./pkg.tgz somepkg", "uv/pypi | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e"],
    ["uv tool install left-pad", "uv/pypi | P left-pad"],
    ["uv tool install left-pad@1.3.0", "uv/pypi | P left-pad@1.3.0"],
    ["uv tool install @scope/pkg@^2", "uv/pypi | S @scope/pkg@^2 => local path — not looked up"],
    ["uv tool install v/pkg", "uv/pypi | S v/pkg => local path — not looked up"],
    ["uv tool install ./x.tgz", "uv/pypi | S ./x.tgz => local path — not looked up"],
    ["uv tool install \"C:\\x.zip\"", "uv/pypi | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["uv tool install /abs/z.tar.gz", "uv/pypi | S /abs/z.tar.gz => local path — not looked up"],
    ["uv tool install https://h/x.zip", "uv/pypi | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["uv tool install git+https://h/r.git", "uv/pypi | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["uv tool install github:u/r", "uv/pypi | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["uv tool install file:../x.tgz", "uv/pypi | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["uv tool install workspace:*", "uv/pypi | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["uv tool install foo@bar.tgz", "uv/pypi | S foo@bar.tgz => archive file — not looked up"],
    ["uv tool install lodash.zip@4.2.0", "uv/pypi | P lodash.zip@4.2.0"],
    ["uv tool install thing.egg@1.0", "uv/pypi | P thing.egg@1.0"],
    ["uv tool install -r reqs.zip somepkg", "uv/pypi | P somepkg | S reqs.zip => archive file — not looked up | U flag -r is not on the confident-shape allowlist ; unknown flag -r"],
    ["uv tool install --prefix x.tar somepkg", "uv/pypi | P somepkg | S x.tar => archive file — not looked up | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix"],
    ["uv tool install --registry https://r.example/x.zip somepkg", "uv/pypi | P somepkg | S https://r.example/x.zip => URL / VCS / protocol spec — not looked up | U flag --registry is not on the confident-shape allowlist ; unknown flag --registry"],
    ["uv tool install -c cons.whl somepkg", "uv/pypi | P somepkg | S cons.whl => archive file — not looked up | U flag -c is not on the confident-shape allowlist ; unknown flag -c"],
    ["uv tool install -e ./pkg.tgz somepkg", "uv/pypi | P somepkg | S ./pkg.tgz => editable install (-e) — local or VCS source, not looked up | U flag -e is not on the confident-shape allowlist"],
    ["pipx install left-pad", "pipx/pypi | P left-pad"],
    ["pipx install left-pad@1.3.0", "pipx/pypi | P left-pad@1.3.0"],
    ["pipx install @scope/pkg@^2", "pipx/pypi | S @scope/pkg@^2 => local path — not looked up"],
    ["pipx install v/pkg", "pipx/pypi | S v/pkg => local path — not looked up"],
    ["pipx install ./x.tgz", "pipx/pypi | S ./x.tgz => local path — not looked up"],
    ["pipx install \"C:\\x.zip\"", "pipx/pypi | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["pipx install /abs/z.tar.gz", "pipx/pypi | S /abs/z.tar.gz => local path — not looked up"],
    ["pipx install https://h/x.zip", "pipx/pypi | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["pipx install git+https://h/r.git", "pipx/pypi | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["pipx install github:u/r", "pipx/pypi | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["pipx install file:../x.tgz", "pipx/pypi | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["pipx install workspace:*", "pipx/pypi | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["pipx install foo@bar.tgz", "pipx/pypi | S foo@bar.tgz => archive file — not looked up"],
    ["pipx install lodash.zip@4.2.0", "pipx/pypi | P lodash.zip@4.2.0"],
    ["pipx install thing.egg@1.0", "pipx/pypi | P thing.egg@1.0"],
    ["pipx install --prefix x.tar somepkg", "pipx/pypi | P x.tar somepkg | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix ; a name that ends like an archive file — this package manager was not measured, so whether it reads the word as a file or as a registry name is not known"],
    ["pipx install --registry https://r.example/x.zip somepkg", "pipx/pypi | P somepkg | S https://r.example/x.zip => URL / VCS / protocol spec — not looked up | U flag --registry is not on the confident-shape allowlist ; unknown flag --registry"],
    ["pipx install -e ./pkg.tgz somepkg", "pipx/pypi | P somepkg | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist"],
    ["pipx run left-pad", "pipx/pypi | P left-pad"],
    ["pipx run left-pad@1.3.0", "pipx/pypi | P left-pad@1.3.0"],
    ["pipx run @scope/pkg@^2", "pipx/pypi | S @scope/pkg@^2 => local path — not looked up"],
    ["pipx run v/pkg", "pipx/pypi | S v/pkg => local path — not looked up"],
    ["pipx run ./x.tgz", "pipx/pypi | S ./x.tgz => local path — not looked up"],
    ["pipx run \"C:\\x.zip\"", "pipx/pypi | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["pipx run /abs/z.tar.gz", "pipx/pypi | S /abs/z.tar.gz => local path — not looked up"],
    ["pipx run https://h/x.zip", "pipx/pypi | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["pipx run git+https://h/r.git", "pipx/pypi | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["pipx run github:u/r", "pipx/pypi | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["pipx run file:../x.tgz", "pipx/pypi | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["pipx run workspace:*", "pipx/pypi | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["pipx run foo@bar.tgz", "pipx/pypi | S foo@bar.tgz => archive file — not looked up"],
    ["pipx run lodash.zip@4.2.0", "pipx/pypi | P lodash.zip@4.2.0"],
    ["pipx run thing.egg@1.0", "pipx/pypi | P thing.egg@1.0"],
    ["pipx run --prefix x.tar somepkg", "pipx/pypi | P x.tar somepkg | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix ; a name that ends like an archive file — this package manager was not measured, so whether it reads the word as a file or as a registry name is not known"],
    ["pipx run --registry https://r.example/x.zip somepkg", "pipx/pypi | P somepkg | S https://r.example/x.zip => URL / VCS / protocol spec — not looked up | U flag --registry is not on the confident-shape allowlist ; unknown flag --registry"],
    ["pipx run -e ./pkg.tgz somepkg", "pipx/pypi | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e"],
    ["composer require left-pad", "composer/packagist | S left-pad => platform package or not a vendor/name — not looked up"],
    ["composer require left-pad@1.3.0", "composer/packagist | S left-pad@1.3.0 => platform package or not a vendor/name — not looked up"],
    ["composer require @scope/pkg@^2", "composer/packagist | S @scope/pkg@^2 => not a valid packagist package name"],
    ["composer require v/pkg", "composer/packagist | P v/pkg"],
    ["composer require ./x.tgz", "composer/packagist | S ./x.tgz => local path — not looked up"],
    ["composer require \"C:\\x.zip\"", "composer/packagist | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["composer require /abs/z.tar.gz", "composer/packagist | S /abs/z.tar.gz => local path — not looked up"],
    ["composer require https://h/x.zip", "composer/packagist | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["composer require git+https://h/r.git", "composer/packagist | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["composer require github:u/r", "composer/packagist | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["composer require file:../x.tgz", "composer/packagist | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["composer require workspace:*", "composer/packagist | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["composer require foo@bar.tgz", "composer/packagist | S foo@bar.tgz => archive file — not looked up"],
    ["composer require lodash.zip@4.2.0", "composer/packagist | S lodash.zip@4.2.0 => platform package or not a vendor/name — not looked up"],
    ["composer require thing.egg@1.0", "composer/packagist | S thing.egg@1.0 => platform package or not a vendor/name — not looked up"],
    ["composer require --prefix x.tar somepkg", "composer/packagist | S x.tar => platform package or not a vendor/name — not looked up ; somepkg => platform package or not a vendor/name — not looked up | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix"],
    ["composer require --registry https://r.example/x.zip somepkg", "composer/packagist | S https://r.example/x.zip => URL / VCS / protocol spec — not looked up ; somepkg => platform package or not a vendor/name — not looked up | U flag --registry is not on the confident-shape allowlist ; unknown flag --registry"],
    ["composer require -e ./pkg.tgz somepkg", "composer/packagist | S ./pkg.tgz => local path — not looked up ; somepkg => platform package or not a vendor/name — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e"],
    ["dotnet add package left-pad", "dotnet/nuget | P left-pad"],
    ["dotnet add package left-pad@1.3.0", "dotnet/nuget | P left-pad@1.3.0"],
    ["dotnet add package @scope/pkg@^2", "dotnet/nuget | S @scope/pkg@^2 => not a valid nuget package name"],
    ["dotnet add package v/pkg", "dotnet/nuget | S v/pkg => not a valid nuget package name"],
    ["dotnet add package ./x.tgz", "dotnet/nuget | S ./x.tgz => local path — not looked up"],
    ["dotnet add package \"C:\\x.zip\"", "dotnet/nuget | S C:\\x.zip => local path — not looked up | U not a single plain install statement ('\\' inside double quotes)"],
    ["dotnet add package /abs/z.tar.gz", "dotnet/nuget | S /abs/z.tar.gz => local path — not looked up"],
    ["dotnet add package https://h/x.zip", "dotnet/nuget | S https://h/x.zip => URL / VCS / protocol spec — not looked up"],
    ["dotnet add package git+https://h/r.git", "dotnet/nuget | S git+https://h/r.git => URL / VCS / protocol spec — not looked up"],
    ["dotnet add package github:u/r", "dotnet/nuget | S github:u/r => URL / VCS / protocol spec — not looked up"],
    ["dotnet add package file:../x.tgz", "dotnet/nuget | S file:../x.tgz => URL / VCS / protocol spec — not looked up"],
    ["dotnet add package workspace:*", "dotnet/nuget | S workspace:* => URL / VCS / protocol spec — not looked up | U not a single plain install statement ('*' outside quotes)"],
    ["dotnet add package foo@bar.tgz", "dotnet/nuget | S foo@bar.tgz => archive file — not looked up"],
    ["dotnet add package lodash.zip@4.2.0", "dotnet/nuget | P lodash.zip@4.2.0"],
    ["dotnet add package thing.egg@1.0", "dotnet/nuget | P thing.egg@1.0"],
    ["dotnet add package --prefix x.tar somepkg", "dotnet/nuget | P x.tar somepkg | U flag --prefix is not on the confident-shape allowlist ; unknown flag --prefix ; a name that ends like an archive file — this package manager was not measured, so whether it reads the word as a file or as a registry name is not known"],
    ["dotnet add package --registry https://r.example/x.zip somepkg", "dotnet/nuget | P somepkg | S https://r.example/x.zip => URL / VCS / protocol spec — not looked up | U flag --registry is not on the confident-shape allowlist ; unknown flag --registry"],
    ["dotnet add package -e ./pkg.tgz somepkg", "dotnet/nuget | P somepkg | S ./pkg.tgz => local path — not looked up | U flag -e is not on the confident-shape allowlist ; unknown flag -e"],
  ];

  it('T-05 every word with no archive ending, and every flag value, reads exactly as it did before', () => {
    const differing = BEFORE.filter(([command, expected]) => summarize(command) !== expected).map(([command, expected]) => ({
      command,
      expected,
      got: summarize(command),
    }));
    expect(differing).toEqual([]);
    expect(BEFORE.length).toBeGreaterThanOrEqual(300);
  });

  /** The package a command names, as `[name, range]` pairs, plus what it skipped (raw and reason). */
  function namedAndSkipped(command: string): { packages: Array<[string, string | undefined]>; skipped: Array<[string, string]> } {
    const cmds = parseInstallCommands(command);
    return {
      packages: cmds.flatMap((c) => c.packages.map((p): [string, string | undefined] => [p.name, p.range])),
      skipped: cmds.flatMap((c) => c.skipped.map((s): [string, string] => [s.raw, s.reason])),
    };
  }

  it('T-10 an alias `x@npm:<name><ending>` names the REAL package for npm and pnpm, and for Yarn and bun the key `x` too: vetted, nothing skipped', () => {
    for (const ending of OLD_LIST) expectName(`npm install x@npm:evil${ending}`, `evil${ending}`);
    expectName('npm install x@npm:evil.zip', 'evil.zip');
    expectName('pnpm add x@npm:evil.tgz', 'evil.tgz');
    // Since pkgvet-yarn-berry-npm-protocol (US-1.AC-3) Yarn and bun read both names: the key `x` and `evil.<ending>`.
    for (const [command, rest] of [['yarn add x@npm:evil.tar', 'evil.tar'], ['bun add x@npm:evil.tgz', 'evil.tgz']] as const) {
      const got = namedAndSkipped(command);
      expect({ command, names: got.packages.map(([n]) => n).sort(), skipped: got.skipped }).toEqual({ command, names: ['x', rest].sort(), skipped: [] });
    }
  });

  it('T-10 `<name>@<tag ending like an archive>` is the package <name> with that tag for a manager that reads no file there', () => {
    const cases: Array<[string, string, string]> = [
      ['npm install evil@foo.zip', 'evil', 'foo.zip'],
      ['pnpm add evil@foo.tgz', 'evil', 'foo.tgz'],
      ['yarn add evil@foo.tgz', 'evil', 'foo.tgz'],
      ['bun add evil@foo.zip', 'evil', 'foo.zip'],
    ];
    for (const [command, name, range] of cases) {
      expect(namedAndSkipped(command), command).toEqual({ packages: [[name, range]], skipped: [] });
    }
  });

  it('T-10 protection: a tag npm and bun read as a file (.tgz .tar.gz .tar) stays skipped as an archive file; a versioned name stays a package', () => {
    for (const prefix of ['npm install', 'bun add']) {
      for (const ending of NPM_FILES) {
        const command = `${prefix} evil@foo${ending}`;
        expect(namedAndSkipped(command), command).toEqual({ packages: [], skipped: [[`evil@foo${ending}`, 'archive file — not looked up']] });
      }
    }
    for (const command of ['pnpm add foo@bar.tgz', 'yarn add foo@bar.tgz', 'pnpm dlx foo@bar.tgz', 'yarn dlx foo@bar.tgz']) {
      expect(namedAndSkipped(command), command).toEqual({ packages: [['foo', 'bar.tgz']], skipped: [] });
    }
    expect(namedAndSkipped('npm install lodash.zip@4.2.0'), 'npm install lodash.zip@4.2.0').toEqual({ packages: [['lodash.zip', '4.2.0']], skipped: [] });
  });

  it('T-10 protection: the versioned forms of Python, Composer and NuGet stay skipped as an archive file', () => {
    for (const command of ['pip install foo@bar.tgz', 'composer require foo@bar.tgz', 'dotnet add package foo@bar.tgz']) {
      expect(namedAndSkipped(command), command).toEqual({ packages: [], skipped: [['foo@bar.tgz', 'archive file — not looked up']] });
    }
  });

  it('T-10 the alias prefix in any letter case is an alias for npm: the real name is the package, the alias name is not, and the lower-case forms stay as they are', () => {
    const cases: Array<[string, Array<[string, string | undefined]>]> = [
      ['npm install x@NPM:evil', [['evil', undefined]]],
      ['npm install x@Npm:evil.zip', [['evil.zip', undefined]]],
      ['npm install x@NPM:evil@^1', [['evil', '^1']]],
      ['npx x@NPM:evil', [['evil', undefined]]],
    ];
    for (const [command, packages] of cases) {
      expect(namedAndSkipped(command), command).toEqual({ packages, skipped: [] });
    }
    expect(namedAndSkipped('npm install x@npm:evil'), 'npm install x@npm:evil').toEqual({ packages: [['evil', undefined]], skipped: [] });
    expect(namedAndSkipped('npm install x@npm:evil@^1'), 'npm install x@npm:evil@^1').toEqual({ packages: [['evil', '^1']], skipped: [] });
  });

  it('T-11 pipx hands the word to pip: an ending pip reads as a file but the old list lacked is a package AND an unmeasured reason', () => {
    for (const ending of ['.tbz', '.txz', '.tlz', '.tar.lz', '.tar.lzma']) {
      const command = `pipx install x${ending}`;
      const cmds = parseInstallCommands(command);
      expect(cmds.map((c) => c.packages.map((p) => p.name)), command).toEqual([[`x${ending}`]]);
      expect(cmds.map((c) => c.skipped), command).toEqual([[]]);
      const why = cmds[0]?.uncertain ?? [];
      expect(
        why.some((r) => r.toLowerCase().includes('archive')),
        `${command}: a reason in uncertain mentions the archive-like ending, got ${JSON.stringify(why)}`,
      ).toBe(true);
    }
  });
});

// ───────────────── install-vet-project-registry-said — "global" is read only when a word says so and no word takes it back

describe('install-vet-project-registry-said', () => {
  /** The `global` the parser gives the single install command of `command`. */
  const globalOf = (command: string): boolean | undefined => {
    const parsed = parseInstallCommands(command);
    expect(parsed, command).toHaveLength(1);
    return parsed[0]?.global;
  };

  it.each([
    'npm install -g x',
    'npm i --global x',
    'npm install --global=true x',
    'npm install --location=global x',
    'npm install --location global x',
    'npm -g install x',
    'npm install -g global-agent',
    'pnpm add -g x',
    'pnpm add --global x',
    'yarn global add x',
    'bun add -g x',
    'bun add --global x',
    'npm install --otp 123456 -g x',
    'npm install -g true x',
    'npm install -g --force x',
    'npm install --save-exact -g x',
    'pnpm add -g --ignore-scripts x',
  ])('T-09 %s: a global install', (command) => {
    expect(globalOf(command)).toBe(true);
  });

  it.each([
    'npm install x',
    'npm install --global=false x',
    'npm install -g=false x',
    'npm install -g false x',
    'npm install --global false x',
    'npm install -g --no-global x',
    'npm install --no-global -g x',
    'npm install -g --global=false x',
    'npm install --location=global --location=project x',
    'npm install -g --location=project x',
    'npm install --location project -g x',
    'npm install x -- -g',
    'npm install -gD x',
    'npm install -g $FLAGS x',
    'npm install -g "$PKG"',
    'pnpm add --global=false x',
    'pnpm add -g false x',
    'pnpm add -g --no-global x',
    'pnpm add --location=global x',
    'pnpm add -g --config.global=false x',
    'pnpm add -g --global-dir /tmp/g x',
    'yarn add -g gdir x',
    'yarn add --global gdir x',
    'yarn add --global=false x',
    'bun add --location=global x',
    'npm install --otp --global x',
    'npm install --otp -g x',
    'npm install --script-shell --global x',
    'npm install --tag --global x',
    'pnpm add --filter -g x',
    'npm i -g --loc=project x',
    'npm i -g --loca=project x',
    'npm i -g --g=false x',
    'npm install -g --foo=bar x',
    'npm install -g --unsafe-perm x',
    'npm --loc=project install -g x',
    'pnpm add -g --frozen x',
  ])('T-09 %s: not certainly global, so not global', (command) => {
    expect(globalOf(command) === true).toBe(false);
  });
});

// ───────────────── install-vet-bare-install-misread — a bare install is read as the manager reads it

describe('install-vet-bare-install-misread', () => {
  /** What the single install command of `command` gives: its packages, its manifest and whether it is global. */
  const read = (command: string): { packages: string[]; manifest: unknown; global: boolean | undefined } => {
    const parsed = parseInstallCommands(command);
    expect(parsed, command).toHaveLength(1);
    const c = parsed[0];
    return { packages: (c?.packages ?? []).map((p) => p.name), manifest: c?.manifest, global: c?.global };
  };
  const MANIFEST = { kind: 'package-json' };

  it.each([
    'npm install --global=false',
    'npm i -g=false',
    'npm install -g --no-global',
    'npm install -g false',
    'npm install --global false',
    'npm install -D false',
    'npm install --force true',
    'pnpm install --global=false',
    'pnpm install -g false',
    'pnpm install --force false',
    'npm install -g $X',
    'npm install -g --location=project',
    'npm ci --global=false',
    'npm install -qD false',
    'npm install -DE false',
    'npm install -g -Dg false',
    'npm install -Dg false',
    'pnpm install -qD false',
    'pnpm install -Dg false',
    'pnpm install -r false',
    'pnpm install --recursive false',
    'pnpm install -w false',
    'pnpm install --workspace-root false',
    'npm -D false install',
    'npm --force true install',
    'npm -g false install',
    'pnpm -D false install',
    'pnpm --force false install',
  ])('T-01 %s: the manifest is installed, and no package is named', (command) => {
    const r = read(command);
    expect({ packages: r.packages, manifest: r.manifest }).toEqual({ packages: [], manifest: MANIFEST });
  });

  it('T-01 npm install -g true is a global install for certain: no package, no manifest', () => {
    expect(read('npm install -g true')).toEqual({ packages: [], manifest: undefined, global: true });
  });

  it.each([
    ['npm install', [], MANIFEST],
    ['npm install -g', [], undefined],
    ['npm install x', ['x'], MANIFEST],
    ['npm install -g x', ['x'], undefined],
    ['npm install --otp -g', [], MANIFEST],
    ['yarn add -D false', ['false'], MANIFEST],
    ['bun add --force false', ['false'], MANIFEST],
    ['npx false', ['false'], undefined],
    ['npm install --unknown-flag false', [], MANIFEST],
    // The loglevel shorthands take no word: the word is a package. A cluster's word belongs to its LAST letter.
    ['npm install --silent true', ['true'], MANIFEST],
    ['npm install --quiet false', ['false'], MANIFEST],
    ['npm install -q false', ['false'], MANIFEST],
    ['npm install --verbose false', ['false'], MANIFEST],
    ['npm install -d false', ['false'], MANIFEST],
    ['npm install -Dq false', ['false'], MANIFEST],
    ['npm install -qd false', ['false'], MANIFEST],
    ['npm install -Dd true', ['true'], MANIFEST],
    ['pnpm install --silent false', ['false'], MANIFEST],
    ['pnpm install -q false', ['false'], MANIFEST],
    ['pnpm install -Dq false', ['false'], MANIFEST],
  ])('T-02 %s: packages %j, manifest %j (a by-name install reads the manifest too; global and launchers do not)', (command, packages, manifest) => {
    const r = read(command);
    expect({ packages: r.packages, manifest: r.manifest }).toEqual({ packages, manifest });
  });
});

// ───────────────── install-vet-unknown-flag-hides-package — a word after a flag the table does not know is also a candidate

describe('install-vet-unknown-flag-hides-package', () => {
  /** What the single install command of `command` gives: its packages, its manifest and the reasons it is uncertain. */
  const read = (command: string): { packages: string[]; manifest: unknown; uncertain: string } => {
    const parsed = parseInstallCommands(command);
    expect(parsed, command).toHaveLength(1);
    const c = parsed[0];
    return { packages: (c?.packages ?? []).map((p) => p.name), manifest: c?.manifest, uncertain: (c?.uncertain ?? []).join(' ; ') };
  };
  const MANIFEST = { kind: 'package-json' };

  it.each([
    'npm install --prefer-dedupe p',
    'npm i --ignore-engines p',
    'npm install --dgunknown p',
    'pnpm add --shamefully-hoist p',
    'yarn add --ignore-engines p',
    'bun add --dgunknown p',
    'pip install --dgunknown p',
    'uv pip install --dgunknown p',
    'npx --ignore-scripts p',
    'bunx --yes p',
  ])('T-01 %s: the word after the unknown flag is a candidate package, and the command is uncertain ("unknown flag")', (command) => {
    const r = read(command);
    expect(r.packages).toContain('p');
    expect(r.uncertain).toMatch(/unknown flag/);
  });

  it('T-01 npm install --dgunknown p q: both words are packages', () => {
    expect(read('npm install --dgunknown p q').packages).toEqual(['p', 'q']);
  });

  it('T-01 npm install --a x --b y p: each unknown flag leaves its word as a candidate', () => {
    expect(read('npm install --a x --b y p').packages).toEqual(['x', 'y', 'p']);
  });

  it('T-02 as before: a value flag of the table, a short flag, an `=` flag, a `--no-` flag and a flag of the table take no candidate', () => {
    expect(read('npm install --registry https://r.example p').packages).toEqual(['p']);
    expect(read('npm install -Z p').packages).toEqual(['p']);
    expect(read('npm install --dgunknown=1 p').packages).toEqual(['p']);
    expect(read('npm install --no-dgunknown p').packages).toEqual(['p']);
    expect(read('npm install --force p').packages).toEqual(['p']);
    expect(read('pip install --no-compile p').packages).toEqual(['p']);
    // pnpm reads `x.tar` as a registry name, so after the unknown `--prefix` it is a candidate package beside `somepkg`;
    // bun reads it as an archive file, which is skipped and said (the manager's own reading of the word, as before).
    expect(read('pnpm add --prefix x.tar somepkg').packages).toEqual(['x.tar', 'somepkg']);
    const bun = parseInstallCommands('bun add --prefix x.tar somepkg')[0];
    expect((bun?.packages ?? []).map((p) => p.name)).toEqual(['somepkg']);
    expect(bun?.skipped).toEqual([{ raw: 'x.tar', reason: expect.stringMatching(/archive file — not looked up/) }]);
  });

  it('T-04 npm install --dgunknown p: p is a candidate AND the manifest is read (p may be the flag value)', () => {
    const r = read('npm install --dgunknown p');
    expect({ packages: r.packages, manifest: r.manifest }).toEqual({ packages: ['p'], manifest: MANIFEST });
  });

  it('T-04 npm install --dgunknown p r: a real package is on the line, and the manifest is read all the same (install-vet-named-install-manifest)', () => {
    const r = read('npm install --dgunknown p r');
    expect({ packages: r.packages, manifest: r.manifest }).toEqual({ packages: ['p', 'r'], manifest: MANIFEST });
  });

  it.each([
    ['npm install --dgunknown false p', ['p']],
    ['pnpm add --dgunknown true p', ['p']],
    ['yarn add --dgunknown false p', ['p']],
    ['yarn add --emoji true lodash', ['lodash']],
    ['bun add --dgunknown true p', ['p']],
    ['npx --dgunknown true p', ['p']],
    // The word is the positional itself, with no unknown flag before it: still a package.
    ['yarn add true', ['true']],
    ['npx false', ['false']],
  ])('T-05 %s: a true / false word after an unknown flag is its value, in every manager — packages %j', (command, packages) => {
    expect(read(command).packages).toEqual(packages);
  });

  it.each([
    'npm --fetch-retries 3 --engine-strict install p',
    'pnpm --fetch-retries 3 --shamefully-hoist add p',
    'yarn --network-concurrency 1 --ignore-engines add p',
    'npm --dgx 1 --dgy install p',
    'npm --dgx 1 --dgy 2 install p',
    'npm --fetch-retries 3 --engine-strict install --prefer-dedupe p',
  ])('T-08 %s: several unknown flags before the subcommand still leave the install, and its package `p`', (command) => {
    expect(read(command).packages).toContain('p');
  });

  it('T-08 npm --dgx x install p stays the launcher `npm x` with the package `install` (what npm itself does)', () => {
    expect(read('npm --dgx x install p').packages).toEqual(['install']);
  });

  // The cost has the shape of a linear growth: 4 000 pairs cost at most 16 times what 500 do (linear reads ~8,
  // quadratic ~64; see test/helpers/timing.ts). Review round 1: 5 000 pairs took 14 to 16 s before the subcommand
  // and in a launcher, past the hook's 15 s limit.
  // Before the subcommand the pair is also written with `x`, which npm reads as its `exec` alias (T-08): another path.
  const PAIR_SHAPES: Array<[string, (n: number) => string]> = [
    ['before the subcommand', (n) => `npm ${'--a y '.repeat(n)}install p`],
    ['before the subcommand, with npm exec alias `x`', (n) => `npm ${'--a x '.repeat(n)}install p`],
    ['after the subcommand', (n) => `npm install ${'--a y '.repeat(n)}p`],
    ['in a launcher', (n) => `npx ${'--a y '.repeat(n)}p`],
  ];
  it.each(PAIR_SHAPES)('T-09 %s: eight times as many `--a y` pairs cost at most 16 times as much', (label, make) => {
    expectLinear(`unknown-flag pairs ${label}`, (n) => void parseInstallCommands(make(n)), 500, { factor: 8, maxRatio: 16 });
  }, 300_000);

  it.each(['npm --fetch-retries 0 install p', 'npm --cache-min 10 install p'])(
    'T-07 %s: the word after the unknown flag is not the subcommand; the install is read',
    (command) => {
      expect(read(command).packages).toContain('p');
    },
  );

  it('T-07 yarn --network-concurrency 1 installs the manifest', () => {
    const r = read('yarn --network-concurrency 1');
    expect({ packages: r.packages, manifest: r.manifest }).toEqual({ packages: [], manifest: MANIFEST });
  });

  it('T-07 yarn --dgunknown build installs the manifest and is uncertain ("unknown flag")', () => {
    const r = read('yarn --dgunknown build');
    expect(r.manifest).toEqual(MANIFEST);
    expect(r.uncertain).toMatch(/unknown flag/);
  });

  it('T-07 yarn build and npm run build are still no install', () => {
    expect(parseInstallCommands('yarn build')).toEqual([]);
    expect(parseInstallCommands('npm run build')).toEqual([]);
  });
});

// ───────────────── install-vet-through-corepack — `corepack <manager> …` and `yarnpkg` are read as the manager they run

describe('install-vet-through-corepack', () => {
  const MANIFEST = { kind: 'package-json' };
  /** Every install command of `command`, whole: what the hook vets is all of it, so the comparison is too. */
  const parsed = (command: string): ReturnType<typeof parseInstallCommands> => parseInstallCommands(command);
  /** What a line gives for vetting: the packages and the manifest it names, whatever the manager's name. */
  const vettable = (command: string): Array<{ packages: string[]; manifest: unknown }> =>
    parseInstallCommands(command).flatMap((c) => (c.packages.length > 0 || c.manifest !== undefined ? [{ packages: c.packages.map((p) => p.name), manifest: c.manifest }] : []));

  const TABLE = [
    'yarn add p', 'yarn install', 'yarn', 'yarn dlx p', 'npm install p', 'npm install', 'npm ci', 'npm exec p', 'npx p',
    'pnpm add p', 'pnpm install', 'pnpm dlx p', 'pnpx p', 'yarn add -D p', 'npm install -g p',
    'npm install-test', 'yarn global add p', 'yarn workspace w add p', 'npx --yes p', 'yarn add --dgunknown p',
  ];

  it.each(TABLE)('T-01 `corepack` before `%s`, with no version, @1.2.3, @^4 or @latest, reads as the line without it', (line) => {
    const base = parsed(line);
    // The table must be a real install for the property to say anything: an empty parse equals an empty parse.
    expect(vettable(line), line).not.toEqual([]);
    const space = line.indexOf(' ');
    const manager = space === -1 ? line : line.slice(0, space);
    const rest = space === -1 ? '' : line.slice(space);
    // The whole parse is compared — packages with names, ranges and `raw`, manifest, global, uncertain, manager — since
    // `corepack` is a prefix the package manager receives no part of: nothing observable may differ from the base line.
    for (const command of [`corepack ${line}`, `corepack ${manager}@1.2.3${rest}`, `corepack ${manager}@^4${rest}`, `corepack ${manager}@latest${rest}`]) {
      expect({ command, parse: parsed(command) }).toEqual({ command, parse: base });
    }
  });

  it('T-01 `corepack npx --yes p`, a flag of the launcher after the manager, reads as `npx --yes p`', () => {
    expect(vettable('npx --yes p')).toEqual([{ packages: ['p'], manifest: undefined }]);
    expect(parsed('corepack npx --yes p')).toEqual(parsed('npx --yes p'));
  });

  it('T-01 EC-2 `corepack yarn@$V add p` names the same package as `yarn add p`; the variable makes the line uncertain, which only warns', () => {
    const [c] = parsed('corepack yarn@$V add p');
    const [base] = parsed('yarn add p');
    expect(c?.packages).toEqual(base?.packages);
    expect({ manager: c?.manager, manifest: c?.manifest }).toEqual({ manager: base?.manager, manifest: base?.manifest });
    expect(base?.uncertain).toEqual([]);
    expect((c?.uncertain ?? []).join(' ; ')).toMatch(/'\$' outside quotes/);
  });

  it.each([
    ['env X=1 corepack yarn add p', 'env X=1 yarn add p'],
    ['sudo corepack npm install -g p', 'sudo npm install -g p'],
    ['corepack yarn add evil@npm:latest', 'yarn add evil@npm:latest'],
  ])('T-01 EC-3 / EC-4 %s reads as %s', (line, plain) => {
    expect(vettable(plain), plain).not.toEqual([]);
    expect(parsed(line)).toEqual(parsed(plain));
  });

  it('T-02 the words as an argument or inside a string are no install; as a package name they are one', () => {
    for (const command of ['grep corepack README.md', 'echo "use corepack yarn add left-pad"', 'git commit -m "corepack yarn add left-pad"', 'cat docs/yarnpkg.md', 'npm view corepack']) {
      expect({ command, parse: parsed(command) }).toEqual({ command, parse: [] });
    }
    expect(vettable('npm install corepack')).toEqual([{ packages: ['corepack'], manifest: MANIFEST }]);
    expect(vettable('yarn add yarnpkg')).toEqual([{ packages: ['yarnpkg'], manifest: MANIFEST }]);
  });

  it('T-02 not installs: what corepack does with its own cache, a name it does not know, and a flag before the manager', () => {
    for (const command of [
      'corepack enable', 'corepack disable', 'corepack install', 'corepack install -g yarn@4.18.1', 'corepack prepare yarn@4.18.1 --activate',
      'corepack pack', 'corepack cache clean', 'corepack hydrate f.tgz', 'corepack YARN add p', 'corepack bun add p',
      'corepack --verbose yarn add p', 'corepack -- yarn add p',
    ]) {
      expect({ command, vetted: vettable(command) }).toEqual({ command, vetted: [] });
    }
  });

  it('T-02 as before: the same commands without `corepack` give what they gave', () => {
    expect(vettable('yarn add p')).toEqual([{ packages: ['p'], manifest: MANIFEST }]);
    expect(vettable('npm install')).toEqual([{ packages: [], manifest: MANIFEST }]);
    expect(vettable('bun add p')).toEqual([{ packages: ['p'], manifest: MANIFEST }]);
    expect(vettable('enable')).toEqual([]);
  });

  it.each(['yarnpkg add p', 'yarnpkg install', 'yarnpkg', 'yarnpkg global add p', 'yarnpkg add -D p', 'yarnpkg dlx p'])(
    'T-04 %s gives what `yarn` gives for the same words',
    (line) => {
      const asYarn = `yarn${line.slice('yarnpkg'.length)}`;
      expect(vettable(asYarn), asYarn).not.toEqual([]);
      expect(parsed(line)).toEqual(parsed(asYarn));
    },
  );

  it.each(['corepack use npm@11.19.0', 'corepack use pnpm@latest', 'corepack use yarn@4.18.1', 'corepack up'])(
    'T-04 %s is an install of the project manifest, naming no package',
    (command) => {
      expect(vettable(command)).toEqual([{ packages: [], manifest: MANIFEST }]);
    },
  );
});

// ───────────────── install-vet-named-install-manifest — an install that names a package also installs the manifest

describe('install-vet-named-install-manifest', () => {
  const MANIFEST = { kind: 'package-json' };
  /** What the single install command of `command` gives: its packages, its manifest and whether it is global. */
  const read = (command: string): { packages: string[]; manifest: unknown; global: boolean | undefined } => {
    const parsed = parseInstallCommands(command);
    expect(parsed, command).toHaveLength(1);
    const c = parsed[0];
    return { packages: (c?.packages ?? []).map((p) => p.name), manifest: c?.manifest, global: c?.global };
  };

  it.each([
    'npm install p',
    'npm i p',
    'npm add p',
    'npm install p --no-save',
    'pnpm add p',
    'pnpm install p',
    'yarn add p',
    'yarn workspace w add p',
    'bun add p',
    'bun install p',
  ])('T-01 %s: the package is named AND the manifest is read', (command) => {
    const r = read(command);
    expect({ packages: r.packages, manifest: r.manifest }).toEqual({ packages: ['p'], manifest: MANIFEST });
  });

  it.each([
    'npm install -g p',
    'npm install --location=global p',
    'pnpm add -g p',
    'bun add -g p',
    'yarn global add p',
    'npx p',
    'npm exec p',
    'pnpm dlx p',
    'yarn dlx p',
    'bunx p',
  ])('T-02 %s: the package is named and the manifest is NOT read (global for certain, or a launcher)', (command) => {
    const r = read(command);
    expect({ packages: r.packages, manifest: r.manifest }).toEqual({ packages: ['p'], manifest: undefined });
  });

  it('T-02 when "global" is in doubt (`npm install -g $X p`) the manifest is read: vet too much, never too little', () => {
    const r = read('npm install -g $X p');
    expect(r.global).not.toBe(true);
    expect(r.manifest).toEqual(MANIFEST);
  });

  it.each(['npm i ./pkg.tgz', 'pnpm add ./pkg.tgz', 'npm install https://x.example/p.tgz'])(
    'T-03 %s: no package is vetted by name, and the manifest is read',
    (command) => {
      const r = read(command);
      expect({ packages: r.packages, manifest: r.manifest }).toEqual({ packages: [], manifest: MANIFEST });
    },
  );
});

// ───────────────── install-vet-update-verbs — the update and maintenance verbs install the manifest

describe('install-vet-update-verbs', () => {
  const MANIFEST = { kind: 'package-json' };
  /** What a line gives for vetting: per install command, the packages it names and the manifest it reads. */
  const vettable = (command: string): Array<{ packages: string[]; manifest: unknown }> =>
    parseInstallCommands(command).map((c) => ({ packages: c.packages.map((p) => p.name), manifest: c.manifest }));
  /** What the line is, in what matters for vetting: manager, ecosystem, packages, manifest and whether it is global. */
  const essence = (command: string): unknown =>
    parseInstallCommands(command).map((c) => ({
      manager: c.manager,
      ecosystem: c.ecosystem,
      packages: c.packages.map((p) => p.name),
      manifest: c.manifest,
      global: c.global,
    }));

  it.each([
    'npm update',
    'npm upgrade',
    'npm up',
    'npm update lodash',
    'pnpm update',
    'pnpm up',
    'pnpm upgrade',
    'pnpm update --latest',
    'pnpm update lodash',
    'yarn upgrade',
    'yarn upgrade lodash',
    'yarn upgrade --latest',
    'yarn up lodash',
    "yarn up '*'",
    'bun update',
    'bun update lodash',
    'bun update --latest',
    'yarn upgrade-interactive',
  ])('T-01 `%s` is a manifest install that names no package (the names after an update verb select dependencies)', (command) => {
    expect(vettable(command)).toEqual([{ packages: [], manifest: MANIFEST }]);
  });

  it.each([
    ['npm u', 'npm update'],
    ['npm udpate', 'npm update'],
    ['npm audit --json fix', 'npm audit fix'],
    ['npm audit fix --dry-run', 'npm audit fix'],
    ['pnpm update --interactive', 'pnpm update'],
    ['pnpm up -i', 'pnpm update'],
  ])('T-01 `%s` reads as `%s` (an npm alias, or a flag that does not change the verb)', (command, plain) => {
    expect(vettable(plain), plain).toEqual([{ packages: [], manifest: MANIFEST }]);
    expect({ command, parse: essence(command) }).toEqual({ command, parse: essence(plain) });
  });

  it.each(['npm install', 'npm ci', 'pnpm install', 'yarn install', 'bun install'])('T-02 guard: `%s` is still a manifest install that names no package', (command) => {
    expect(vettable(command)).toEqual([{ packages: [], manifest: MANIFEST }]);
  });

  it.each([
    'npm outdated',
    'npm rebuild',
    'npm run update',
    'npm audit',
    'npm audit signatures',
    'pnpm outdated',
    'yarn outdated',
    'bun outdated',
    'npm view lodash',
  ])('T-02 guard: `%s` is no install', (command) => {
    expect({ command, parse: parseInstallCommands(command) }).toEqual({ command, parse: [] });
  });

  it.each(['npm update -g', 'pnpm update -g'])('T-02 guard: `%s` is global for certain and reads no manifest', (command) => {
    expect({ command, manifests: parseInstallCommands(command).flatMap((c) => (c.manifest === undefined ? [] : [c.manifest])) }).toEqual({ command, manifests: [] });
  });

  it.each([
    ['corepack npm update', 'npm update'],
    ['corepack pnpm@latest update', 'pnpm update'],
    ['corepack yarn@4.18.1 up lodash', 'yarn up lodash'],
    ['corepack yarn dedupe', 'yarn dedupe'],
  ])('T-01 / T-04 through corepack: `%s` reads as `%s`', (command, plain) => {
    expect(vettable(plain), plain).toEqual([{ packages: [], manifest: MANIFEST }]);
    expect({ command, parse: parseInstallCommands(command) }).toEqual({ command, parse: parseInstallCommands(plain) });
  });

  it.each([
    ['npm dedupe', 'npm install'],
    ['npm ddp', 'npm install'],
    ['npm prune', 'npm install'],
    ['npm audit fix', 'npm install'],
    ['npm audit fix --force', 'npm install'],
    ['pnpm dedupe', 'pnpm install'],
    ['yarn dedupe', 'yarn install'],
    ['yarn up', 'yarn install'],
  ])('T-04 `%s` reads as `%s` (manager, ecosystem, packages, manifest, global), and is a manifest install', (command, install) => {
    // Non-vacuous: the comparison line is a real manifest install, so an empty parse cannot equal it.
    expect(vettable(install), install).toEqual([{ packages: [], manifest: MANIFEST }]);
    expect({ command, parse: essence(command) }).toEqual({ command, parse: essence(install) });
  });
});

// ───────────────── install-vet-dotnet-forms — `dotnet package add` and `dotnet tool install` ask NuGet for the package too

describe('install-vet-dotnet-forms', () => {
  /** What a line is, in what matters for vetting: manager, ecosystem, packages (name and range), what was skipped and said uncertain. */
  const essence = (command: string): unknown =>
    parseInstallCommands(command).map((c) => ({
      ecosystem: c.ecosystem,
      packages: c.packages.map((p) => [p.name, p.range]),
      skipped: c.skipped,
      uncertain: c.uncertain,
    }));
  /** The same, without the uncertainty: for the forms whose uncertainty the spec does not pin down. */
  const packagesOf = (command: string): unknown =>
    parseInstallCommands(command).map((c) => ({ ecosystem: c.ecosystem, packages: c.packages.map((p) => [p.name, p.range]), skipped: c.skipped }));

  it.each([
    ['dotnet package add Some.Pkg', 'dotnet add package Some.Pkg', [['Some.Pkg', undefined]]],
    ['dotnet package add Some.Pkg --version 1.2.3', 'dotnet add package Some.Pkg --version 1.2.3', [['Some.Pkg', '1.2.3']]],
    ['dotnet package add Some.Pkg.nupkg', 'dotnet add package Some.Pkg.nupkg', [['Some.Pkg.nupkg', undefined]]],
  ] as const)('T-01 `%s` reads as `%s`: NuGet package %j', (command, oldForm, expected) => {
    // Non-vacuous: the old form is pinned to the expectation, so an empty parse cannot equal it.
    expect(vetted(oldForm), oldForm).toEqual(expected);
    expect(vetted(command), command).toEqual(expected);
    expect(essence(command), `${command} against ${oldForm}`).toEqual(essence(oldForm));
  });

  it('T-01 `dotnet package add Some.Pkg --project app.csproj` gives the NuGet package, the project word is no package', () => {
    const command = 'dotnet package add Some.Pkg --project app.csproj';
    expect(ecosystems(command)).toEqual(['nuget']);
    expect(vetted(command)).toEqual([['Some.Pkg', undefined]]);
    expect(packagesOf(command)).toEqual(packagesOf('dotnet add package Some.Pkg'));
    // The project is a flag here: the NuGet configuration next to it is not read, as for `dotnet add <project> package`.
    const projectReason = parseInstallCommands('dotnet add app.csproj package Some.Pkg')
      .flatMap((c) => c.uncertain)
      .filter((u) => u.includes('project argument'));
    expect(projectReason).toHaveLength(1);
    expect(parseInstallCommands(command).flatMap((c) => c.uncertain)).toEqual(expect.arrayContaining(projectReason));
  });

  it.each([
    ['dotnet tool install some.tool', [['some.tool', undefined]]],
    ['dotnet tool install -g some.tool', [['some.tool', undefined]]],
    ['dotnet tool install --global some.tool --version 1.0.0', [['some.tool', '1.0.0']]],
    ['dotnet tool install --tool-path ./t some.tool', [['some.tool', undefined]]],
    ['dotnet tool install --local some.tool', [['some.tool', undefined]]],
    ['dotnet tool install some.tool.zip', [['some.tool.zip', undefined]]],
    ['dotnet tool install some.tool.nupkg', [['some.tool.nupkg', undefined]]],
  ] as const)('T-01 `%s` is a NuGet install of %j: the flag values are no package', (command, expected) => {
    expect(ecosystems(command), command).toEqual(['nuget']);
    expect(vetted(command), command).toEqual(expected);
  });

  it('T-02 guard: `dotnet add package` is read as before', () => {
    expect(vetted('dotnet add package Some.Pkg')).toEqual([['Some.Pkg', undefined]]);
    expect(ecosystems('dotnet add package Some.Pkg')).toEqual(['nuget']);
    expect(parseInstallCommands('dotnet add package Some.Pkg').map((c) => c.uncertain)).toEqual([[]]);
    expect(vetted('dotnet add app.csproj package Some.Pkg')).toEqual([['Some.Pkg', undefined]]);
    expect(ecosystems('dotnet add app.csproj package Some.Pkg')).toEqual(['nuget']);
    expect(
      parseInstallCommands('dotnet add app.csproj package Some.Pkg').some((c) => c.uncertain.some((u) => /project/.test(u))),
      'the project argument is said as an uncertainty',
    ).toBe(true);
  });

  it.each([
    'dotnet build',
    'dotnet restore',
    'dotnet tool list',
    'dotnet tool run some.tool',
    'dotnet tool uninstall some.tool',
    'dotnet package list',
    'dotnet package remove Some.Pkg',
  ])('T-02 guard: `%s` is no install', (command) => {
    expect(parseInstallCommands(command)).toEqual([]);
  });

  it('T-04 `dotnet tool install` with no name gives no package', () => {
    expect(vetted('dotnet tool install')).toEqual([]);
    expect(vetted('dotnet tool install -g')).toEqual([]);
    // Non-vacuous: the form is read (an install of the NuGet ecosystem), it just names nothing.
    expect(ecosystems('dotnet tool install -g')).toEqual(['nuget']);
  });

  it('T-04 `dotnet tool install a b` vets `a` and says `b` is an extra argument', () => {
    const [cmd, ...rest] = parseInstallCommands('dotnet tool install a b');
    expect(rest).toEqual([]);
    expect(cmd?.packages.map((p) => p.name)).toEqual(['a']);
    expect(cmd?.skipped).toEqual([{ raw: 'b', reason: expect.stringMatching(/unexpected extra argument/) }]);
  });

  it('T-04 `--add-source <url>` is no package: the URL is recorded as the command\'s registry', () => {
    const url = 'https://feed.example/v3/index.json';
    const [cmd] = parseInstallCommands(`dotnet tool install some.tool --add-source ${url}`);
    expect(cmd?.packages.map((p) => p.name)).toEqual(['some.tool']);
    expect(cmd?.skipped).toEqual([]);
    expect(cmd?.customRegistry).toBe(url);
  });

  it('T-04 `dotnet tool install $TOOL` is skipped and said, never vetted', () => {
    const [cmd] = parseInstallCommands('dotnet tool install $TOOL');
    expect(cmd?.ecosystem).toBe('nuget');
    expect(cmd?.packages).toEqual([]);
    expect(cmd?.skipped.map((s) => s.raw)).toEqual(['$TOOL']);
  });

  // The flag tables of the two new forms (the SDK 10.0.404 help): each test fails when its entry leaves the table, because the
  // flag is then unknown and the word after it is a candidate package, or the source is no longer a registry of its own.
  /** The command's own reading: packages, the uncertainty that says a flag is unknown, and the registry it names. */
  const reading = (command: string): { packages: string[][]; unknownFlags: string[]; skipped: string[]; registry: string | undefined } => {
    const cmds = parseInstallCommands(command);
    return {
      packages: cmds.flatMap((c) => c.packages.map((p) => [p.name, p.range ?? ''])),
      unknownFlags: cmds.flatMap((c) => c.uncertain.filter((u) => u.startsWith('unknown flag'))),
      skipped: cmds.flatMap((c) => c.skipped.map((s) => s.raw)),
      registry: cmds[0]?.customRegistry,
    };
  };

  it.each([
    ['dotnet tool install -v diag some.tool', 'diag'],
    ['dotnet tool install --verbosity diag some.tool', 'diag'],
    ['dotnet tool install some.tool -v diag', 'diag'],
  ])('review 1: `%s`: `-v` / `--verbosity` is the MSBuild verbosity, its value is neither a package nor a version', (command, value) => {
    expect(reading(command)).toEqual({ packages: [['some.tool', '']], unknownFlags: [], skipped: [], registry: undefined });
    expect(command).toContain(value);
  });

  it.each([
    ['dotnet package add Some.Pkg -v 1.2.3', '1.2.3'],
    ['dotnet package add -v 1.2.3 Some.Pkg', '1.2.3'],
    ['dotnet add package Some.Pkg -v 1.2.3', '1.2.3'],
  ])('review 1: `%s`: `-v` is the version of the package', (command, version) => {
    expect(reading(command)).toEqual({ packages: [['Some.Pkg', version]], unknownFlags: [], skipped: [], registry: undefined });
  });

  it.each([
    ['dotnet tool install --configfile ./nuget.config some.tool', './nuget.config'],
    ['dotnet tool install --source https://feed.example/v3/index.json some.tool', 'https://feed.example/v3/index.json'],
    ['dotnet tool install --add-source https://feed.example/v3/index.json some.tool', 'https://feed.example/v3/index.json'],
    ['dotnet package add Some.Pkg --source https://feed.example/v3/index.json', 'https://feed.example/v3/index.json'],
    ['dotnet package add Some.Pkg -s https://feed.example/v3/index.json', 'https://feed.example/v3/index.json'],
  ])('review 1: `%s`: the source is a registry of its own, as in `dotnet add package`', (command, registry) => {
    const r = reading(command);
    expect(r.registry).toBe(registry);
    expect(r.packages).toHaveLength(1);
    expect(r.unknownFlags).toEqual([]);
  });

  it.each([
    'dotnet tool install -a arm64 some.tool',
    'dotnet tool install --arch arm64 some.tool',
    'dotnet tool install --tool-manifest ./.config/dotnet-tools.json some.tool',
    'dotnet tool install --tool-path ./t some.tool',
    'dotnet tool install --framework net10.0 some.tool',
    'dotnet package add --file app.cs Some.Pkg',
    'dotnet package add --project app.csproj Some.Pkg',
    'dotnet package add --package-directory ./pk Some.Pkg',
    'dotnet package add --framework net10.0 Some.Pkg',
  ])('review 1: `%s`: the flag takes the next word, which is not looked up as a package', (command) => {
    const r = reading(command);
    expect(r.packages.map((p) => p[0])).toEqual([command.endsWith('some.tool') ? 'some.tool' : 'Some.Pkg']);
    expect(r.unknownFlags).toEqual([]);
    expect(r.skipped).toEqual([]);
  });
});

// ───────────────── pkgvet-yarn-berry-npm-protocol — `key@npm:rest` is the registry protocol for Yarn and bun, an alias for npm and pnpm

describe('pkgvet-yarn-berry-npm-protocol', () => {
  /** The names a line would vet, sorted: the order of two readings of one word is not what is pinned. */
  const namesOf = (command: string): string[] => vetted(command).map(([name]) => name).sort();
  const uncertainOf = (command: string): string[] => parseInstallCommands(command).flatMap((c) => c.uncertain);

  // `yarn dlx` and `yarn workspace w add` read the spec like `yarn add`.
  const BERRY_PREFIXES = ['yarn add', 'bun add', 'yarn dlx', 'yarn workspace w add'] as const;

  it.each(
    BERRY_PREFIXES.flatMap((prefix) =>
      (
        [
          ['evil-pkg-zq@npm:^1.2.3', 'evil-pkg-zq'],
          ['evil-pkg-zq@npm:*', 'evil-pkg-zq'],
          ["'evil-pkg-zq@npm:>=1.0.0'", 'evil-pkg-zq'],
          ['evil-pkg-zq@NPM:^1', 'evil-pkg-zq'],
          ['@scope-zq/evil-pkg-zq@npm:^1', '@scope-zq/evil-pkg-zq'],
        ] as const
      ).map(([spec, key]) => [prefix, spec, key] as const),
    ),
  )('T-01 `%s %s`: the rest is no package name, the package is the key %s', (prefix, spec, key) => {
    expect(namesOf(`${prefix} ${spec}`)).toEqual([key]);
  });

  it.each(
    BERRY_PREFIXES.flatMap((prefix) =>
      (
        [
          ['evil-pkg-zq@npm:latest', 'evil-pkg-zq', 'latest'],
          ['evil-pkg-zq@npm:1.0.0', 'evil-pkg-zq', '1.0.0'],
          ['evil-pkg-zq@npm:1.x', 'evil-pkg-zq', '1.x'],
          ['alias-zq@npm:real-zq', 'alias-zq', 'real-zq'],
          ['evil-pkg-zq@NPM:latest', 'evil-pkg-zq', 'latest'],
          ['@scope-zq/evil-pkg-zq@npm:1.0.0', '@scope-zq/evil-pkg-zq', '1.0.0'],
        ] as const
      ).map(([spec, key, rest]) => [prefix, spec, key, rest] as const),
    ),
  )('T-01 `%s %s`: a valid name without a range of its own, both %s and %s are vetted, the command is uncertain', (prefix, spec, key, rest) => {
    const command = `${prefix} ${spec}`;
    expect(namesOf(command)).toEqual([key, rest].sort());
    expect(uncertainOf(command).length, 'the two readings are said as an uncertainty').toBeGreaterThan(0);
  });

  // The other managers, and a rest that carries its own range, are read as before.
  const SAME_FOR_ALL = ['npm install', 'pnpm add', 'yarn add', 'bun add'] as const;

  it.each(['npm install', 'pnpm add'] as const)('T-02 guard: `%s` reads `key@npm:rest` as an alias, only the rest is vetted', (prefix) => {
    expect(vetted(`${prefix} evil-pkg-zq@npm:latest`)).toEqual([['latest', undefined]]);
    expect(vetted(`${prefix} alias-zq@npm:real-zq`)).toEqual([['real-zq', undefined]]);
    const [cmd] = parseInstallCommands(`${prefix} evil-pkg-zq@npm:^1.2.3`);
    expect(cmd?.packages).toEqual([]);
    expect(cmd?.skipped.map((s) => s.raw)).toEqual(['evil-pkg-zq@npm:^1.2.3']);
  });

  it.each(SAME_FOR_ALL)('T-02 guard: `%s` reads a rest with a range of its own as an alias of the rest', (prefix) => {
    expect(vetted(`${prefix} alias-zq@npm:real-zq@1.0.0`)).toEqual([['real-zq', '1.0.0']]);
    expect(vetted(`${prefix} alias-zq@npm:@scope-zq/real-zq@^2`)).toEqual([['@scope-zq/real-zq', '^2']]);
  });

  it.each(SAME_FOR_ALL)('T-02 guard: `%s` skips a rest that is a path or a shell expansion', (prefix) => {
    for (const spec of ['evil-pkg-zq@npm:./x.tgz', 'evil-pkg-zq@npm:$X']) {
      const [cmd] = parseInstallCommands(`${prefix} ${spec}`);
      expect(cmd?.packages, spec).toEqual([]);
      expect(cmd?.skipped.map((s) => s.raw), spec).toEqual([spec]);
    }
  });

  it.each(['yarn add', 'bun add'] as const)('T-01 `%s`: a key read both ways keeps a rest that is a version or a range as its range, a word leaves it with none; the second name never has one', (prefix) => {
    const read = (spec: string): Array<[string, string | undefined]> => vetted(`${prefix} ${spec}`);
    expect(read('evil-pkg-zq@npm:1.0.0')).toEqual([['evil-pkg-zq', '1.0.0'], ['1.0.0', undefined]]);
    expect(read('evil-pkg-zq@npm:1.x')).toEqual([['evil-pkg-zq', '1.x'], ['1.x', undefined]]);
    expect(read('evil-pkg-zq@npm:1.2')).toEqual([['evil-pkg-zq', '1.2'], ['1.2', undefined]]);
    expect(read('evil-pkg-zq@npm:1.0.0-beta.1')).toEqual([['evil-pkg-zq', '1.0.0-beta.1'], ['1.0.0-beta.1', undefined]]);
    expect(read('evil-pkg-zq@npm:latest')).toEqual([['evil-pkg-zq', undefined], ['latest', undefined]]);
    expect(read('alias-zq@npm:real-zq')).toEqual([['alias-zq', undefined], ['real-zq', undefined]]);
    expect(read('evil-pkg-zq@npm:evil.tar')).toEqual([['evil-pkg-zq', undefined], ['evil.tar', undefined]]);
  });

  // ── round 1 of the review (T-06)

  it.each(['yarn add', 'bun add'] as const)('T-06 `%s`: a rest that is `~` and a version is a range for the key, `~/x` and `~user/x` stay paths', (prefix) => {
    expect(vetted(`${prefix} evil-pkg-zq@npm:~1.2.3`)).toEqual([['evil-pkg-zq', '~1.2.3']]);
    expect(vetted(`${prefix} evil-pkg-zq@npm:~1`)).toEqual([['evil-pkg-zq', '~1']]);
    for (const spec of ['evil-pkg-zq@npm:~/x', 'evil-pkg-zq@npm:~user-zq/x']) {
      const [cmd] = parseInstallCommands(`${prefix} ${spec}`);
      expect(cmd?.packages, spec).toEqual([]);
      expect(cmd?.skipped.map((s) => s.raw), spec).toEqual([spec]);
    }
  });

  it.each(['npm install', 'pnpm add'] as const)('T-06 guard: `%s` reads `key@npm:~1.2.3` as before: a path, skipped', (prefix) => {
    const [cmd] = parseInstallCommands(`${prefix} evil-pkg-zq@npm:~1.2.3`);
    expect(cmd?.packages).toEqual([]);
    expect(cmd?.skipped.map((s) => s.raw)).toEqual(['evil-pkg-zq@npm:~1.2.3']);
  });

  it.each(['yarn add', 'bun add'] as const)('T-06 `%s`: the range of the key is the rest only when the rest is a range; an empty rest is the key', (prefix) => {
    expect(vetted(`${prefix} evil-pkg-zq@npm:^1.2.3`)).toEqual([['evil-pkg-zq', '^1.2.3']]);
    expect(vetted(`${prefix} lodash-zq@npm:user/repo`)).toEqual([['lodash-zq', undefined]]);
    expect(vetted(`${prefix} 'lodash-zq@npm:foo bar'`)).toEqual([['lodash-zq', undefined]]);
    expect(vetted(`${prefix} evil-pkg-zq@npm:`)).toEqual([['evil-pkg-zq', undefined]]);
  });

  it.each([
    ['yarn add x@npm:evil.tar', 'evil.tar'],
    ['bun add x@npm:evil.tgz', 'evil.tgz'],
  ] as const)('T-06 (EC-5) `%s` vets both names, nothing skipped', (command, rest) => {
    expect(namesOf(command)).toEqual(['x', rest].sort());
    expect(parseInstallCommands(command).flatMap((c) => c.skipped)).toEqual([]);
  });

  it('T-06 the two readings are said once per command: the first word and how many more are like it', () => {
    const words = Array.from({ length: 5 }, (_, i) => `k${i}-zq@npm:latest`);
    const reasons = parseInstallCommands(`yarn add ${words.join(' ')}`)
      .flatMap((c) => c.uncertain)
      .filter((u) => u.includes(' is read two ways'));
    expect(reasons).toHaveLength(1);
    expect(reasons[0]).toContain('k0-zq@npm:latest');
    expect(reasons[0]).toContain('and 4 more words like it');
    const one = parseInstallCommands('yarn add k0-zq@npm:latest').flatMap((c) => c.uncertain).filter((u) => u.includes(' is read two ways'));
    expect(one).toHaveLength(1);
    expect(one[0]).not.toContain('more word');
  });
});

// ───────────────── install-vet-npm-exec-bool-word — a launcher line is read as the launcher reads it

describe('install-vet-npm-exec-bool-word', () => {
  const MANIFEST = { kind: 'package-json' };
  /** The names a line would vet, sorted: the order of two readings of one word is not what is pinned. */
  const namesOf = (command: string): string[] => vetted(command).map(([name]) => name).sort();
  const uncertainOf = (command: string): string[] => parseInstallCommands(command).flatMap((c) => c.uncertain);
  const manifestsOf = (command: string): unknown[] => parseInstallCommands(command).map((c) => c.manifest);
  const NPM_EXEC = ['npm exec', 'npm x'] as const;

  it.each(
    NPM_EXEC.flatMap((prefix) =>
      [
        '--yes true p',
        '--yes false p',
        '-y true p',
        '-qy true p',
        '-dy false p',
        '--prefer-offline false p',
        '--prefer-online false p',
        '--ignore-existing false p',
        '--workspaces false p',
        '--include-workspace-root false p',
        '--yes false -- p',
      ].map((rest) => [prefix, rest] as const),
    ),
  )('T-01 `%s %s`: the word after a boolean flag of npm is its value, the package is p', (prefix, rest) => {
    expect(namesOf(`${prefix} ${rest}`), `${prefix} ${rest}`).toEqual(['p']);
  });

  it('T-01 `npm --yes false exec p` gives p and no `false`', () => {
    expect(namesOf('npm --yes false exec p')).toEqual(['p']);
  });

  it.each(NPM_EXEC)('T-01 `%s --yes true` alone names no package', (prefix) => {
    expect(namesOf(`${prefix} --yes true`)).toEqual([]);
  });

  it.each(
    NPM_EXEC.flatMap((prefix) =>
      ['--silent false p', '--quiet false p', '-q false p', '-d false p', '-s false p', '-yq false p', '--yes=true false p', '-- false p'].map(
        (rest) => [prefix, rest] as const,
      ),
    ),
  )('T-01 `%s %s`: after a loglevel shortcut, an `=` flag or `--` the word is the package: false', (prefix, rest) => {
    expect(namesOf(`${prefix} ${rest}`), `${prefix} ${rest}`).toContain('false');
  });

  it('T-02 guard: the plain launchers give p', () => {
    for (const command of ['npx p', 'npm exec p', 'pnpm dlx p', 'yarn dlx p', 'bunx p']) {
      expect({ command, names: namesOf(command) }).toEqual({ command, names: ['p'] });
    }
  });

  it('T-02 guard: `npx --yes false p` is read as before, the package is false', () => {
    expect(namesOf('npx --yes false p')).toEqual(['false']);
  });

  it.each(['npx --no-install p', 'npx --no p', "npx -c 'p --help'"])('T-02 guard: `%s` names no package (nothing is downloaded, or the line is a shell command)', (command) => {
    expect(namesOf(command)).toEqual([]);
    // Non-vacuous: the line is read as a launcher command, it names nothing.
    expect(parseInstallCommands(command)).toHaveLength(1);
  });

  it('T-02 guard: `npx -p p cmd` gives p', () => {
    expect(namesOf('npx -p p cmd')).toEqual(['p']);
  });

  it('T-02 guard: `pnpm exec p` is no install', () => {
    expect(parseInstallCommands('pnpm exec p')).toEqual([]);
  });

  it.each(['yarn add -D false', 'bun add --force false'])('T-02 guard: `%s` gives the package false', (command) => {
    expect(namesOf(command)).toEqual(['false']);
  });

  it.each(NPM_EXEC)('T-04 `%s --ignore-scripts p` gives p with no uncertainty (the flag is npm\'s own, boolean)', (prefix) => {
    const command = `${prefix} --ignore-scripts p`;
    expect(namesOf(command)).toEqual(['p']);
    expect(uncertainOf(command)).toEqual([]);
  });

  it.each(NPM_EXEC)('T-04 `%s -p false p`: `-p` is a boolean flag of npm, the package is p', (prefix) => {
    expect(namesOf(`${prefix} -p false p`)).toEqual(['p']);
  });

  it.each(NPM_EXEC)('T-04 `%s --no-install p`: the flag does not stop the download, p is vetted', (prefix) => {
    expect(namesOf(`${prefix} --no-install p`)).toEqual(['p']);
  });

  it.each(NPM_EXEC)('T-04 `%s --package=p cmd` and `--package p -- cmd` give p', (prefix) => {
    expect(namesOf(`${prefix} --package=p cmd`)).toEqual(['p']);
    expect(namesOf(`${prefix} --package p -- cmd`)).toEqual(['p']);
  });

  it.each([
    'npm exec --no false p',
    'npm exec --offline false p',
    'npx --no false p',
    'pnpm dlx -c false p',
    'pnpm dlx --shell-mode false p',
  ])('T-05 `%s`: p is vetted and the command is uncertain', (command) => {
    expect(namesOf(command)).toEqual(['p']);
    expect(uncertainOf(command).length, 'the two readings are said as an uncertainty').toBeGreaterThan(0);
  });

  it.each(['npx --offline false p', 'npx --no-install false p', 'npx --no-yes false p'])(
    'T-05 `%s`: the word is the flag\'s value, p is vetted and the command is uncertain',
    (command) => {
      expect(namesOf(command)).toEqual(['p']);
      expect(uncertainOf(command).length, 'the two readings are said as an uncertainty').toBeGreaterThan(0);
    },
  );

  it.each(['npx --offline p', 'npx --no-install p', 'npx --no p'])('T-05 guard: `%s` without the word names no package', (command) => {
    expect(namesOf(command)).toEqual([]);
    expect(parseInstallCommands(command)).toHaveLength(1);
  });

  it.each(['npx -qy false p', 'bunx --quiet false p', 'pnpm dlx --silent false p'])(
    'T-05 `%s`: both false and p are vetted and the command is uncertain',
    (command) => {
      expect(namesOf(command)).toEqual(['false', 'p']);
      expect(uncertainOf(command).length, 'the two readings are said as an uncertainty').toBeGreaterThan(0);
    },
  );

  it.each(['pnpm dlx -c p', 'pnpm dlx --shell-mode p', 'pnpx -c p', "pnpm dlx --package p -c 'echo x'"])(
    'T-06 `%s`: the one word is the package p',
    (command) => {
      expect(namesOf(command)).toEqual(['p']);
    },
  );

  it('T-06 `pnpm dlx -c \'p --version\'` (several words) names no package', () => {
    expect(namesOf("pnpm dlx -c 'p --version'")).toEqual([]);
    // Non-vacuous: the line is read as a launcher command, it names nothing.
    expect(parseInstallCommands("pnpm dlx -c 'p --version'")).toHaveLength(1);
  });

  it.each(['yarn --production false', 'yarn --production true', 'yarn install --production false', 'bun install --production true'])(
    'T-07 `%s` is an install of the manifest, uncertain',
    (command) => {
      expect(manifestsOf(command), command).toEqual([MANIFEST]);
      expect(uncertainOf(command).length, 'the two readings are said as an uncertainty').toBeGreaterThan(0);
    },
  );

  // EC-5 (review round 1): no measured manager installs the word between `--production` and the subcommand as a package.
  it.each(['yarn --production false', 'yarn --production true'])('T-07 `%s` reads the manifest and vets no package (EC-5)', (command) => {
    expect(namesOf(command)).toEqual([]);
  });

  it('T-07 `bun install --production true` still vets the word `true` as a package', () => {
    expect(namesOf('bun install --production true')).toEqual(['true']);
  });

  it('T-07 `yarn add --production true p` vets p and true and reads the manifest', () => {
    expect(namesOf('yarn add --production true p')).toEqual(['p', 'true']);
    expect(manifestsOf('yarn add --production true p')).toEqual([MANIFEST]);
    expect(uncertainOf('yarn add --production true p').length).toBeGreaterThan(0);
  });

  it.each(['yarn --production', 'bun install --production'])('T-07 `%s` without a word is read as before: the manifest, no package', (command) => {
    expect(manifestsOf(command), command).toEqual([MANIFEST]);
    expect(namesOf(command)).toEqual([]);
  });

  // ── T-08 (review round 1)
  const TWO_WAYS = 'is read two ways';
  const saysTwoWays = (command: string): boolean => uncertainOf(command).some((u) => u.includes(TWO_WAYS));

  it.each(['npm exec -sy true p', 'npm exec -sy false p', 'npm x -sy true p', 'npm install -sD true p'])(
    'T-08 `%s`: `-s` is a boolean flag of npm; a group that does not end in a loglevel letter takes the word as its value, p is the package',
    (command) => {
      // npm 11.20.0 (measured 2026-11-20): -sy / -sD ask for P; the LAST letter decides.
      expect(namesOf(command), command).toEqual(['p']);
    },
  );

  it('T-08 `npm exec -ys false p` and `npm install -Ds true p`: `-s` last is a loglevel flag, the word is a package', () => {
    expect(namesOf('npm exec -ys false p')).toEqual(['false']);
    expect(namesOf('npm install -Ds true p')).toEqual(['p', 'true']);
  });

  it.each(['yarn --production true', 'yarn --production false'])('T-08 `%s`: the manifest is read, no package, uncertain with the two readings said (EC-5)', (command) => {
    expect(manifestsOf(command)).toEqual([MANIFEST]);
    expect(namesOf(command)).toEqual([]);
    expect(saysTwoWays(command), 'the reason names the two readings').toBe(true);
  });

  it.each(['yarn --production true add p', 'yarn --production false add p'])('T-08 `%s`: the rest is read as the subcommand says, p is vetted, the word is not (EC-5)', (command) => {
    expect(namesOf(command)).toEqual(['p']);
    expect(manifestsOf(command)).toEqual([MANIFEST]);
    expect(saysTwoWays(command)).toBe(true);
  });

  it.each(['yarn --production false upgrade', 'yarn --production false install'])('T-08 `%s`: the manifest, no package, uncertain (EC-5)', (command) => {
    expect(manifestsOf(command)).toEqual([MANIFEST]);
    expect(namesOf(command)).toEqual([]);
    expect(saysTwoWays(command)).toBe(true);
  });

  it('T-08 guard: after the subcommand the word is looked up, for Yarn and for bun (EC-4)', () => {
    expect(namesOf('bun install --production true')).toEqual(['true']);
    expect(namesOf('yarn add --production true p')).toEqual(['p', 'true']);
    expect(manifestsOf('bun install --production true')).toEqual([MANIFEST]);
  });

  it.each(['npx --no=true p', 'npx --no=false p', 'npx --offline=false p'])('T-08 `%s`: p is vetted and no reason says two readings (a flag with `=` takes no word)', (command) => {
    expect(namesOf(command)).toEqual(['p']);
    expect(saysTwoWays(command)).toBe(false);
  });

  it('T-08 `yarn dlx -q false p`: both words are vetted, uncertain with the two readings said', () => {
    expect(namesOf('yarn dlx -q false p')).toEqual(['false', 'p']);
    expect(saysTwoWays('yarn dlx -q false p')).toBe(true);
  });

  it.each(['pnpm dlx --quiet false p', 'pnpm dlx --verbose false p'])('T-08 `%s`: the word and p are vetted, uncertain with the two readings said', (command) => {
    expect(namesOf(command)).toEqual(['false', 'p']);
    expect(saysTwoWays(command)).toBe(true);
  });

  it('T-08 `pnpm dlx -p false p`: `-p` is a boolean flag, p is the package', () => {
    expect(namesOf('pnpm dlx -p false p')).toEqual(['p']);
  });

  it('T-08 `pnpm dlx -c \'p --version\'` names nothing and skips nothing (a command, not a name)', () => {
    const cmds = parseInstallCommands("pnpm dlx -c 'p --version'");
    expect(cmds).toHaveLength(1);
    expect(cmds.flatMap((c) => c.skipped)).toEqual([]);
  });

  it.each(['npm exec -c p', 'npm exec --call p', 'npm exec --no p', 'npm exec --offline p', 'npm x --no p'])('T-08 `%s` names no package', (command) => {
    expect(namesOf(command)).toEqual([]);
    expect(parseInstallCommands(command)).toHaveLength(1);
  });

  it('T-08 `npm exec --registry <url> p` is a registry of its own; `-w ws p` is a workspace context', () => {
    const url = 'https://reg.example/';
    expect(parseInstallCommands(`npm exec --registry ${url} p`).map((c) => c.customRegistry)).toEqual([url]);
    expect(uncertainOf('npm exec -w ws p')).toContain('workspace context (-w)');
    expect(namesOf('npm exec -w ws p')).toEqual(['p']);
  });

  it.each([
    'npm exec --no false p',
    'npm exec --offline false p',
    'npx --no false p',
    'npx --no-install false p',
    'pnpm dlx -c false p',
    'pnpm dlx --shell-mode false p',
    'npx -qy false p',
    'bunx --quiet false p',
    'pnpm dlx --silent false p',
    'yarn --production false',
  ])('T-08 `%s`: the uncertainty says the two readings, in words', (command) => {
    expect(saysTwoWays(command), command).toBe(true);
  });
});

// ───────────────── install-vet-tilde-range-skipped — `pkg@~1.0.0` is a package and a range, not a path that starts with `~`

describe('install-vet-tilde-range-skipped', () => {
  const skippedOf = (command: string): string[] => parseInstallCommands(command).flatMap((c) => c.skipped.map((s) => s.raw));

  // Every install and launcher line of the npm family, with its subject word.
  const LINES = [
    'npm install',
    'npm i -D',
    'npm install -g',
    'pnpm add',
    'yarn add',
    'yarn global add',
    'bun add',
    'npx',
    'npm exec',
    'pnpm dlx',
    'yarn dlx',
    'bunx',
  ] as const;

  const NAME = 'tilde-pkg-zq';
  const SCOPED = '@scope-zq/tilde-pkg-zq';

  it.each(
    LINES.flatMap((line) =>
      (
        [
          [`${NAME}@~1.0.0`, NAME, '~1.0.0'],
          [`${NAME}@~1`, NAME, '~1'],
          [`${NAME}@~1.0.x`, NAME, '~1.0.x'],
          [`${SCOPED}@~1.0.0`, SCOPED, '~1.0.0'],
          [`"${NAME}@~1.2.3 || ~2.0.0"`, NAME, '~1.2.3 || ~2.0.0'],
        ] as const
      ).map(([spec, name, range]) => [line, spec, name, range] as const),
    ),
  )('T-01 `%s %s`: the package %s with the range %s, nothing skipped', (line, spec, name, range) => {
    const command = `${line} ${spec}`;
    expect(vetted(command), command).toEqual([[name, range]]);
    expect(skippedOf(command), command).toEqual([]);
  });

  it.each(['npm install', 'pnpm add', 'yarn add', 'bun add', 'npx', 'pnpm dlx'] as const)(
    'T-01 `%s alias@npm:real@~1.0.0` is the package `real` with the range, nothing skipped',
    (line) => {
      const command = `${line} alias-zq@npm:real-zq@~1.0.0`;
      expect(vetted(command), command).toEqual([['real-zq', '~1.0.0']]);
      expect(skippedOf(command), command).toEqual([]);
    },
  );

  it.each(['npm install', 'pnpm add', 'yarn add', 'bun add', 'npx', 'bunx'] as const)(
    'T-02 guard: `%s` still skips a path, whole or after the `@`, as a local path',
    (line) => {
      for (const word of ['~/pasta', `${NAME}@~/x`, `${NAME}@~user-zq/x`, `${NAME}@./x`, `${NAME}@../x`]) {
        const command = `${line} ${word}`;
        expect(vetted(command), command).toEqual([]);
        expect(skippedOf(command), command).toEqual([word]);
      }
    },
  );

  // Round 1 of the review (T-06): a `~` that does not open a path is a registry spec — the package is vetted, with the range when
  // the hook reads one and without when it does not. These replace the two cases of T-02 that said `~` and `~abc` are skipped.
  const TILDE_WORDS = ['~x', '~X', '~x.x.x', '~*.*', '"~ 1"', '~', '~abc', '~latest'] as const;
  const ALL_LINES = ['npm install', 'pnpm add', 'yarn add', 'bun add', 'npx', 'npm exec', 'pnpm dlx', 'yarn dlx', 'bunx'] as const;

  it.each(ALL_LINES.flatMap((line) => TILDE_WORDS.map((word) => [line, word] as const)))(
    'T-06 `%s %s` after the name: the package is vetted, with no range, nothing skipped',
    (line, word) => {
      const spec = word.startsWith('"') ? `"${NAME}@${word.slice(1)}` : `${NAME}@${word}`;
      const command = `${line} ${spec}`;
      expect(vetted(command), command).toEqual([[NAME, undefined]]);
      expect(skippedOf(command), command).toEqual([]);
    },
  );

  it.each(TILDE_WORDS.map((word) => [word] as const))('T-06 the tool reads `name@%s` as the package, with no range', (word) => {
    const raw = `${NAME}@${word.replaceAll('"', '')}`;
    const r = parsePackageSpec('npm', raw);
    expect('name' in r, raw).toBe(true);
    expect(r, raw).toMatchObject({ name: NAME });
    expect('range' in r ? r.range : undefined, raw).toBeUndefined();
  });

  it.each(ALL_LINES)('T-06 `%s`: a tilde that opens a path stays a path, skipped', (line) => {
    for (const word of [`${NAME}@~/x`, `${NAME}@~user-zq/x`, `${NAME}@~1/x`, '~/pasta']) {
      const command = `${line} ${word}`;
      expect(vetted(command), command).toEqual([]);
      expect(skippedOf(command), command).toEqual([word]);
    }
  });

  it('T-06 a tilde followed by a backslash is a path: skipped, in a command (quoted) and for the tool', () => {
    const raw = `${NAME}@~\\x`;
    expect(vetted(`npm install '${raw}'`)).toEqual([]);
    expect(skippedOf(`npm install '${raw}'`)).toEqual([raw]);
    expect(parsePackageSpec('npm', raw)).toMatchObject({ raw });
    expect('name' in parsePackageSpec('npm', raw)).toBe(false);
  });

  it('T-06 `name@~1.0.0.tgz` follows the list of files of the manager of files: skipped for npm and bun, vetted for pnpm and Yarn, as `name@1.0.0.tgz`', () => {
    for (const word of ['~1.0.0.tgz', '~1.tar.gz', '1.0.0.tgz']) {
      for (const line of ['npm install', 'bun add']) expect(vetted(`${line} ${NAME}@${word}`), `${line} ${word}`).toEqual([]);
      for (const line of ['pnpm add', 'yarn add']) expect(vetted(`${line} ${NAME}@${word}`), `${line} ${word}`).toEqual([[NAME, word]]);
    }
  });

  it.each(['npm install', 'pnpm add', 'yarn add', 'bun add', 'npx'] as const)('T-02 guard: `%s` reads the other ranges as today', (line) => {
    expect(vetted(`${line} ${NAME}@^1.0.0`)).toEqual([[NAME, '^1.0.0']]);
    expect(vetted(`${line} ${NAME}@1.0.0`)).toEqual([[NAME, '1.0.0']]);
    expect(vetted(`${line} "${NAME}@>=1 <2"`)).toEqual([[NAME, '>=1 <2']]);
    expect(vetted(`${line} ${NAME}@latest`)).toEqual([[NAME, undefined]]);
  });

  it('T-02 guard: pip and composer read their own `~` as today, and give the package', () => {
    expect(vetted(`pip install "${NAME}~=1.0"`)).toEqual([[NAME, '~=1.0']]);
    expect(vetted('composer require vendor-zq/tilde-pkg-zq:~1.0')).toEqual([['vendor-zq/tilde-pkg-zq', '~1.0']]);
  });
});

// ───────────────── install-vet-npm-unread-verbs — the initializers and `npm install-test <package>` are read

describe('install-vet-npm-unread-verbs', () => {
  const X = 'dgprobe-zzq7731-init';
  const S = '@dgprobe-zzq7731';
  const MANIFEST = { kind: 'package-json' };

  /** What each install command of a line gives: the packages as `[name, range, raw]`, the manifest and whether it is a launch that looks in the project first. */
  const shapes = (command: string): Array<{ packages: Array<[string, string | undefined, string]>; manifest: unknown; localFirst: unknown }> =>
    parseInstallCommands(command).map((c) => ({
      packages: c.packages.map((p): [string, string | undefined, string] => [p.name, p.range, p.raw]),
      manifest: c.manifest,
      localFirst: c.localFirst,
    }));
  /** The one command an initializer line is: one package, no manifest, no `localFirst`. */
  const initializer = (name: string, range: string | undefined, raw: string): unknown[] => [
    { packages: [[name, range, raw]], manifest: undefined, localFirst: undefined },
  ];

  describe('initializers', () => {
    /** The words an initializer takes, each with what the manager looks up for it (`create-<x>`, `@s/create`, `@s/create-<x>`). */
    const WORDS: Array<[string, string, string | undefined]> = [
      [X, `create-${X}`, undefined],
      [`${X}@1.2.3`, `create-${X}`, '1.2.3'],
      [`${X}@latest`, `create-${X}`, undefined],
      [`${X}@^1`, `create-${X}`, '^1'],
      [S, `${S}/create`, undefined],
      [`${S}@1.2.3`, `${S}/create`, '1.2.3'],
      [`${S}/${X}`, `${S}/create-${X}`, undefined],
      [`${S}/${X}@1.2.3`, `${S}/create-${X}`, '1.2.3'],
    ];
    const LINES: Array<[string, string]> = [
      ['npm create', ''],
      ['npm init', ''],
      ['npm innit', ''],
      ['yarn create', ''],
      ['pnpm create', ' my-app'],
      ['bun create', ' dest'],
      ['bun c', ''],
    ];

    it.each(LINES.flatMap(([line, after]) => WORDS.map(([word, name, range]) => [line, word, after, name, range] as const)))(
      'T-01 `%s %s%s` gives one command, the package %s with the range %s and the word as written',
      (line, word, after, name, range) => {
        expect(shapes(`${line} ${word}${after}`), `${line} ${word}${after}`).toEqual(initializer(name, range, word));
      },
    );

    it.each([
      [`npm init -y ${X}`, `create-${X}`, X],
      [`npm init --silent ${X} my-app`, `create-${X}`, X],
      [`npm init ${X} -- --template react`, `create-${X}`, X],
      ['bun create App.tsx', 'create-App.tsx', 'App.tsx'],
      [`pnpm create -C sub ${X}`, `create-${X}`, X],
      [`yarn create --cwd ./sub ${X}`, `create-${X}`, X],
      [`npm --dgunknown create ${X}`, `create-${X}`, X],
      [`corepack yarn@4 create ${X}`, `create-${X}`, X],
      [`yarnpkg create ${X}`, `create-${X}`, X],
    ])('T-01 `%s` gives one command, which looks up %s, with nothing of the initializer arguments', (command, name, raw) => {
      expect(shapes(command), command).toEqual(initializer(name, undefined, raw));
    });

    // What today's parser answers, written out: the forms that fetch nothing, and the verbs the work leaves as they are.
    it.each(['npm init', 'npm init -y', 'yarn create', 'pnpm create'])('T-05 `%s` names no initializer: no command', (command) => {
      expect(parseInstallCommands(command)).toEqual([]);
    });

    it.each(['npm link', 'npm link P', 'npm pack P', 'npm view P'])('T-05 `%s` is not an install command: no command', (command) => {
      expect(parseInstallCommands(command)).toEqual([]);
    });

    it.each(['npm init user/repo', 'npm init ./folder', 'bun create user/repo'])('T-05 `%s` is not a registry name: no command', (command) => {
      expect(parseInstallCommands(command)).toEqual([]);
    });

    // The word as written decides, not what a `create-` in front would make of it: `npm init .` is not the package `create-.`.
    it.each([
      'npm init .',
      'npm init ..',
      'npm init ~',
      'npm create ~/templates/app',
      'yarn create .',
      'pnpm create ..',
      'bun create .',
      'npm init template.tgz',
      'npm init https://example.invalid/template.tgz',
    ])('T-05 `%s` names a path, an archive or a URL, not a registry name: no command', (command) => {
      expect(parseInstallCommands(command)).toEqual([]);
    });

    it.each(['npm --dgunknown create install P', 'npm --dgunknown init install P', 'bun --dgunknown c install P'])(
      'T-05 `%s` stays the `install` command with P, as today',
      (command) => {
        expect(shapes(command), command).toEqual([{ packages: [['P', undefined, 'P']], manifest: MANIFEST, localFirst: undefined }]);
      },
    );

    it('T-05 `yarn --dgunknown create` stays the manifest install of the verbless `yarn`, as today', () => {
      expect(shapes('yarn --dgunknown create')).toEqual([{ packages: [], manifest: MANIFEST, localFirst: undefined }]);
    });

    it.each(['npm install-test', 'npm it'])('T-05 `%s` with no package: the manifest and no package', (command) => {
      expect(shapes(command)).toEqual([{ packages: [], manifest: MANIFEST, localFirst: undefined }]);
    });

    it('T-05 `pnpm install-test left-pad` is not read: no command', () => {
      expect(parseInstallCommands('pnpm install-test left-pad')).toEqual([]);
    });

    it.each([
      [`npx create-${X}`, true],
      [`npm exec create-${X}`, true],
      [`pnpm dlx create-${X}`, undefined],
    ])('T-05 `%s` stays a launcher of that package, as today', (command, localFirst) => {
      expect(shapes(command), command).toEqual([{ packages: [[`create-${X}`, undefined, `create-${X}`]], manifest: undefined, localFirst }]);
    });
  });

  describe('install-test', () => {
    const P = 'dgprobe-zzq7731-pkg';
    /** What a line gives except its verb: the packages, the manifest, the global flag and the reasons it is uncertain (the verb named in a reason is left out). */
    const reading = (command: string): unknown[] =>
      parseInstallCommands(command).map((c) => ({
        packages: c.packages.map((p): [string, string | undefined, string] => [p.name, p.range, p.raw]),
        manifest: c.manifest,
        global: c.global,
        uncertain: c.uncertain.map((u) => u.replace(/\('npm [a-z-]+'\)/, "('npm <verb>')")),
      }));

    it.each(['install-test', 'it'].flatMap((verb) => ['', '-D ', '--no-save ', '-g '].map((flags) => [verb, flags] as const)))(
      'T-04 `npm %s %s<P>` is read as `npm install` with the same flags: packages, manifest, global and uncertain',
      (verb, flags) => {
        expect(reading(`npm ${verb} ${flags}${P}`), `npm ${verb} ${flags}${P}`).toEqual(reading(`npm install ${flags}${P}`));
      },
    );

    it.each(['install-test', 'it'])('T-04 `npm %s <P>@1.2.3` is read as `npm install <P>@1.2.3`, with the range', (verb) => {
      expect(reading(`npm ${verb} ${P}@1.2.3`)).toEqual(reading(`npm install ${P}@1.2.3`));
      expect(vetted(`npm ${verb} ${P}@1.2.3`)).toEqual([[P, '1.2.3']]);
    });

    it.each(['install-test', 'it'])('T-04 `npm %s -g <P>` names the package and reads no manifest (global)', (verb) => {
      const [c] = parseInstallCommands(`npm ${verb} -g ${P}`);
      expect({ packages: c?.packages.map((p) => p.name), manifest: c?.manifest, global: c?.global }).toEqual({
        packages: [P],
        manifest: undefined,
        global: true,
      });
    });
  });
});

// ───────────────── install-vet-global-update-by-name — the names given to a global update, or to `yarn up`, are read

describe('install-vet-global-update-by-name', () => {
  const P = 'dgprobe-zzq7731-named';
  const MANIFEST = { kind: 'package-json' };
  type Parsed = ReturnType<typeof parseInstallCommands>[number];
  /** `updateNames` is the field this work adds: read through a type that has it, so a parser without it fails by its assertion, not by the compiler. */
  type WithUpdateNames = Parsed & { updateNames?: readonly PackageSpec[] };
  /** What a line gives, per command: the packages, the names given to an update verb as `[name, range, raw]`, the manifest, the update flag, whether it is global and why it is uncertain. */
  const read = (
    command: string,
  ): Array<{
    packages: string[];
    updateNames: Array<[string, string | undefined, string]> | undefined;
    manifest: unknown;
    update: unknown;
    global: unknown;
    uncertain: string[];
  }> =>
    parseInstallCommands(command).map((c) => ({
      packages: c.packages.map((p) => p.name),
      updateNames: (c as WithUpdateNames).updateNames?.map((p): [string, string | undefined, string] => [p.name, p.range, p.raw]),
      manifest: c.manifest,
      update: c.update,
      global: c.global,
      uncertain: c.uncertain,
    }));
  /** The same, without the reasons the command is uncertain: the words of the verb differ between two spellings of one command. */
  const essence = (command: string): unknown => read(command).map(({ uncertain: _uncertain, ...rest }) => rest);
  const workspaceReason = (command: string): boolean => read(command).some((c) => c.uncertain.some((u) => u.startsWith('workspace context')));

  it.each([
    `npm update -g ${P}`,
    `npm up -g ${P}`,
    `npm upgrade -g ${P}`,
    `npm update ${P} --global`,
    `npm -g update ${P}`,
    `npm update --location=global ${P}`,
    `pnpm update -g ${P}`,
    `pnpm up -g ${P}`,
    `pnpm upgrade -g ${P}`,
    `bun update -g ${P}`,
    `yarn global upgrade ${P}`,
    `yarn global upgrade ${P} --latest`,
  ])('T-01 `%s` gives the name in `updateNames` and not in `packages`; global for certain, no manifest', (command) => {
    expect(read(command), command).toEqual([
      { packages: [], updateNames: [[P, undefined, P]], manifest: undefined, update: undefined, global: true, uncertain: expect.any(Array) },
    ]);
  });

  it('T-01 `npm update -g <P>@2` gives the name with its range', () => {
    expect(read(`npm update -g ${P}@2`).map((c) => ({ packages: c.packages, updateNames: c.updateNames, manifest: c.manifest }))).toEqual([
      { packages: [], updateNames: [[P, '2', `${P}@2`]], manifest: undefined },
    ]);
  });

  it.each([`pnpm update -g --latest ${P}`, `npm update -gD ${P}`, `npm update -g false ${P}`, `npm update --global=false ${P}`])(
    'T-01 `%s` is global but not for certain: `updateNames` has the name AND the manifest is read',
    (command) => {
      const parsed = read(command);
      expect(parsed.length, command).toBe(1);
      expect({
        command,
        packages: parsed.map((c) => c.packages),
        named: parsed.map((c) => (c.updateNames ?? []).filter((n) => n[0] === P).length),
        manifest: parsed.map((c) => c.manifest),
        update: parsed.map((c) => c.update),
      }).toEqual({ command, packages: [[]], named: [1], manifest: [MANIFEST], update: [true] });
    },
  );

  it("T-01 `bash -c 'npm update -g <P>'` gives what `npm update -g <P>` gives: the nested command is not dropped for having no packages", () => {
    // The shell guard hands the scripts of `bash -c` to the parser as `nested`: the plain reading of the outer line finds no install.
    const nested = (line: string, script: string): unknown =>
      parseInstallCommands(line, { nested: [{ text: script, shell: 'bash' }] }).map((c) => ({
        packages: c.packages.map((p) => p.name),
        updateNames: (c as WithUpdateNames).updateNames?.map((p): [string, string | undefined, string] => [p.name, p.range, p.raw]),
        manifest: c.manifest,
        update: c.update,
        global: c.global,
      }));
    expect(nested(`bash -c 'npm update -g ${P}'`, `npm update -g ${P}`)).toEqual(essence(`npm update -g ${P}`));
    expect(nested(`bash -c 'npm update -g ${P}'`, `npm update -g ${P}`)).toEqual([
      { packages: [], updateNames: [[P, undefined, P]], manifest: undefined, update: undefined, global: true },
    ]);
    expect(nested("bash -c 'npm update -g'", 'npm update -g')).toEqual(essence('npm update -g'));
  });

  it.each(['npm update -g', 'pnpm update -g', 'bun update -g', 'yarn global upgrade'])(
    'T-01 `%s` has no names: `updateNames` is empty, global for certain, no manifest',
    (command) => {
      expect(read(command), command).toEqual([
        { packages: [], updateNames: [], manifest: undefined, update: undefined, global: true, uncertain: expect.any(Array) },
      ]);
    },
  );

  // ── the Yarn forms (T-03)

  it.each([
    [`yarn workspace W up ${P}`, `yarn up ${P}`],
    ['yarn workspace W up', 'yarn up'],
    [`yarn workspaces foreach -A up ${P}`, `yarn up ${P}`],
    [`yarn workspaces foreach --all -p up ${P}`, `yarn up ${P}`],
  ])('T-03 `%s` gives what `%s` gives, and is uncertain for the workspace context', (command, plain) => {
    expect(essence(command), command).toEqual(essence(plain));
    expect(essence(command), command).not.toEqual([]);
    expect(workspaceReason(command), command).toBe(true);
  });

  it('T-03 `yarn up <P>` gives the name in `updateNames`, the manifest and the update, and no package', () => {
    expect(essence(`yarn up ${P}`)).toEqual([{ packages: [], updateNames: [[P, undefined, P]], manifest: MANIFEST, update: true, global: undefined }]);
  });

  it.each([
    [`yarn workspace W up ${P}`, [[P, undefined, P]]],
    [`yarn workspaces foreach -A up ${P}`, [[P, undefined, P]]],
    ['yarn workspace W up', []],
  ])('T-03 `%s`: `updateNames` is %j and `packages` is empty', (command, names) => {
    expect(read(command).map((c) => ({ packages: c.packages, updateNames: c.updateNames }))).toEqual([{ packages: [], updateNames: names }]);
  });

  it('T-03 `yarn workspaces foreach -A add <P>` gives what `yarn workspace W add <P>` gives: the package in `packages`', () => {
    expect(essence(`yarn workspaces foreach -A add ${P}`)).toEqual(essence(`yarn workspace W add ${P}`));
    expect(essence(`yarn workspaces foreach -A add ${P}`)).toEqual([{ packages: [P], updateNames: undefined, manifest: MANIFEST, update: undefined, global: undefined }]);
    expect(workspaceReason(`yarn workspaces foreach -A add ${P}`)).toBe(true);
  });

  it('T-03 `yarn workspaces foreach --dgunknown-flag up <P>` is uncertain for the flag the hook does not know', () => {
    const reasons = read(`yarn workspaces foreach --dgunknown-flag up ${P}`).flatMap((c) => c.uncertain);
    expect(
      reasons.some((u) => u.includes('a flag of yarn workspaces foreach the hook does not know')),
      reasons.join(' | '),
    ).toBe(true);
  });

  it('T-03 `yarn up <P>@^3` gives the name with its range', () => {
    expect(read(`yarn up ${P}@^3`).map((c) => ({ packages: c.packages, updateNames: c.updateNames }))).toEqual([
      { packages: [], updateNames: [[P, '^3', `${P}@^3`]] },
    ]);
  });

  it.each([`yarn up '*'`, `yarn up '@babel/*'`])('T-03 `%s` gives no name: a pattern is not a package', (command) => {
    expect(read(command).map((c) => ({ packages: c.packages, updateNames: c.updateNames }))).toEqual([{ packages: [], updateNames: [] }]);
  });

  it.each(['yarn workspace W run build', 'yarn workspaces list', `yarn workspace W upgrade ${P}`])('T-03 `%s` stays unread: no command', (command) => {
    expect(parseInstallCommands(command)).toEqual([]);
  });

  // ── protection (T-06): the parser clause

  it.each(['yarn up lodash', "yarn up '*'", 'corepack yarn@4.18.1 up lodash'])('T-06 `%s` keeps `packages` empty and the manifest read, as today', (command) => {
    expect(read(command).map((c) => ({ packages: c.packages, manifest: c.manifest, update: c.update }))).toEqual([{ packages: [], manifest: MANIFEST, update: true }]);
  });
});
