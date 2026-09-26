import { describe, expect, it } from 'vitest';

import { parseInstallCommands, parsePackageSpec } from '../../../src/pkgvet/parseCommand.js';
import type { PackageSpec, PkgEcosystem } from '../../../src/pkgvet/types.js';

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
      expect(uncertain(command)).toEqual([]);
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
    expect(uncertain('npm install --some-new-flag value lodash')).toEqual([expect.stringMatching(/--some-new-flag/)]);
    expect(uncertain('pip install -Z requests')).toEqual([expect.stringMatching(/-Z/)]);
    expect(uncertain('pip install -qZ requests')).toEqual([expect.stringMatching(/-Z/)]);
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

  it('`set -e` (a shell option, not an assignment) keeps the parse confident', () => {
    expect(uncertain('set -e && npm install foo')).toEqual([]);
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

  it('a cd AFTER the install does not affect it', () => {
    expect(uncertain('npm install foo && cd dist')).toEqual([]);
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
