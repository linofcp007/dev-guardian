import { describe, expect, it } from 'vitest';
import {
  extractModuleEdges,
  resolveModuleEdges,
  RESOLVABLE_LANGUAGES,
} from '../../../src/surface/moduleEdges.js';

const FILES = new Set([
  'src/app.ts', 'src/routes/users.ts', 'src/util.ts',
  'pkg/handler.go', 'app/models.py', 'src/settings.rs',
]);

function edge(file: string, specifier: string, language: string) {
  return { file, specifier, language };
}

describe('resolveModuleEdges', () => {
  it('resolves a JS/TS relative specifier, trying the extension candidates', () => {
    const { resolved } = resolveModuleEdges(
      [edge('src/app.ts', './routes/users', 'typescript')], FILES,
    );
    expect(resolved).toEqual([{ file: 'src/app.ts', module_file: 'src/routes/users.ts' }]);
  });

  it('resolves a Python dotted module to a path', () => {
    const { resolved } = resolveModuleEdges([edge('app/urls.py', 'app.models', 'python')], FILES);
    expect(resolved).toEqual([{ file: 'app/urls.py', module_file: 'app/models.py' }]);
  });

  it('resolves a Rust crate path', () => {
    const { resolved } = resolveModuleEdges([edge('src/main.rs', 'crate::settings', 'rust')], FILES);
    expect(resolved).toEqual([{ file: 'src/main.rs', module_file: 'src/settings.rs' }]);
  });

  it('reports an unresolvable specifier instead of dropping it', () => {
    // The wrong implementation silently discards what it cannot resolve, and a
    // later task then reads a thinner graph as "nothing imports this file".
    const { resolved, unresolved } = resolveModuleEdges(
      [edge('Order.java', 'com.example.Service', 'java')], FILES,
    );
    expect(resolved).toEqual([]);
    expect(unresolved).toHaveLength(1);
  });

  it('reports a third-party specifier as unresolved, not as an edge to nothing', () => {
    const { resolved, unresolved } = resolveModuleEdges(
      [edge('src/app.ts', 'express', 'typescript')], FILES,
    );
    expect(resolved).toEqual([]);
    expect(unresolved).toHaveLength(1);
  });

  it('never invents a module_file that is not a known project file', () => {
    const { resolved } = resolveModuleEdges(
      [edge('src/app.ts', './does-not-exist', 'typescript')], FILES,
    );
    expect(resolved).toEqual([]);
  });

  it('lists exactly the five languages whose specifiers encode a path', () => {
    expect([...RESOLVABLE_LANGUAGES].sort()).toEqual(
      ['go', 'javascript', 'python', 'rust', 'typescript'],
    );
  });

  // ---- additional coverage: the given suite never exercises Go's resolver,
  // Rust's self:: form, the Python relative-import guard, or native-separator
  // safety. Each test below names the wrong implementation it distinguishes.

  it('prefers the longer, more specific Go package-directory match', () => {
    // A wrong implementation that returns the FIRST match found (order-
    // dependent on Map iteration) rather than the longest would sometimes
    // pick the shallower 'handler/' package instead of 'pkg/handler/'.
    const files = new Set(['pkg/handler/server.go', 'handler/server.go']);
    const { resolved } = resolveModuleEdges(
      [edge('cmd/main.go', 'myapp/pkg/handler', 'go')], files,
    );
    expect(resolved).toEqual([{ file: 'cmd/main.go', module_file: 'pkg/handler/server.go' }]);
  });

  it('resolves a Go import to EVERY file in the package directory, not a representative one', () => {
    // Go imports a DIRECTORY; every file in it is part of the package. A
    // wrong implementation that returns one file leaves the package's other
    // files with no inbound edge — and `validate_finding` spends exactly that
    // absence as "no route imports this file", fabricating `unreachable` for
    // a file the route demonstrably reaches.
    const files = new Set([
      'pkg/util/util.go', 'pkg/util/strings.go', 'pkg/util/README.md', 'cmd/main.go',
    ]);
    const { resolved, unresolved } = resolveModuleEdges(
      [edge('cmd/main.go', 'myapp/pkg/util', 'go')], files,
    );
    expect(resolved.map((r) => r.module_file).sort()).toEqual([
      'pkg/util/strings.go', 'pkg/util/util.go',
    ]);
    expect(resolved.every((r) => r.file === 'cmd/main.go')).toBe(true);
    expect(unresolved).toEqual([]);
  });

  it('does not resolve a Go import to a FILE whose basename matches the last path segment', () => {
    // `pkg/handler.go` is a file in package `pkg`; `myapp/pkg/handler` names
    // the DIRECTORY `pkg/handler`, which does not exist here. The shipped
    // basename-matching resolver claimed an edge into a file that specifier
    // does not import — a silent WRONG edge, not a missed one.
    const files = new Set(['pkg/handler.go', 'cmd/main.go']);
    const { resolved, unresolved } = resolveModuleEdges(
      [edge('cmd/main.go', 'myapp/pkg/handler', 'go')], files,
    );
    expect(resolved).toEqual([]);
    expect(unresolved).toHaveLength(1);
  });

  it('does not attribute a Go import to a root-level .go file (empty package directory)', () => {
    // A root-level file's directory is the empty string. A wrong
    // implementation that indexes it anyway matches `endsWith('/')`-style on
    // any specifier ending in a separator, or — worse — treats every
    // specifier as ending with the empty suffix and resolves everything to
    // the repository root.
    const files = new Set(['main.go', 'pkg/util/util.go']);
    const { resolved, unresolved } = resolveModuleEdges(
      [edge('pkg/util/util.go', 'myapp/', 'go')], files,
    );
    expect(resolved).toEqual([]);
    expect(unresolved).toHaveLength(1);
  });

  it('leaves a Go standard-library import unresolved rather than matching an unrelated known file', () => {
    const { resolved, unresolved } = resolveModuleEdges(
      [edge('pkg/handler.go', 'net/http', 'go')], FILES,
    );
    expect(resolved).toEqual([]);
    expect(unresolved).toHaveLength(1);
  });

  it('does not attribute a zero-slash Go import to a same-named project file', () => {
    // 'errors' is Go stdlib. A wrong implementation matches it by bare
    // equality against a project's own errors.go — a real, silent WRONG
    // edge (handler.go does NOT import errors.go), not just a missed one.
    // Every valid Go import carries at least the module-name prefix
    // (go.mod's `module` directive is never empty), so a specifier with no
    // '/' at all is never a legitimate intra-project shape — this is what
    // the reviewer's run of the previously-shipped dist/surface/
    // moduleEdges.js demonstrated: resolved: [{module_file: 'errors.go'}].
    const files = new Set(['pkg/handler.go', 'errors.go']);
    const { resolved, unresolved } = resolveModuleEdges(
      [edge('pkg/handler.go', 'errors', 'go')], files,
    );
    expect(resolved).toEqual([]);
    expect(unresolved).toHaveLength(1);
  });

  it("resolves a Rust self:: path relative to the importing file's own directory", () => {
    // Neither the brief's own suite nor RESOLVABLE_LANGUAGES membership on
    // its own proves self:: (as opposed to crate::) actually resolves.
    const files = new Set(['src/handlers/mod.rs', 'src/handlers/util.rs']);
    const { resolved } = resolveModuleEdges(
      [edge('src/handlers/mod.rs', 'self::util', 'rust')], files,
    );
    expect(resolved).toEqual([{ file: 'src/handlers/mod.rs', module_file: 'src/handlers/util.rs' }]);
  });

  it('resolves a Rust module::Item path by falling back to the module once the full chain fails', () => {
    // `use crate::settings::Config;` imports the Config item FROM
    // settings.rs — there is no settings/Config.rs. A wrong implementation
    // that treats every `::`-segment as a path component never resolves
    // this, which is the DOMINANT real-world shape for a Rust `use`
    // statement (found by running the real multi-language fixture through
    // this exact pipeline: rust-actix/config.rs's own `use
    // crate::settings::Config;` did not resolve until this fallback was
    // added).
    const files = new Set(['src/settings.rs']);
    const { resolved } = resolveModuleEdges(
      [edge('src/main.rs', 'crate::settings::Config', 'rust')], files,
    );
    expect(resolved).toEqual([{ file: 'src/main.rs', module_file: 'src/settings.rs' }]);
  });

  it('prefers the full Rust module chain over the fallback when every segment is genuinely a module', () => {
    // Guards the ORDER of the fallback in the test above: a wrong
    // implementation that tried the shortest prefix first (or only ever
    // dropped straight to one segment) would return 'src/api.rs' here
    // instead of the more specific, genuinely-correct full-depth file.
    const files = new Set(['src/api/v1/handlers.rs', 'src/api.rs']);
    const { resolved } = resolveModuleEdges(
      [edge('src/main.rs', 'crate::api::v1::handlers', 'rust')], files,
    );
    expect(resolved).toEqual([{ file: 'src/main.rs', module_file: 'src/api/v1/handlers.rs' }]);
  });

  it('does not resolve a relative Python import (leading dot)', () => {
    // A wrong implementation strips the leading dot and treats what remains
    // as an absolute dotted path, silently resolving at the PROJECT ROOT
    // instead of relative to the importing file's own package — landing on
    // a real but WRONG file precisely because one happens to exist there
    // too. Reporting unresolved is safer than a plausible-looking wrong hit.
    const files = new Set(['models.py', 'app/models.py']);
    const { resolved, unresolved } = resolveModuleEdges(
      [edge('app/urls.py', '.models', 'python')], files,
    );
    expect(resolved).toEqual([]);
    expect(unresolved).toHaveLength(1);
  });

  it('resolves an absolute POSIX path without eating its leading slash', () => {
    // Linux, macOS and every Docker-Semgrep run report absolute POSIX paths.
    // `joinAndNormalize` dropped empty segments, and an absolute path's
    // leading `/` IS an empty first segment — so '/src/api' + './helper.js'
    // normalised to 'src/api/helper.js', which never equals the index key
    // '/src/api/helper.ts'. Measured effect: an entirely empty import graph
    // and `unknown` for every finding on every non-Windows host.
    const files = new Set(['/src/api/helper.ts', '/src/api/server.ts']);
    const { resolved } = resolveModuleEdges(
      [edge('/src/api/server.ts', './helper.js', 'typescript')], files,
    );
    expect(resolved).toEqual([
      { file: '/src/api/server.ts', module_file: '/src/api/helper.ts' },
    ]);
  });

  it("resolves an absolute POSIX Rust self:: path against the importing file's directory", () => {
    // The second resolver that anchors on the importing file's own directory,
    // and therefore the second one the leading-slash loss silently disabled.
    const files = new Set(['/app/src/handlers/mod.rs', '/app/src/handlers/util.rs']);
    const { resolved } = resolveModuleEdges(
      [edge('/app/src/handlers/mod.rs', 'self::util', 'rust')], files,
    );
    expect(resolved).toEqual([
      { file: '/app/src/handlers/mod.rs', module_file: '/app/src/handlers/util.rs' },
    ]);
  });

  it('resolves against a native-Windows-separator project-file set and returns the file verbatim', () => {
    // Semgrep reports absolute, native-separator paths on Windows (see
    // moduleEdges.ts's own comment). A wrong implementation that compares
    // projectFiles as given, with no POSIX normalisation, would never match.
    // A DIFFERENT wrong implementation that normalises but then returns the
    // NORMALISED candidate (forward slashes) instead of projectFiles' own
    // spelling would silently stop string-equalling how the same file is
    // spelled elsewhere in the snapshot (e.g. a route's `file`).
    const files = new Set(['src\\routes\\users.ts']);
    const { resolved } = resolveModuleEdges(
      [edge('src/app.ts', './routes/users', 'typescript')], files,
    );
    expect(resolved).toEqual([{ file: 'src/app.ts', module_file: 'src\\routes\\users.ts' }]);
  });
});

describe('extractModuleEdges', () => {
  // Every case below is a form extractImports() in mapAttackSurface.ts
  // drops today because it requires both a symbol AND a module — see that
  // function's doc comment. A wrong implementation of extractModuleEdges
  // that reproduces the same `symbol === undefined` guard would emit ZERO
  // edges for every test in this block.

  it('extracts a Java import with no bound symbol at all', () => {
    const results = [
      {
        check_id: 'guardian-import-java',
        path: 'Order.java',
        start: { line: 3 },
        extra: {
          metadata: { guardian_kind: 'import', framework: 'java' },
          metavars: { $MODULE: { abstract_content: 'com.example.Service' } },
        },
      },
    ];
    expect(extractModuleEdges(results)).toEqual([
      { file: 'Order.java', specifier: 'com.example.Service', language: 'java' },
    ]);
  });

  it('extracts a bare Python `import os` with no symbol', () => {
    const results = [
      {
        check_id: 'guardian-import-python',
        path: 'app/main.py',
        start: { line: 1 },
        extra: {
          metadata: { guardian_kind: 'import', framework: 'python' },
          metavars: { $MODULE: { abstract_content: 'os' } },
        },
      },
    ];
    expect(extractModuleEdges(results)).toEqual([
      { file: 'app/main.py', specifier: 'os', language: 'python' },
    ]);
  });

  it('extracts an unaliased Go import, stripping the string-literal quoting', () => {
    const results = [
      {
        check_id: 'guardian-import-go',
        path: 'pkg/handler.go',
        start: { line: 2 },
        extra: {
          metadata: { guardian_kind: 'import', framework: 'go' },
          metavars: { $MODULE: { abstract_content: '"net/http"' } },
        },
      },
    ];
    expect(extractModuleEdges(results)).toEqual([
      { file: 'pkg/handler.go', specifier: 'net/http', language: 'go' },
    ]);
  });

  it('extracts a plain C# `using` with no symbol', () => {
    const results = [
      {
        check_id: 'guardian-import-csharp',
        path: 'Orders/OrderService.cs',
        start: { line: 1 },
        extra: {
          metadata: { guardian_kind: 'import', framework: 'csharp' },
          metavars: { $MODULE: { abstract_content: 'System' } },
        },
      },
    ];
    expect(extractModuleEdges(results)).toEqual([
      { file: 'Orders/OrderService.cs', specifier: 'System', language: 'csharp' },
    ]);
  });

  it('extracts a Ruby require with no symbol, stripping the string-literal quoting', () => {
    const results = [
      {
        check_id: 'guardian-import-ruby',
        path: 'app/models/order.rb',
        start: { line: 1 },
        extra: {
          metadata: { guardian_kind: 'import', framework: 'ruby' },
          metavars: { $MODULE: { abstract_content: '"active_support/core_ext"' } },
        },
      },
    ];
    expect(extractModuleEdges(results)).toEqual([
      { file: 'app/models/order.rb', specifier: 'active_support/core_ext', language: 'ruby' },
    ]);
  });

  it('reconstructs a Rust specifier by joining $MODULE and $SYMBOL with `::`', () => {
    // A wrong implementation that used $MODULE alone would emit `crate`
    // instead of `crate::settings` — which then fails to resolve at all,
    // because resolveRust's `crate::` prefix check would never match a bare
    // `crate` with no separator.
    const results = [
      {
        check_id: 'guardian-import-rust',
        path: 'src/main.rs',
        start: { line: 1 },
        extra: {
          metadata: { guardian_kind: 'import', framework: 'rust' },
          metavars: {
            $MODULE: { abstract_content: 'crate' },
            $SYMBOL: { abstract_content: 'settings' },
          },
        },
      },
    ];
    expect(extractModuleEdges(results)).toEqual([
      { file: 'src/main.rs', specifier: 'crate::settings', language: 'rust' },
    ]);
  });

  it("undoes Semgrep's space-join quirk for a multi-segment Rust $MODULE", () => {
    // routes.yml's guardian-import-rust comment documents that Semgrep joins
    // a multi-segment $MODULE with a SPACE, not `::`. A wrong implementation
    // that concatenates `${module}::${symbol}` verbatim would emit
    // 'crate models::User' (a literal space, unresolvable) instead of the
    // correct 'crate::models::User'.
    const results = [
      {
        check_id: 'guardian-import-rust',
        path: 'src/main.rs',
        start: { line: 5 },
        extra: {
          metadata: { guardian_kind: 'import', framework: 'rust' },
          metavars: {
            $MODULE: { abstract_content: 'crate models' },
            $SYMBOL: { abstract_content: 'User' },
          },
        },
      },
    ];
    expect(extractModuleEdges(results)).toEqual([
      { file: 'src/main.rs', specifier: 'crate::models::User', language: 'rust' },
    ]);
  });

  it('ignores a match whose guardian_kind is not import', () => {
    const results = [
      {
        check_id: 'guardian-route-express',
        path: 'src/routes/users.ts',
        start: { line: 1 },
        extra: {
          metadata: { guardian_kind: 'route', framework: 'express' },
          metavars: { $PATH: { abstract_content: "'/users'" } },
        },
      },
    ];
    expect(extractModuleEdges(results)).toEqual([]);
  });

  it('returns no edges for malformed input instead of throwing', () => {
    expect(() => extractModuleEdges([null, undefined, { nonsense: true }, 42])).not.toThrow();
    expect(extractModuleEdges([null, undefined, { nonsense: true }, 42])).toEqual([]);
  });

  it('extracts an unaliased Go import end-to-end and resolves it to its package directory', () => {
    // Combines extraction and resolution for the one language the given
    // Step-1 suite lists in RESOLVABLE_LANGUAGES but never actually resolves.
    // The package file is NOT named after its directory — the shape a
    // basename-matching resolver silently fails on, which is the norm in real
    // Go code (`pkg/handler/server.go`, not `pkg/handler/handler.go`).
    const results = [
      {
        check_id: 'guardian-import-go',
        path: 'cmd/server/main.go',
        start: { line: 4 },
        extra: {
          metadata: { guardian_kind: 'import', framework: 'go' },
          metavars: { $MODULE: { abstract_content: '"myapp/pkg/handler"' } },
        },
      },
    ];
    const edges = extractModuleEdges(results);
    expect(edges).toEqual([
      { file: 'cmd/server/main.go', specifier: 'myapp/pkg/handler', language: 'go' },
    ]);

    const files = new Set(['pkg/handler/server.go', 'cmd/server/main.go']);
    const { resolved, unresolved } = resolveModuleEdges(edges, files);
    expect(resolved).toEqual([
      { file: 'cmd/server/main.go', module_file: 'pkg/handler/server.go' },
    ]);
    expect(unresolved).toEqual([]);
  });
});
