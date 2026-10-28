/**
 * Tests weakened by a change (`testintegrity/detect.ts`), on a change set
 * built by hand — the git side is `test/integration/testIntegrityGit.test.ts`.
 * Every rule fires on an ADDED line of a TEST file and nowhere else: a skip
 * already there, a skip in a fixture or in application code, a commented-out
 * `.only` and a conditional `skipIf` are hard negatives.
 */

import { describe, expect, it } from 'vitest';
import {
  countAssertions,
  detectTestWeakening,
  isRelevantPath,
  isTestFile,
  TEST_INTEGRITY_TOOL,
  type ChangedFile,
} from '../../../src/testintegrity/detect.js';

/** A modified file whose added lines are `added` (numbered from 1). */
function addedLines(path: string, added: string[], extra: Partial<ChangedFile> = {}): ChangedFile {
  return { status: 'modified', path, added: added.map((text, i) => ({ line: i + 1, text })), removed: [], ...extra };
}

const rows = (changes: ChangedFile[]): string[] =>
  detectTestWeakening(changes).map((f) => `${f.rule_id} ${f.file_path}:${f.line_start ?? '-'} ${f.severity}`);

describe('which files are tests', () => {
  it('by each runner convention; never a fixture, a snapshot or test data', () => {
    for (const p of [
      'src/a.test.ts',
      'src/a.spec.tsx',
      'web/__tests__/a.js',
      'tests/test_api.py',
      'pkg/api_test.py',
      'pkg/handler_test.go',
      'src/test/java/com/x/FooTest.java',
      'app/src/test/kotlin/FooTests.kt',
      'Api.Tests/OrdersTests.cs',
      'tests/integration.rs',
      'tests/Unit/UserTest.php',
      'spec/models/user_spec.rb',
      'e2e/login.spec.ts',
    ]) {
      expect(isTestFile(p), p).toBe(true);
    }
    for (const p of ['src/app.ts', 'test/fixtures/hits/a.test.ts', 'tests/__snapshots__/a.test.ts.snap', 'pkg/testdata/x_test.go', 'src/lib.rs', 'README.md']) {
      expect(isTestFile(p), p).toBe(false);
    }
    expect(isRelevantPath('package.json')).toBe(true);
    expect(isRelevantPath('apps/web/package.json')).toBe(true);
    expect(isRelevantPath('src/lib.rs')).toBe(true);
    expect(isRelevantPath('src/app.ts')).toBe(false);
  });
});

describe('test-focused (high)', () => {
  it('every focusing shape, on its line', () => {
    const f = addedLines('src/a.test.ts', [
      "it.only('x', () => {});",
      "describe.only('y', () => {});",
      "test.only('z', async () => {});",
      "test.describe.only('pw', () => {});",
      "it.concurrent.only('c', () => {});",
      "fit('jasmine', () => {});",
      "fdescribe('jasmine', () => {});",
    ]);
    expect(rows([f])).toEqual([1, 2, 3, 4, 5, 6, 7].map((n) => `test-focused src/a.test.ts:${n} high`));
    const one = detectTestWeakening([f])[0];
    expect(one?.tool).toBe(TEST_INTEGRITY_TOOL);
    expect(one?.category).toBe('quality');
    expect(one?.message).toMatch(/silently skips every other test/);
  });

  it('RSpec fit / fdescribe / focus: true', () => {
    expect(rows([addedLines('spec/a_spec.rb', ["  fit 'x' do", "fdescribe Foo do", "it 'y', focus: true do"])])).toEqual([
      'test-focused spec/a_spec.rb:1 high',
      'test-focused spec/a_spec.rb:2 high',
      'test-focused spec/a_spec.rb:3 high',
    ]);
  });
});

describe('test-skipped (medium) — one shape per runner', () => {
  const cases: Array<[string, string]> = [
    ['src/a.test.ts', "it.skip('x', () => {});"],
    ['src/a.test.ts', "describe.skip('x', () => {});"],
    ['src/a.test.ts', "test.skip('x', () => {});"],
    ['src/a.test.ts', "xit('x', () => {});"],
    ['src/a.test.ts', "xdescribe('x', () => {});"],
    ['src/a.test.ts', "xtest('x', () => {});"],
    ['e2e/a.spec.ts', "test.fixme('x', async () => {});"],
    ['tests/test_a.py', '@pytest.mark.skip(reason="flaky")'],
    ['tests/test_a.py', '@pytest.mark.skipif(sys.platform == "win32", reason="x")'],
    ['tests/test_a.py', '@pytest.mark.xfail'],
    ['tests/test_a.py', '    pytest.skip("later")'],
    ['tests/test_a.py', '@unittest.skip("x")'],
    ['tests/test_a.py', '        self.skipTest("x")'],
    ['pkg/a_test.go', '\tt.Skip("flaky")'],
    ['pkg/a_test.go', '\tt.Skipf("on %s", runtime.GOOS)'],
    ['src/test/java/FooTest.java', '    @Disabled("broken")'],
    ['src/test/java/FooTest.java', '    @Ignore'],
    ['Api.Tests/OrdersTests.cs', '    [Fact(Skip = "flaky")]'],
    ['Api.Tests/OrdersTests.cs', '    [Ignore("later")]'],
    ['src/lib.rs', '    #[ignore]'],
    ['tests/Unit/UserTest.php', '        $this->markTestSkipped("x");'],
    ['spec/a_spec.rb', "  xit 'does x' do"],
    ['spec/a_spec.rb', '    skip "not yet"'],
    ['spec/a_spec.rb', '    pending'],
    ['spec/a_spec.rb', "  it 'x', skip: true do"],
  ];
  for (const [path, line] of cases) {
    it(`${path}: ${line.trim()}`, () => {
      expect(rows([addedLines(path, [line])])).toEqual([`test-skipped ${path}:1 medium`]);
    });
  }

  it('the finding asks for the reason', () => {
    const f = detectTestWeakening([addedLines('src/a.test.ts', ["it.skip('x', () => {});"])])[0];
    expect(f?.message).toMatch(/say which in the change/);
  });
});

describe('hard negatives', () => {
  it('a comment, a conditional skipIf / runIf, an unrelated .only / .skip name, a removed skip', () => {
    const f = addedLines(
      'src/a.test.ts',
      [
        "// it.only('x', () => {});",
        "/* describe.skip('x') */",
        "it.skipIf(process.platform === 'win32')('x', () => {});",
        "describe.runIf(HAS_DB)('db', () => {});",
        "const onlyOne = list.only;",
        "await page.skip();",
        "expect(names).toEqual(['it.only']);",
      ],
      { removed: [{ line: 1, text: "it.skip('old', () => {});" }] },
    );
    expect(rows([f])).toEqual([]);
  });

  // Fix round 1, item 6: `fit` is also xterm's FitAddon and a model's training call.
  it('a `fit` / `x…` that is no test declaration: a member call, a call with no test name', () => {
    const f = addedLines('src/terminal.test.ts', [
      'fitAddon.fit();',
      'await model.fit(xs, ys, { epochs: 3 });',
      'const width = fit(container);',
      'const shape = xdescribe(node);',
      'suite.test.only = true;',
      'commit.skip(1);',
    ]);
    expect(rows([f])).toEqual([]);
    // …and the declarations still are, with a template name too.
    expect(rows([addedLines('src/a.test.ts', ['fit(`renders ${name}`, () => {});', "  xit('later', () => {});"])])).toEqual([
      'test-focused src/a.test.ts:1 high',
      'test-skipped src/a.test.ts:2 medium',
    ]);
  });

  it('application code and fixtures are not tests: a .only or @Disabled there says nothing', () => {
    expect(rows([addedLines('src/app.ts', ["it.only('x', () => {});"])])).toEqual([]);
    expect(rows([addedLines('test/fixtures/a.test.ts', ["it.only('x', () => {});"])])).toEqual([]);
    expect(rows([addedLines('src/main/java/Foo.java', ['@Disabled'])])).toEqual([]);
    expect(rows([addedLines('pkg/main.go', ['t.Skip()'])])).toEqual([]);
  });

  it('a new .todo is a plan, not a replaced test', () => {
    expect(rows([addedLines('src/a.test.ts', ["it.todo('later');"])])).toEqual([]);
  });
});

describe('test-todo-replaced, test-file-deleted, test-assertions-removed', () => {
  it('a .todo added where a test was removed', () => {
    const f = addedLines('src/a.test.ts', ["it.todo('adds two numbers');"], {
      removed: [{ line: 1, text: "it('adds two numbers', () => {" }, { line: 1, text: '  expect(add(1, 1)).toBe(2);' }],
    });
    expect(rows([f])).toEqual(['test-todo-replaced src/a.test.ts:1 medium']);
  });

  it('a deleted test file, and one renamed to a name no runner picks up; a rename between test names is no deletion', () => {
    const before = "it('a', () => { expect(1).toBe(1); expect(2).toBe(2); });";
    expect(
      rows([
        { status: 'deleted', path: 'src/a.test.ts', added: [], removed: [], before },
        { status: 'renamed', path: 'src/b.ts.bak', oldPath: 'src/b.test.ts', added: [], removed: [], before, after: before },
        { status: 'renamed', path: 'src/c.spec.ts', oldPath: 'src/c.test.ts', added: [], removed: [], before, after: before },
        { status: 'deleted', path: 'src/app.ts', added: [], removed: [], before: 'x' },
      ]),
    ).toEqual(['test-file-deleted src/a.test.ts:- medium', 'test-file-deleted src/b.test.ts:- medium']);
    const f = detectTestWeakening([{ status: 'deleted', path: 'src/a.test.ts', added: [], removed: [], before }])[0];
    expect(f?.message).toMatch(/its 2 assertion\(s\)/);
  });

  it('fewer assertions: reported at the first removed one; the same number moved around: nothing', () => {
    const before = ['it("a", () => {', '  expect(a).toBe(1);', '  expect(b).toBe(2);', '  assert.equal(c, 3);', '});'].join('\n');
    const after = ['it("a", () => {', '  expect(a).toBe(1);', '});'].join('\n');
    const f: ChangedFile = {
      status: 'modified',
      path: 'src/a.test.ts',
      added: [],
      removed: [
        { line: 3, text: '  expect(b).toBe(2);' },
        { line: 3, text: '  assert.equal(c, 3);' },
      ],
      before,
      after,
    };
    expect(rows([f])).toEqual(['test-assertions-removed src/a.test.ts:3 medium']);
    expect(detectTestWeakening([f])[0]?.title).toBe('src/a.test.ts: assertions dropped from 3 to 1');
    const moved = { ...f, after: before.replace('expect(b)', '  expect(b)'), removed: [] };
    expect(rows([moved])).toEqual([]);
  });

  it('counts assertions per language, comments left out', () => {
    expect(countAssertions('assert x == 1\nself.assertEqual(a, b)\n# assert nothing\nwith pytest.raises(E):', 'py')).toBe(3);
    expect(countAssertions('t.Fatalf("x")\nrequire.NoError(t, err)\nassert.Equal(t, 1, 1)\n// t.Error()', 'go')).toBe(3);
    expect(countAssertions('assert_eq!(a, b);\nassert!(x);\n// assert!(y);', 'rs')).toBe(2);
    expect(countAssertions('assertEquals(1, x);\nassertThat(y).isTrue();\nverify(mock).call();', 'jvm')).toBe(3);
    expect(countAssertions('Assert.Equal(1, x);\nx.Should().Be(1);', 'cs')).toBe(2);
    expect(countAssertions('$this->assertSame(1, $x);\nself::assertTrue($y);', 'php')).toBe(2);
    expect(countAssertions('expect(x).to eq(1)\nassert_equal 1, x', 'rb')).toBe(2);
  });
});

describe('test-script-always-passes', () => {
  const pkg = (scripts: Record<string, string>): string => JSON.stringify({ name: 'x', scripts }, null, 2);

  it('a test script given --passWithNoTests, || true, || exit 0, or replaced by echo / exit 0', () => {
    const before = pkg({ test: 'vitest run', 'test:e2e': 'playwright test', 'test:unit': 'jest', ci: 'npm test', lint: 'eslint .' });
    const after = pkg({
      test: 'vitest run --passWithNoTests',
      'test:e2e': 'playwright test || true',
      'test:unit': 'echo "no tests"',
      ci: 'npm test || exit 0',
      lint: 'eslint . || true',
    });
    const r = rows([{ status: 'modified', path: 'package.json', added: [], removed: [], before, after }]);
    expect(r).toEqual([
      'test-script-always-passes package.json:4 medium',
      'test-script-always-passes package.json:5 medium',
      'test-script-always-passes package.json:6 medium',
      'test-script-always-passes package.json:7 medium',
    ]);
  });

  it('a script that already passed regardless, a new script, an unrelated change: nothing', () => {
    const before = pkg({ test: 'jest --passWithNoTests', build: 'tsc' });
    const after = pkg({ test: 'jest --passWithNoTests --ci', build: 'tsc || true', 'test:new': 'vitest run' });
    expect(rows([{ status: 'modified', path: 'package.json', added: [], removed: [], before, after }])).toEqual([]);
    expect(rows([{ status: 'modified', path: 'package.json', added: [], removed: [], before: 'not json', after: '{' }])).toEqual([]);
  });

  it('a package.json added with a script that always passes', () => {
    const after = pkg({ test: 'echo ok || true' });
    expect(rows([{ status: 'added', path: 'apps/web/package.json', added: [], removed: [], before: null, after }])).toEqual([
      'test-script-always-passes apps/web/package.json:4 medium',
    ]);
  });
});
