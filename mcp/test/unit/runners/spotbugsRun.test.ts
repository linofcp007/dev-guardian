/**
 * SpotBugs' class directories found, its run judged and its report read
 * (`runners/spotbugsRun.ts`, `scannerParsers/spotbugs.ts`). The report is
 * SpotBugs 4.10.5's own with FindSecBugs 1.14.0 and the security filter, over
 * a seeded Maven layout whose `Uses.class` calls a class not on the
 * classpath, measured on 2026-10-24: exit 0, the sources named under the
 * `-sourcepath` root, each rule's CWE, and the missing class in
 * `invocations`.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { spotbugsParserFor } from '../../../src/runners/scannerParsers/spotbugs.js';
import { classDirs, hasJvmSource, judgeSpotbugs, SECURITY_FILTER } from '../../../src/runners/spotbugsRun.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const ROOT = resolve('fixture-project');
const REPORT = readFileSync(
  resolve(fileURLToPath(new URL('.', import.meta.url)), '../../fixtures/scanners/spotbugs/seeded-4.10.5.sarif.json'),
  'utf8',
).split('{{ROOT_URI}}').join(pathToFileURL(ROOT).href);

const run = (exitCode: number | null, stderr = '', outcome: 'completed' | 'failed' | 'timed_out' = 'completed') => ({
  outcome,
  exitCode,
  stdout: '',
  stderr,
});

describe('classDirs', () => {
  it("every module's target/classes and build/classes/<lang>/main with its src/main/<lang> roots; never into src/ or node_modules", () => {
    const root = makeTempDir('spotbugs-classes-');
    for (const d of [
      'target/classes/com/a',
      'src/main/java/com/a',
      'svc/build/classes/java/main/com/b',
      'svc/build/classes/kotlin/main',
      'svc/build/classes/java/test',
      'svc/src/main/kotlin',
      'node_modules/x/target/classes',
      'src/test/target/classes',
      'docs',
    ]) {
      mkdirSync(join(root, ...d.split('/')), { recursive: true });
    }
    writeFileSync(join(root, 'target', 'classes', 'com', 'a', 'A.class'), 'x');
    expect(classDirs(root)).toEqual({
      dirs: ['svc/build/classes/java/main', 'svc/build/classes/kotlin/main', 'target/classes'],
      sourceRoots: ['src/main/java', 'svc/src/main/kotlin'],
    });
    expect(classDirs(makeTempDir('spotbugs-none-'))).toEqual({ dirs: [], sourceRoots: [] });
  });

  it('hasJvmSource: Java, Kotlin, Scala or Groovy', () => {
    expect(hasJvmSource(['a.py', 'b/C.java'])).toBe(true);
    expect(hasJvmSource(['x.kt'])).toBe(true);
    expect(hasJvmSource(['a.py', 'build.gradle'])).toBe(false);
  });
});

describe('judgeSpotbugs', () => {
  it('exit 0 with its SARIF is sound; the missing classes are a note, never a failure', () => {
    const j = judgeSpotbugs({ run: run(0), report: REPORT });
    expect(j.ok).toBe(true);
    expect(j.notes).toEqual([
      "1 class(es) the code calls were not on SpotBugs' classpath (its dependencies): flows through them are unknown to it",
    ]);
  });

  it('a run that could not open its input, no report, a report not SpotBugs’, a timeout: failures', () => {
    const noInput = judgeSpotbugs({
      run: run(1, 'Exception in thread "main" java.io.IOException: No files to analyze could be opened'),
      report: null,
    });
    expect(noInput).toMatchObject({ ok: false, reason: 'exit 1: Exception in thread "main" java.io.IOException: No files to analyze could be opened' });
    expect(judgeSpotbugs({ run: run(0), report: null }).reason).toBe('SpotBugs wrote no report');
    expect(judgeSpotbugs({ run: run(0), report: '{"runs":[{"tool":{"driver":{"name":"detekt"}}}]}' }).ok).toBe(false);
    expect(judgeSpotbugs({ run: run(null, '', 'timed_out'), report: REPORT }).reason).toBe('did not finish (timed_out)');
  });

  it('a class it could not analyse — exit 0, executionSuccessful false — is named Not analysed, once, never a clean run', () => {
    // SpotBugs 4.10.5's own notifications over a `Junk.class` that is not a class (measured 2026-10-24).
    const sarif = JSON.stringify({
      runs: [
        {
          tool: { driver: { name: 'SpotBugs' } },
          results: [],
          invocations: [
            {
              exitCode: 5,
              exitCodeDescription: 'ERROR,BUGS FOUND',
              executionSuccessful: false,
              toolExecutionNotifications: [
                {
                  descriptor: { id: 'spotbugs-error-0' },
                  level: 'error',
                  message: { text: 'Invalid class resource com/example/Junk.class in /p/target/classes:com/example/Junk.class' },
                },
                { descriptor: { id: 'spotbugs-error-1' }, level: 'error', message: { text: 'Error scanning com/example/Junk for referenced classes' } },
              ],
            },
          ],
        },
      ],
    });
    const j = judgeSpotbugs({ run: run(0), report: sarif });
    expect(j.ok).toBe(true);
    expect(j.partial).toEqual([
      {
        file: join('/p/target/classes', 'com/example/Junk.class'),
        type: 'Not analysed',
        message: 'Invalid class resource com/example/Junk.class in /p/target/classes:com/example/Junk.class',
      },
    ]);
  });

  it("the filter keeps SpotBugs' security categories only", () => {
    expect(SECURITY_FILTER).toContain('<Match><Bug category="SECURITY"/></Match>');
    expect(SECURITY_FILTER).toContain('<Match><Bug category="MALICIOUS_CODE"/></Match>');
  });
});

describe('spotbugsParserFor', () => {
  const findings = spotbugsParserFor([]).parse(REPORT, { project_path: ROOT }).findings;

  it('every result, its source under the -sourcepath root, its CWE; injections high whatever the level', () => {
    expect(findings.map((f) => [f.rule_id, f.file_path, f.line_start, f.severity])).toEqual([
      ['COMMAND_INJECTION', 'src/main/java/com/example/App.java', 14, 'high'],
      ['SQL_INJECTION_JDBC', 'src/main/java/com/example/App.java', 10, 'high'],
      ['SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE', 'src/main/java/com/example/App.java', 10, 'high'],
      ['WEAK_MESSAGE_DIGEST_MD5', 'src/main/java/com/example/App.java', 18, 'medium'],
      ['COMMAND_INJECTION', 'src/main/java/com/example/Uses.java', 7, 'high'],
    ]);
    expect(findings[0]).toMatchObject({ tool: 'spotbugs', category: 'security', title: 'Potential Command Injection' });
    expect(findings[0]?.cwe).toContain('CWE-78');
    expect(findings.find((f) => f.rule_id === 'WEAK_MESSAGE_DIGEST_MD5')?.cwe).toContain('CWE-328');
  });

  it('a source SpotBugs did not find under a root: the one project file ending with its package path, else as written', () => {
    const sarif = JSON.stringify({
      runs: [
        {
          tool: { driver: { name: 'SpotBugs', rules: [{ id: 'XSS_SERVLET', relationships: [] }] } },
          results: [
            { ruleId: 'XSS_SERVLET', level: 'warning', message: { text: 'XSS' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'com/x/Web.java' }, region: { startLine: 4 } } }] },
          ],
        },
      ],
    });
    expect(spotbugsParserFor(['mod/src/main/java/com/x/Web.java', 'README.md']).parse(sarif, {}).findings[0]?.file_path).toBe(
      'mod/src/main/java/com/x/Web.java',
    );
    expect(spotbugsParserFor(['a/com/x/Web.java', 'b/com/x/Web.java']).parse(sarif, {}).findings[0]?.file_path).toBe('com/x/Web.java');
    // Kotlin need not mirror its package: the one file of that name.
    expect(spotbugsParserFor(['src/main/kotlin/x/Web.java', 'README.md']).parse(sarif, {}).findings[0]?.file_path).toBe(
      'src/main/kotlin/x/Web.java',
    );
    expect(spotbugsParserFor(['a/Web.java', 'b/Web.java']).parse(sarif, {}).findings[0]?.file_path).toBe('com/x/Web.java');
  });
});
