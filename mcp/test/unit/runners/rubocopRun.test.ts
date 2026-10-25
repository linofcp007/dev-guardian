/**
 * RuboCop's run judged, the files it is handed and its report read
 * (`runners/rubocopRun.ts`, `scannerParsers/rubocop.ts`). The report is
 * RuboCop 1.92.1's own (RubyInstaller 4.0.9) over a seeded `lib/app.rb`, a
 * `lib/broken.rb` that does not parse and a 32-line RSpec `describe` block,
 * with dev-guardian's configuration, measured on 2026-10-24: exit 1, the
 * syntax error a `Lint/Syntax` offense, the long `describe` block allowed.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import {
  declaredRubyVersion,
  judgeRubocop,
  rubocopConfig,
  RUBOCOP_SYNTAX_ERROR,
  rubocopEnv,
  rubySources,
} from '../../../src/runners/rubocopRun.js';
import { rubocopParser } from '../../../src/runners/scannerParsers/rubocop.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPORT = readFileSync(resolve(fileURLToPath(new URL('.', import.meta.url)), '../../fixtures/scanners/rubocop/seeded-1.92.1.json'), 'utf8');

const run = (exitCode: number | null, stdout: string, stderr = '', outcome: 'completed' | 'failed' | 'timed_out' = 'completed') => ({
  outcome,
  exitCode,
  stdout,
  stderr,
});

describe('rubySources', () => {
  it('.rb, .rake, .gemspec and .ru files, and Gemfile, Rakefile and their kin by name; nothing else', () => {
    expect(rubySources(['lib\\a.rb', 'Gemfile', 'x/Rakefile', 'tasks/db.rake', 'g.gemspec', 'config.ru', 'Gemfile.lock', 'a.erb', 'README'])).toEqual([
      'Gemfile',
      'config.ru',
      'g.gemspec',
      'lib/a.rb',
      'tasks/db.rake',
      'x/Rakefile',
    ]);
  });
});

describe('judgeRubocop', () => {
  it('exit 1 with offenses is sound; a file it could not parse (Lint/Syntax) is named, partial', () => {
    const j = judgeRubocop(run(1, REPORT));
    expect(j.ok).toBe(true);
    expect(j.partial).toEqual([{ file: 'lib/broken.rb', type: RUBOCOP_SYNTAX_ERROR, message: expect.stringContaining('unexpected token $end') }]);
  });

  it('exit 2 is a failure with what RuboCop said; a report that is not RuboCop’s, too', () => {
    const missing = judgeRubocop(run(2, '{"metadata":{"rubocop_version":"1.92.1"},"files":[]}', 'Error: No such file or directory: C:/p/nothere.rb'));
    expect(missing).toMatchObject({ ok: false, reason: 'exit 2: Error: No such file or directory: C:/p/nothere.rb' });
    expect(judgeRubocop(run(0, '{"files":[]}')).ok).toBe(false);
    expect(judgeRubocop(run(0, 'not json')).ok).toBe(false);
    expect(judgeRubocop(run(null, '', '', 'timed_out')).reason).toBe('did not finish (timed_out)');
  });
});

describe('rubocopConfig, the target Ruby and the environment', () => {
  it("pending cops off, no suggestions, the usual DSLs' blocks allowed to be long; the target Ruby when one is known", () => {
    expect(rubocopConfig(null)).toMatch(/AllCops:\n {2}NewCops: disable\n {2}SuggestExtensions: false\nMetrics/);
    expect(rubocopConfig('3.4')).toMatch(/SuggestExtensions: false\n {2}TargetRubyVersion: 3\.4\n/);
    for (const m of ['describe', 'context', 'it', 'task', 'namespace', 'draw']) expect(rubocopConfig(null)).toContain(`    - ${m}\n`);
  });

  it('declaredRubyVersion: .ruby-version, then .tool-versions, Gemfile.lock and the Gemfile, as text; null for JRuby or none', () => {
    const at = (files: Record<string, string>): { version: string; from: string } | null => {
      const dir = makeTempDir('rubocop-target-');
      for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
      return declaredRubyVersion(dir);
    };
    expect(at({ '.ruby-version': 'ruby-3.3.0\n', Gemfile: "ruby '3.1.0'\n" })).toEqual({ version: '3.3', from: '.ruby-version' });
    expect(at({ '.tool-versions': 'nodejs 22.13.0\nruby 3.2.2\n' })).toEqual({ version: '3.2', from: '.tool-versions' });
    expect(at({ 'Gemfile.lock': 'GEM\n  specs:\n\nRUBY VERSION\n   ruby 3.4.1p0\n\nBUNDLED WITH\n   2.6.2\n' })).toEqual({
      version: '3.4',
      from: 'Gemfile.lock',
    });
    expect(at({ Gemfile: "source 'https://rubygems.org'\nruby \"4.0.1\"\n" })).toEqual({ version: '4.0', from: 'Gemfile' });
    expect(at({ '.ruby-version': 'jruby-9.4.5.0\n' })).toBeNull();
    expect(at({})).toBeNull();
  });

  it('RUBYOPT, RUBYGEMS_GEMDEPS and BUNDLE_GEMFILE are left out, whatever their case; the rest kept', () => {
    expect(rubocopEnv({ RUBYOPT: '-rbundler/setup', rubygems_gemdeps: '-', BUNDLE_GEMFILE: 'Gemfile', PATH: '/bin', HOME: '/h' })).toEqual({
      PATH: '/bin',
      HOME: '/h',
    });
  });
});

describe('rubocopParser', () => {
  const findings = rubocopParser.parse(REPORT, { project_path: resolve('p') }).findings;

  it('every offense, its kind from its department and its severity from RuboCop’s, a Security warning medium', () => {
    expect(findings.map((f) => [f.rule_id, f.file_path, f.line_start, f.subcategory, f.severity])).toEqual([
      ['Naming/MethodParameterName', 'lib/app.rb', 1, 'naming', 'info'],
      ['Lint/UselessAssignment', 'lib/app.rb', 2, 'smell', 'low'],
      ['Security/Eval', 'lib/app.rb', 3, 'smell', 'medium'],
      ['Security/MarshalLoad', 'lib/app.rb', 7, 'smell', 'medium'],
      ['Lint/Syntax', 'lib/broken.rb', 1, 'smell', 'medium'],
    ]);
  });

  it('the cop and its page in the message', () => {
    expect(findings.find((f) => f.rule_id === 'Security/Eval')?.message).toContain('https://docs.rubocop.org/rubocop/cops_security.html#securityeval');
  });
});
