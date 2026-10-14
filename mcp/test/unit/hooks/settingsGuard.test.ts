/**
 * `hooks/settingsGuard.ts` — which edits of Claude Code's own settings the
 * Write/Edit guard refuses (final review M5): only one that INTRODUCES
 * `disableAllHooks: true` or an env switch that turns a dev-guardian hook off.
 * The end-to-end half (the dispatcher's deny) is in `hooksDispatcher.test.ts`.
 */

import { describe, expect, it } from 'vitest';
import {
  applyEdit,
  hookLooseningSettings,
  isClaudeSettingsPath,
  newlyAsked,
  newlyLoosened,
  settingsVerdict,
} from '../../../src/hooks/settingsGuard.js';
import { expectLinear } from '../../helpers/timing.js';

describe('isClaudeSettingsPath', () => {
  it.each([
    ['.claude/settings.json', true],
    ['.claude/settings.local.json', true],
    ['C:\\Users\\me\\CLAUDE SKILLS\\proj\\.claude\\settings.local.json', true],
    ['/home/me/.claude/settings.json', true],
    ['/proj/.CLAUDE/Settings.json', true],
    ['.claude/settings.json.bak', false],
    ['claude/settings.json', false],
    ['.claude/other.json', false],
    ['docs/settings.json', false],
  ] as const)('%s -> %s', (path, expected) => {
    expect(isClaudeSettingsPath(path)).toBe(expected);
  });

  // Review round 2, ruling 3: Claude Code reads its user settings from
  // `$CLAUDE_CONFIG_DIR` when that is set — `~/.claude-conta2/settings.json` on
  // the machine this was found on — and nothing guarded them there.
  describe('under CLAUDE_CONFIG_DIR', () => {
    const win = process.platform === 'win32';
    const dir = win ? 'C:\\Users\\me\\.claude-conta2' : '/home/me/.claude-conta2';
    const sep = win ? '\\' : '/';
    it.each([
      [`${dir}${sep}settings.json`, true],
      [`${dir}${sep}settings.local.json`, true],
      [`${dir}${sep}`.replace(/[\\/]$/, '/settings.json'), true],
      [`${dir}${sep}other.json`, false],
      [`${dir}${sep}sub${sep}settings.json`, false],
      [`${dir}-other${sep}settings.json`, false],
    ] as const)('%s -> %s', (path, expected) => {
      expect(isClaudeSettingsPath(path, dir)).toBe(expected);
      expect(isClaudeSettingsPath(path)).toBe(false);
    });

    it.runIf(win)('case-insensitively on Windows', () => {
      expect(isClaudeSettingsPath('c:\\users\\ME\\.Claude-Conta2\\Settings.JSON', dir)).toBe(true);
    });
  });
});

describe('hookLooseningSettings', () => {
  it('names each switch that turns a hook off', () => {
    expect(
      hookLooseningSettings(
        JSON.stringify({
          disableAllHooks: true,
          env: { GUARDIAN_HOOKS: 'off', GUARDIAN_HOOKS_BASH_BLOCK: 'false', GUARDIAN_PKG_VET: '0' },
        }),
      ),
    ).toEqual([
      'disableAllHooks: true',
      'env GUARDIAN_HOOKS=off',
      'env GUARDIAN_HOOKS_BASH_BLOCK=false',
      'env GUARDIAN_PKG_VET=0',
    ]);
  });

  it('matches env names case-insensitively (Windows env is) and a numeric 0', () => {
    expect(hookLooseningSettings('{"env":{"guardian_pkg_vet":0,"Guardian_Hooks_Bash_Block":"0"}}')).toEqual([
      'env GUARDIAN_PKG_VET=0',
      'env GUARDIAN_HOOKS_BASH_BLOCK=0',
    ]);
  });

  it('is empty for values that switch nothing off, and for everything else in the file', () => {
    expect(
      hookLooseningSettings(
        JSON.stringify({
          disableAllHooks: false,
          env: { GUARDIAN_HOOKS: 'on', GUARDIAN_HOOKS_BASH_BLOCK: '1', GUARDIAN_PKG_VET: '1', NODE_ENV: 'x' },
          permissions: { allow: ['Bash(npm test)'] },
          hooks: { PostToolUse: [] },
        }),
      ),
    ).toEqual([]);
  });

  it('falls back to patterns for text that is not a JSON object (JSONC, an edit fragment)', () => {
    expect(hookLooseningSettings('// mine\n{ "disableAllHooks": true, }')).toEqual(['disableAllHooks: true']);
    expect(hookLooseningSettings('"FOO": "1", "GUARDIAN_PKG_VET": "0"')).toEqual(['env GUARDIAN_PKG_VET=0']);
    expect(hookLooseningSettings('"GUARDIAN_HOOKS_BASH_BLOCK": "1"')).toEqual([]);
  });

  it('a leading byte-order mark does not hide the keys', () => {
    expect(hookLooseningSettings('\uFEFF{"disableAllHooks":true}')).toEqual(['disableAllHooks: true']);
  });

  // Follow-up Part Y: `enabledPlugins` turning the plugin off switches every
  // one of its hooks off, exactly like `disableAllHooks`.
  it('names an enabledPlugins entry that turns dev-guardian off, under any marketplace name', () => {
    expect(hookLooseningSettings('{"enabledPlugins":{"dev-guardian@dev-guardian":false}}')).toEqual([
      'enabledPlugins dev-guardian@dev-guardian=false',
    ]);
    expect(
      hookLooseningSettings('{"enabledPlugins":{"other@x":false,"Dev-Guardian@corp-marketplace":false,"dev-guardian":true}}'),
    ).toEqual(['enabledPlugins Dev-Guardian@corp-marketplace=false']);
  });

  it('does not name enabledPlugins entries that turn dev-guardian on, or other plugins off', () => {
    expect(hookLooseningSettings('{"enabledPlugins":{"dev-guardian@dev-guardian":true,"other@x":false}}')).toEqual([]);
    expect(hookLooseningSettings('{"permissions":{"deny":["dev-guardian@x"]},"dev-guardian@x":false}')).toEqual([]);
  });

  it('falls back to a pattern for an enabledPlugins fragment', () => {
    expect(hookLooseningSettings('"dev-guardian@dev-guardian": false')).toEqual([
      'enabledPlugins dev-guardian@dev-guardian=false',
    ]);
    expect(hookLooseningSettings('"dev-guardian@dev-guardian": true')).toEqual([]);
  });
});

describe('newlyLoosened', () => {
  it('reports only what the new content adds', () => {
    const before = '{"env":{"GUARDIAN_PKG_VET":"0"}}';
    expect(newlyLoosened(before, '{"env":{"GUARDIAN_PKG_VET":"0"},"permissions":{"allow":["Bash(ls)"]}}')).toEqual([]);
    expect(newlyLoosened(before, '{"env":{"GUARDIAN_PKG_VET":"0","GUARDIAN_HOOKS":"off"}}')).toEqual([
      'env GUARDIAN_HOOKS=off',
    ]);
  });

  it('a new file adds everything it sets', () => {
    expect(newlyLoosened(undefined, '{"disableAllHooks":true}')).toEqual(['disableAllHooks: true']);
  });

  it('flipping dev-guardian from enabled to disabled is new; keeping it disabled is not', () => {
    const on = '{"enabledPlugins":{"dev-guardian@dev-guardian":true}}';
    const off = '{"enabledPlugins":{"dev-guardian@dev-guardian":false}}';
    expect(newlyLoosened(on, off)).toEqual(['enabledPlugins dev-guardian@dev-guardian=false']);
    expect(newlyLoosened(off, off.replace('}}', ',"x@y":true}}'))).toEqual([]);
  });
});

// Review of 3.4.0, finding 4: variables that switch the hooks off whatever
// their value, the value forms another parser may read as the switch, and a
// settings file that is JSONC, escapes a key or repeats one.
describe('review of 3.4.0, finding 4: every form that may switch the hooks off', () => {
  const key = ['disable', 'AllHooks'].join('');

  it('NODE_OPTIONS and GUARDIAN_PKG_VET_DEADLINE_MS switch a hook off whatever their value — a new value is new', () => {
    expect(hookLooseningSettings('{"env":{"NODE_OPTIONS":"--import=data:text/javascript,process.exit(0)"}}')).toEqual([
      'env NODE_OPTIONS=--import=data:text/javascript,process.exit(0)',
    ]);
    expect(hookLooseningSettings('{"env":{"guardian_pkg_vet_deadline_ms":1}}')).toEqual(['env GUARDIAN_PKG_VET_DEADLINE_MS=1']);
    const mine = '{"env":{"NODE_OPTIONS":"--max-old-space-size=4096"}}';
    expect(newlyLoosened(mine, mine.replace('}}', ',"A":"b"}}'))).toEqual([]);
    expect(newlyLoosened(mine, '{"env":{"NODE_OPTIONS":"--require ./x.js"}}')).toEqual(['env NODE_OPTIONS=--require ./x.js']);
    expect(hookLooseningSettings('"NODE_OPTIONS": "--require x"')).toEqual(['env NODE_OPTIONS=--require x']);
  });

  it('PATH, HOME and USERPROFILE are asked about, not refused — in env only', () => {
    expect(newlyLoosened(undefined, '{"env":{"PATH":"/tmp/fake:/usr/bin"}}')).toEqual([]);
    expect(newlyAsked(undefined, '{"env":{"PATH":"/tmp/fake:/usr/bin"}}')).toEqual(['env PATH=/tmp/fake:/usr/bin']);
    expect(newlyAsked('{"env":{"Path":"C:/x"}}', '{"env":{"Path":"C:/x"},"model":"m"}')).toEqual([]);
    expect(newlyAsked(undefined, '{"env":{"HOME":"/tmp/h","USERPROFILE":"C:/h"}}')).toEqual(['env HOME=/tmp/h', 'env USERPROFILE=C:/h']);
    expect(newlyAsked(undefined, '{"extraKnownMarketplaces":{"m":{"source":{"source":"directory","path":"/srv/m"}}}}')).toEqual([]);
    expect(newlyAsked(undefined, '"source": "directory", "path": "/srv/m"')).toEqual([]);
    expect(newlyAsked(undefined, '"PATH": "/tmp/fake"')).toEqual(['env PATH=/tmp/fake']);
  });

  it.each([
    [`{"${key}": "true"}`, true],
    [`{"${key}": 1}`, true],
    [`{"${key}": "false"}`, true],
    [`{"${key}": {}}`, true],
    [`{"${key}": false}`, false],
    [`{"${key}": 0}`, false],
    [`{"${key}": null}`, false],
    [`{"${key}": ""}`, false],
  ])('disableAllHooks in %s switches the hooks off: %s', (text, off) => {
    expect(hookLooseningSettings(text)).toEqual(off ? ['disableAllHooks: true'] : []);
    expect(hookLooseningSettings(text.slice(1, -1))).toEqual(off ? ['disableAllHooks: true'] : []);
  });

  it.each(['"false"', '0', 'null', '"true"', '"no"'])('an enabledPlugins entry naming dev-guardian set to %s turns it off', (value) => {
    expect(hookLooseningSettings(`{"enabledPlugins":{"dev-guardian@m":${value}}}`)).toEqual(['enabledPlugins dev-guardian@m=false']);
    expect(hookLooseningSettings(`"dev-guardian@m": ${value}`)).toEqual(['enabledPlugins dev-guardian@m=false']);
  });

  it('a JSONC file, an escaped key and a repeated key are all read', () => {
    const escaped = '"disable\\u0041llHooks"';
    expect(hookLooseningSettings(`// mine\n{ ${escaped}: true, /* x */ "model": "m", }`)).toEqual(['disableAllHooks: true']);
    expect(hookLooseningSettings(`${escaped}: true`)).toEqual(['disableAllHooks: true']);
    expect(hookLooseningSettings(`{"${key}": true, "${key}": false}`)).toEqual(['disableAllHooks: true']);
    expect(hookLooseningSettings('{"env":{"GUARDIAN_HOOKS":"off"},"env":{"GUARDIAN_HOOKS":"on"}}')).toEqual(['env GUARDIAN_HOOKS=off']);
    expect(hookLooseningSettings('{"env":{"GUARDIAN_HOOKS":"off","GUARDIAN_HOOKS":"on"}}')).toEqual(['env GUARDIAN_HOOKS=off']);
  });

  it('a file nested past what is read, or that is no JSON, falls back to the patterns without throwing', () => {
    expect(hookLooseningSettings(`${'['.repeat(100)}{"${key}": true}${']'.repeat(100)}`)).toEqual(['disableAllHooks: true']);
    expect(hookLooseningSettings(`{"${key}": true`)).toEqual(['disableAllHooks: true']);
    expect(hookLooseningSettings('/* unterminated')).toEqual([]);
  });

  it('a large settings file is read in linear time', () => {
    const make = (n: number): string =>
      JSON.stringify({ permissions: { allow: Array.from({ length: Math.ceil(n / 24) }, (_, k) => `Bash(npm run t${String(k)})`) } }, null, 1);
    expectLinear('the lenient settings reader', (n) => hookLooseningSettings(`// c\n${make(n)}`), 16 * 1024);
  }, 120_000);
});

describe('applyEdit', () => {
  it('replaces the first occurrence, or every one with replaceAll', () => {
    expect(applyEdit('a b a', 'a', 'x')).toBe('x b a');
    expect(applyEdit('a b a', 'a', 'x', true)).toBe('x b x');
  });

  it('is undefined when the old string is not there (the edit cannot be reproduced)', () => {
    expect(applyEdit('abc', 'z', 'x')).toBeUndefined();
    expect(applyEdit('abc', '', 'x')).toBeUndefined();
  });

  it('keeps `$` sequences in the replacement literal', () => {
    expect(applyEdit('a', 'a', "$& $' $1")).toBe("$& $' $1");
  });
});

// Review 12, findings 2, 3 and 7.
describe('review 12: deep settings, more env switches, managed settings', () => {
  const key = ['disable', 'AllHooks'].join('');
  const deep = (depth: number, reps: number, extra = `"${key}":true`): string =>
    `{"nest":${'['.repeat(depth)}0${']'.repeat(depth)},"note":"${'dev-guardian'.repeat(reps)}",${extra}}`;

  it('valid JSON nested past what the lenient reader reads is read by JSON.parse, not the patterns (finding 2)', () => {
    expect(hookLooseningSettings(deep(70, 10))).toEqual(['disableAllHooks: true']);
    expect(hookLooseningSettings(deep(70, 10, '"env":{"NODE_OPTIONS":"--require=./x.js"}'))).toEqual(['env NODE_OPTIONS=--require=./x.js']);
    expect(hookLooseningSettings(deep(70, 10, '"enabledPlugins":{"dev-guardian@m":false}'))).toEqual(['enabledPlugins dev-guardian@m=false']);
    expect(hookLooseningSettings(deep(70, 10, '"permissions":{}'))).toEqual([]);
  });

  it('valid JSON nested 70 deep with a long dev-guardian string: eight times as long costs well under 22.6 times as much', () => {
    expectLinear('deep settings with a long string', (n) => hookLooseningSettings(deep(70, Math.ceil(n / 12))), 2_000);
  }, 120_000);

  it('a fragment with a long string repeating dev-guardian: the plugin pattern stays linear', () => {
    expectLinear('a fragment repeating dev-guardian', (n) => hookLooseningSettings(`"note": "${'dev-guardian'.repeat(Math.ceil(n / 12))}", "x": 1`), 2_000);
    expect(hookLooseningSettings(`"note": "${'dev-guardian'.repeat(100)}", "dev-guardian@m": false`)).toEqual(['enabledPlugins dev-guardian@m=false']);
  }, 120_000);

  it('settingsVerdict reads each side once, and says when it ran past its deadline', () => {
    expect(settingsVerdict('{}', `{"${key}": true, "env": {"PATH": "/x"}}`)).toEqual({ off: ['disableAllHooks: true'], ask: ['env PATH=/x'] });
    let t = 0;
    const now = (): number => (t += 1000);
    expect(settingsVerdict('{}', '{}', { deadline: 1500, now })).toMatchObject({ late: true });
  });

  it.each([
    ['GUARDIAN_OFFLINE', '1', 'off'],
    ['NODE_TLS_REJECT_UNAUTHORIZED', '0', 'off'],
    ['NODE_USE_ENV_PROXY', '1', 'ask'],
    ['HTTPS_PROXY', 'http://127.0.0.1:9', 'ask'],
    ['http_proxy', 'http://127.0.0.1:9', 'ask'],
    ['NODE_EXTRA_CA_CERTS', '/x/ca.pem', 'ask'],
    ['GUARDIAN_ANYTHING', 'x', 'ask'],
    ['NODE_TLS_REJECT_UNAUTHORIZED', '1', 'ask'],
    ['NODE_ENV', 'test', 'none'],
    ['GUARDIAN_HOOKS', 'on', 'none'],
    ['GUARDIAN_PKG_VET', '1', 'none'],
  ] as const)('env %s=%s: %s (finding 3)', (name, value, expected) => {
    const v = settingsVerdict(undefined, JSON.stringify({ env: { [name]: value } }));
    expect({ off: v.off.length > 0, ask: v.ask.length > 0 }).toEqual({ off: expected === 'off', ask: expected === 'ask' });
  });

  it.each([
    ['C:\\Program Files\\ClaudeCode\\managed-settings.json', true],
    ['C:/ProgramData/ClaudeCode/managed-settings.json', true],
    ['/Library/Application Support/ClaudeCode/managed-settings.json', true],
    ['/etc/claude-code/managed-settings.json', true],
    ['/etc/claude-code/other.json', false],
    ['docs/managed-settings.json', false],
  ] as const)('%s is Claude Code settings: %s (finding 7)', (path, expected) => {
    expect(isClaudeSettingsPath(path)).toBe(expected);
  });
});
