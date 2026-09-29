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
  newlyLoosened,
} from '../../../src/hooks/settingsGuard.js';

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
          env: { GUARDIAN_HOOKS: 'on', GUARDIAN_HOOKS_BASH_BLOCK: '1', GUARDIAN_PKG_VET: '1', NODE_OPTIONS: 'x' },
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
