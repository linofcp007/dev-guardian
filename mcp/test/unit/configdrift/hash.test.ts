/**
 * What the config-drift hash notices, and what it deliberately does not.
 *
 * The whole mechanism rests on one comparison: "is the file on the user's
 * disk still the file we shipped?". Answering that with a raw byte hash gets
 * the answer wrong on this repo's own primary platform pair — configs are
 * authored on Windows and consumed in POSIX CI, and git's `core.autocrlf`
 * rewrites line endings on checkout. A byte hash would report every Windows
 * checkout as "the user edited their copy" and every POSIX one as "they
 * didn't", from the same commit. So the hash is taken over a canonical form,
 * and these tests pin exactly which differences survive canonicalisation.
 */

import { describe, expect, it } from 'vitest';
import { hashConfigText, stripProvenanceHeader } from '../../../src/configdrift/hash.js';
import { buildProvenanceHeader, commentPrefixFor } from '../../../src/configdrift/header.js';

describe('canonicaliseConfig', () => {
  it('treats CRLF and LF as the same content', () => {
    expect(hashConfigText('rules:\r\n  - id: a\r\n')).toBe(hashConfigText('rules:\n  - id: a\n'));
  });

  it('treats a lone CR as the same content', () => {
    expect(hashConfigText('rules:\r  - id: a\r')).toBe(hashConfigText('rules:\n  - id: a\n'));
  });

  it('ignores a UTF-8 BOM', () => {
    expect(hashConfigText('﻿rules: []\n')).toBe(hashConfigText('rules: []\n'));
  });

  it('ignores a missing or doubled trailing newline', () => {
    expect(hashConfigText('rules: []')).toBe(hashConfigText('rules: []\n\n\n'));
  });

  it('does NOT ignore trailing whitespace inside a line', () => {
    // A real edit, however trivial. Stripping it would also hide a rule whose
    // only change was a re-indent, which is not always cosmetic in YAML.
    expect(hashConfigText('rules: []   \n')).not.toBe(hashConfigText('rules: []\n'));
  });

  it('does NOT ignore a comment change', () => {
    expect(hashConfigText('# a\nrules: []\n')).not.toBe(hashConfigText('# b\nrules: []\n'));
  });
});

describe('stripProvenanceHeader', () => {
  it('removes the block we stamp, so a stamped copy hashes as the shipped body', () => {
    const prefix = commentPrefixFor('.semgrep.yml');
    if (prefix === null) throw new Error('expected a comment prefix for .semgrep.yml');
    const body = 'rules:\n  - id: a\n';
    const stamped = buildProvenanceHeader({
      source: 'semgrep/base.yml',
      pluginVersion: '1.8.0',
      prefix,
    }) + body;
    expect(stripProvenanceHeader(stamped)).toBe(body);
    expect(hashConfigText(stamped)).toBe(hashConfigText(body));
  });

  it('leaves a file that has no header untouched', () => {
    const body = '# just an ordinary comment\nrules: []\n';
    expect(stripProvenanceHeader(body)).toBe(body);
  });

  it('leaves an unterminated lookalike header untouched rather than eating the file', () => {
    const body = '# dev-guardian:managed something a user typed\nrules: []\n';
    expect(stripProvenanceHeader(body)).toBe(body);
  });
});

describe('commentPrefixFor', () => {
  it('gives # for the YAML and TOML targets', () => {
    expect(commentPrefixFor('.semgrep.yml')).toBe('#');
    expect(commentPrefixFor('.gitleaks.toml')).toBe('#');
    expect(commentPrefixFor('.pre-commit-config.yaml')).toBe('#');
  });

  it('gives null for JSON, which has no comment syntax', () => {
    // This is the reason a header cannot be the only provenance mechanism.
    expect(commentPrefixFor('renovate.json')).toBeNull();
  });
});
