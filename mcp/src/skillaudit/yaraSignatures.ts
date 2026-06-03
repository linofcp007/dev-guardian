/**
 * YARA-style signature engine (pure JS, no native YARA binary).
 *
 * Shipping the real `yara` binary cross-platform (and keeping rule files in
 * sync) is a maintenance and portability cost we don't want for a plugin
 * that must "just work" on Windows/macOS/Linux. Instead we model the part of
 * YARA that matters here: named signatures, each a set of string/regex
 * conditions matched content-wide, with an `any` / `all` / `minHits`
 * condition. This catches the same class of artifacts (encoded payloads,
 * known C2/exfil hosts, reverse shells, miners) without a toolchain.
 *
 * Signatures are matched against whole-file content (not per line) because
 * obfuscated payloads are frequently single very long lines. A reportable
 * line number is recovered from the first matching string.
 *
 * Pure data + pure functions. No I/O.
 */

import type { Severity } from '../types.js';
import type { ThreatCategory } from './taxonomy.js';

export interface YaraSignature {
  id: string;
  category: ThreatCategory;
  severity: Severity;
  title: string;
  description: string;
  strings: RegExp[];
  /** 'any' (default): minHits distinct strings; 'all': every string. */
  condition?: 'any' | 'all';
  /** For 'any', minimum distinct strings that must hit (default 1). */
  minHits?: number;
}

export interface YaraMatch {
  signature: YaraSignature;
  line: number;
  snippet: string;
  matched: number;
}

export const YARA_SIGNATURES: YaraSignature[] = [
  {
    id: 'sig-exfil-host',
    category: 'data_exfiltration',
    severity: 'high',
    title: 'Known exfiltration / drop host',
    description:
      'References a host commonly used to receive exfiltrated data or out-of-band callbacks.',
    strings: [
      /\b(pastebin\.com|hastebin\.com|paste\.ee|ix\.io|transfer\.sh|0x0\.st|file\.io)\b/i,
      /\b(requestbin|webhook\.site|pipedream\.net|ngrok\.(io|app)|burpcollaborator\.net|oast\.(pro|live|site|fun))\b/i,
      /discord(app)?\.com\/api\/webhooks\//i,
      /api\.telegram\.org\/bot[0-9]+:/i,
    ],
  },
  {
    id: 'sig-reverse-shell',
    category: 'dangerous_code',
    severity: 'critical',
    title: 'Reverse / bind shell payload',
    description: 'Classic reverse-shell one-liner (bash /dev/tcp, nc -e, python socket+subprocess).',
    strings: [
      /\/dev\/tcp\/\d{1,3}(\.\d{1,3}){3}\/\d+/i,
      /\bbash\s+-i\s+>&?\s*\/dev\/tcp/i,
      /\bnc(\.traditional)?\b[^\n]{0,40}-e\s+(\/bin\/(ba)?sh|cmd)/i,
      /import\s+socket\s*,\s*subprocess\s*,\s*os/i,
      /IEX\s*\(\s*New-Object\s+Net\.WebClient\)/i,
    ],
  },
  {
    id: 'sig-crypto-miner',
    category: 'rogue_agent',
    severity: 'high',
    title: 'Cryptocurrency miner',
    description: 'References to mining software or stratum pools.',
    strings: [
      /\bxmrig\b/i,
      /stratum\+tcp:\/\//i,
      /\b(minergate|coinhive|cryptonight|nicehash)\b/i,
    ],
  },
  {
    id: 'sig-wallet-hijack',
    category: 'rogue_agent',
    severity: 'high',
    title: 'Clipboard / wallet-address hijack',
    description:
      'Hardcoded crypto wallet address combined with clipboard access — typical address-swap malware.',
    strings: [
      /\b(0x[a-fA-F0-9]{40}|bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/,
      /(clipboard|pbcopy|xclip|Set-Clipboard|navigator\.clipboard)/i,
    ],
    condition: 'all',
  },
  {
    id: 'sig-long-base64',
    category: 'yara',
    severity: 'medium',
    title: 'Large encoded blob',
    description:
      'A long contiguous base64 string — often an embedded binary or obfuscated payload. Inspect manually.',
    strings: [/[A-Za-z0-9+/]{220,}={0,2}/],
  },
  {
    id: 'sig-hex-blob',
    category: 'yara',
    severity: 'medium',
    title: 'Large \\x hex-escaped blob',
    description: 'A long run of \\xNN hex escapes — common obfuscation for shellcode or payloads.',
    strings: [/(?:\\x[0-9a-fA-F]{2}){24,}/],
  },
  {
    id: 'sig-fromcharcode-obfuscation',
    category: 'yara',
    severity: 'medium',
    title: 'String.fromCharCode obfuscation',
    description: 'Heavy use of fromCharCode to assemble strings hidden from static review.',
    strings: [/String\.fromCharCode\s*\((?:\s*\d+\s*,){8,}/],
  },
  {
    id: 'sig-disable-history',
    category: 'privilege_escalation',
    severity: 'medium',
    title: 'Anti-forensics: shell history tampering',
    description: 'Disables or wipes shell history to hide activity.',
    strings: [
      /unset\s+HISTFILE|export\s+HISTSIZE=0|set\s+\+o\s+history/i,
      /history\s+-c\b|rm\s+[^\n]{0,40}\.bash_history/i,
    ],
  },
];

/** Match all signatures against whole-file content. */
export function matchSignatures(content: string): YaraMatch[] {
  const out: YaraMatch[] = [];
  for (const sig of YARA_SIGNATURES) {
    const hits: Array<{ index: number }> = [];
    for (const re of sig.strings) {
      const m = firstMatch(content, re);
      if (m) hits.push({ index: m.index });
    }
    const need = sig.condition === 'all' ? sig.strings.length : sig.minHits ?? 1;
    if (hits.length >= need) {
      const firstIndex = Math.min(...hits.map((h) => h.index));
      const { line, snippet } = locate(content, firstIndex);
      out.push({ signature: sig, line, snippet, matched: hits.length });
    }
  }
  return out;
}

function firstMatch(content: string, re: RegExp): { index: number } | null {
  const flags = re.flags.includes('g') ? re.flags : `${re.flags}g`;
  const global = new RegExp(re.source, flags);
  const m = global.exec(content);
  return m ? { index: m.index } : null;
}

function locate(content: string, index: number): { line: number; snippet: string } {
  const before = content.slice(0, index);
  const line = before.split(/\r?\n/).length;
  const lineStart = before.lastIndexOf('\n') + 1;
  const lineEnd = content.indexOf('\n', index);
  const raw = content.slice(lineStart, lineEnd === -1 ? content.length : lineEnd);
  return { line, snippet: raw.trim().slice(0, 240) };
}
