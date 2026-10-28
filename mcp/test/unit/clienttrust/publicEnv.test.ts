/**
 * A secret behind a browser-exposed env prefix, in `.env*` files
 * (`clienttrust/publicEnv.ts`): what the Semgrep rule
 * `client-public-env-secret` cannot read — the files git ignores, and the
 * VALUE (a service-role JWT in the anon key's variable). Pure: text in,
 * findings out.
 *
 * Every secret-shaped value is built at run time, never written whole into
 * the repository: the repository's own secret scan must not find them.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  checkEnvFile,
  classifySecretValue,
  ENV_PUBLIC_SECRET_RULE,
  isEnvFileName,
  isEnvTemplateName,
  jwtRole,
  parseEnvFile,
  PUBLIC_ENV_SECRET_NAME,
  publicNameSaysSecret,
} from '../../../src/clienttrust/publicEnv.js';
import { isCredentialFinding } from '../../../src/fingerprint/findingIdentity.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../../..', import.meta.url)));
const PACK = resolve(REPO_ROOT, 'configs', 'semgrep', 'client-trust.yml');

const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (role: string): string =>
  `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', ref: 'qwertyuiopasdfgh', role, iat: 1700000000, exp: 2000000000 })}.${'Zx9Q'.repeat(10)}`;
const SERVICE_ROLE = jwt('service_role');
const ANON = jwt('anon');
const STRIPE_LIVE = ['sk', 'live', 'Zx9Qw3Er5Ty7Ui9OpAs1Df3Gh5Jk7L'].join('_');
const STRIPE_TEST = ['sk', 'test', 'Zx9Qw3Er5Ty7Ui9OpAs1Df3Gh5Jk7L'].join('_');
const STRIPE_PUBLISHABLE = ['pk', 'live', 'Zx9Qw3Er5Ty7Ui9OpAs1Df3Gh5Jk7L'].join('_');
const OPENAI = `sk-proj-${'Ab3dEf5gHi7jKl9mNo1pQr3sTu5vWx7yZa9bCd1eFg'}`;
const DB_URL = ['postgres://app', 'Zx9Qw3Er5Ty7@db.internal:5432/app'].join(':');
const FIREBASE = `AIza${'Sy'}${'B1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R7'}`;

describe('the names', () => {
  it('a browser prefix plus a secret name: flagged; a public-by-design or server-only name: not', () => {
    for (const name of [
      'NEXT_PUBLIC_STRIPE_SECRET_KEY',
      'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY',
      'VITE_SUPABASE_SERVICE_KEY',
      'EXPO_PUBLIC_OPENAI_API_KEY',
      'REACT_APP_JWT_SECRET',
      'NUXT_PUBLIC_DATABASE_URL',
      'GATSBY_ALGOLIA_ADMIN_KEY',
      'VUE_APP_DB_PASSWORD',
      'PUBLIC_ANTHROPIC_API_KEY',
      'NEXT_PUBLIC_STRIPE_WEBHOOK_SECRET',
      'VITE_GROQ_KEY',
      'NEXT_PUBLIC_REPLICATE_API_TOKEN',
    ]) {
      expect(publicNameSaysSecret(name), name).toBe(true);
    }
    for (const name of [
      'NEXT_PUBLIC_SUPABASE_ANON_KEY',
      'NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY',
      'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY',
      'NEXT_PUBLIC_FIREBASE_API_KEY',
      'NEXT_PUBLIC_SENTRY_DSN',
      'NEXT_PUBLIC_RECAPTCHA_SITE_KEY',
      'NEXT_PUBLIC_GOOGLE_MAPS_API_KEY',
      'NEXT_PUBLIC_HAS_SECRETSAUCE',
      'STRIPE_SECRET_KEY',
      'SUPABASE_SERVICE_ROLE_KEY',
      'OPENAI_API_KEY',
      'PUBLIC_URL',
    ]) {
      expect(publicNameSaysSecret(name), name).toBe(false);
    }
  });

  it('is the same expression as the Semgrep rule client-public-env-secret (configs/semgrep/client-trust.yml)', () => {
    const yaml = readFileSync(PACK, 'utf8');
    const start = yaml.indexOf('  - id: client-public-env-secret');
    const end = yaml.indexOf('  - id: client-supabase-service-role');
    const regex = /^\s+regex: (.+)$/m.exec(yaml.slice(start, end))?.[1];
    expect(regex, 'the rule has a metavariable-regex').toBeDefined();
    expect(regex).toBe(PUBLIC_ENV_SECRET_NAME.source);
  });

  it('env file names: .env and .env.<anything>, never .envrc; templates by their suffix', () => {
    for (const n of ['.env', '.env.local', '.env.production.local', '.env.example']) expect(isEnvFileName(n), n).toBe(true);
    for (const n of ['.envrc', '.environment', 'env', 'x.env', '.env/']) expect(isEnvFileName(n), n).toBe(false);
    for (const n of ['.env.example', '.env.local.example', '.env.sample', '.env.template', '.env.dist', '.env.defaults']) {
      expect(isEnvTemplateName(n), n).toBe(true);
    }
    for (const n of ['.env', '.env.local', '.env.production']) expect(isEnvTemplateName(n), n).toBe(false);
  });
});

describe('parseEnvFile', () => {
  it('reads export, spaces, quotes, inline comments and a multi-line double-quoted value', () => {
    const text = [
      '# comment',
      'export A=1',
      'B = "two words" # c',
      "C='x'",
      'D=plain # trailing',
      'E="line1',
      'line2"',
      'F=',
      'not an assignment',
    ].join('\n');
    expect(parseEnvFile(text)).toEqual([
      { name: 'A', value: '1', line: 2 },
      { name: 'B', value: 'two words', line: 3 },
      { name: 'C', value: 'x', line: 4 },
      { name: 'D', value: 'plain', line: 5 },
      { name: 'E', value: 'line1\nline2', line: 6 },
      { name: 'F', value: '', line: 8 },
    ]);
  });
});

describe('classifySecretValue', () => {
  it('knows a secret by its shape, whatever the variable', () => {
    expect(classifySecretValue(STRIPE_LIVE)).toEqual({ label: 'a Stripe live secret key', live: true });
    expect(classifySecretValue(STRIPE_TEST)).toEqual({ label: 'a Stripe test-mode secret key', live: false });
    expect(classifySecretValue(SERVICE_ROLE)).toEqual({ label: 'a Supabase service-role key', live: true });
    expect(classifySecretValue(`sb_secret_${'Ab3dEf5gHi7jKl9m'}`)?.label).toBe('a Supabase secret key');
    expect(classifySecretValue(`whsec_${'Ab3dEf5gHi7jKl9mNo1p'}`)?.label).toBe('a Stripe webhook signing secret');
    expect(classifySecretValue(DB_URL)?.label).toBe('a connection URL with a password');
    expect(classifySecretValue(OPENAI)?.label).toBe('an OpenAI API key');
  });

  it('public by design is never a secret: the anon JWT, pk_, a Firebase web key, a URL without a password', () => {
    expect(jwtRole(ANON)).toBe('anon');
    expect(classifySecretValue(ANON)).toBeNull();
    expect(classifySecretValue(STRIPE_PUBLISHABLE)).toBeNull();
    expect(classifySecretValue(`sb_publishable_${'Ab3dEf5gHi7jKl9m'}`)).toBeNull();
    expect(classifySecretValue(FIREBASE)).toBeNull();
    expect(classifySecretValue('https://abcd.supabase.co')).toBeNull();
    expect(classifySecretValue('postgres://app:<password>@db/app')).toBeNull();
    expect(classifySecretValue('')).toBeNull();
  });
});

describe('checkEnvFile', () => {
  const text = [
    `NEXT_PUBLIC_SUPABASE_URL=https://abcd.supabase.co`,
    `NEXT_PUBLIC_SUPABASE_ANON_KEY=${SERVICE_ROLE}`,
    `NEXT_PUBLIC_STRIPE_SECRET_KEY=${STRIPE_LIVE}`,
    `VITE_OPENAI_API_KEY=${OPENAI}`,
    `NEXT_PUBLIC_JWT_SECRET=a-real-looking-value-9f8e7d`,
    `NEXT_PUBLIC_STRIPE_TEST=${STRIPE_TEST}`,
    `NEXT_PUBLIC_RESEND_API_KEY=`,
    `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=${STRIPE_PUBLISHABLE}`,
    `NEXT_PUBLIC_FIREBASE_API_KEY=${FIREBASE}`,
    `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=${ANON}`,
    `SUPABASE_SERVICE_ROLE_KEY=${SERVICE_ROLE}`,
    `STRIPE_SECRET_KEY=${STRIPE_LIVE}`,
  ].join('\n');

  it('flags each browser-exposed secret on its line, by value or by name, at the scheme severity', () => {
    const findings = checkEnvFile('apps/web/.env.local', text);
    const rows = findings.map((f) => `${f.line_start} ${f.severity} ${f.title.split(':')[0]}`);
    expect(rows).toEqual([
      '2 critical NEXT_PUBLIC_SUPABASE_ANON_KEY',
      '3 critical NEXT_PUBLIC_STRIPE_SECRET_KEY',
      '4 critical VITE_OPENAI_API_KEY',
      '5 critical NEXT_PUBLIC_JWT_SECRET',
      '6 high NEXT_PUBLIC_STRIPE_TEST',
      '7 medium NEXT_PUBLIC_RESEND_API_KEY',
    ]);
    for (const f of findings) {
      expect(f.tool).toBe('guardian-client-trust');
      expect(f.rule_id).toBe(ENV_PUBLIC_SECRET_RULE);
      expect(f.file_path).toBe('apps/web/.env.local');
      expect(f.category).toBe('security');
      expect(f.cwe).toEqual(['CWE-798']);
    }
    const anon = findings[0];
    expect(anon?.title).toContain('a Supabase service-role key');
    expect(anon?.message).toMatch(/already reached the browsers/);
    expect(anon?.message).toMatch(/rotate/);
    expect(anon?.message).toMatch(/anon \(publishable\) key/);
  });

  it('never carries a value: no snippet, the value in no field, and a credential finding (identity never hashes the line)', () => {
    const findings = checkEnvFile('.env.local', text);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.snippet).toBeUndefined();
      const all = JSON.stringify(f);
      for (const secret of [SERVICE_ROLE, STRIPE_LIVE, OPENAI, STRIPE_TEST, 'a-real-looking-value-9f8e7d']) {
        expect(all.includes(secret), `${f.title} leaks a value`).toBe(false);
        expect(all.includes(secret.slice(0, 12)), `${f.title} leaks a prefix`).toBe(false);
      }
      expect(isCredentialFinding(f)).toBe(true);
    }
  });

  it('a template: a secret name with a placeholder is medium; a real key in a template keeps its severity', () => {
    const findings = checkEnvFile(
      '.env.example',
      ['NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_your-key-here', 'NEXT_PUBLIC_OPENAI_API_KEY=', `VITE_SERVICE_ROLE=${SERVICE_ROLE}`].join('\n'),
    );
    expect(findings.map((f) => `${f.line_start} ${f.severity}`)).toEqual(['1 medium', '2 medium', '3 critical']);
    expect(findings[0]?.message).toMatch(/Developers who copy this template/);
  });

  it('nothing for server-only variables, public-by-design values, comments and non-env text', () => {
    const quiet = [
      '# NEXT_PUBLIC_STRIPE_SECRET_KEY=' + STRIPE_LIVE,
      'STRIPE_SECRET_KEY=' + STRIPE_LIVE,
      `DATABASE_URL=${DB_URL}`,
      'NEXT_PUBLIC_SUPABASE_ANON_KEY=' + ANON,
      'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=' + STRIPE_PUBLISHABLE,
      'NEXT_PUBLIC_FIREBASE_API_KEY=' + FIREBASE,
      'NEXT_PUBLIC_APP_URL=https://example.com',
      'NEXT_PUBLIC_SENTRY_DSN=https://abc@o1.ingest.sentry.io/1',
    ].join('\n');
    expect(checkEnvFile('.env.local', quiet)).toEqual([]);
  });
});
