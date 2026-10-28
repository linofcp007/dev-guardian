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
  jwtClaims,
  parseEnvFile,
  PUBLIC_ENV_SECRET_NAME,
  publicNameSaysSecret,
} from '../../../src/clienttrust/publicEnv.js';
import { isCredentialFinding } from '../../../src/fingerprint/findingIdentity.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../../..', import.meta.url)));
const PACK = resolve(REPO_ROOT, 'configs', 'semgrep', 'client-trust.yml');

const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (role: string, extra: Record<string, unknown> = {}): string =>
  `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', ref: 'qwertyuiopasdfgh', role, iat: 1700000000, exp: 2000000000, ...extra })}.${'Zx9Q'.repeat(10)}`;
/** A signed-in user's access token: role authenticated, a subject, an expiry years away. */
const USER_TOKEN = jwt('authenticated', { sub: '5f0c1e2a-9b8d-4c7e-a6f5-0e1d2c3b4a59', email: 'someone@example.com', exp: 4102444800 });
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
      'NEXT_PUBLIC_WALLET_PASSPHRASE',
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
      'NEXT_PUBLIC_PASSWORD_MIN_LENGTH',
      'NEXT_PUBLIC_PASSWORD_RESET_URL',
      'VITE_AUTH_TOKEN_KEY',
      'PUBLIC_SECRET_SANTA_MODE',
      'NEXT_PUBLIC_STRIPE_SECRET_KEY_NAME',
      'NEXT_PUBLIC_OPENAI_API_KEY_ENABLED',
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
    expect(jwtClaims(ANON)).toEqual({ role: 'anon', subject: false });
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

  // Fix round 3, item 3: a template's values are a template's — no build ships
  // them. What a template exposes is the NAME: whoever fills it in puts the
  // secret behind the browser prefix.
  it('a template (.env.example, .sample, .template, .dist) is never critical: the finding is the browser prefix on a secret name', () => {
    const lines = [
      'NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_your-key-here',
      'NEXT_PUBLIC_OPENAI_API_KEY=',
      `VITE_SERVICE_ROLE=${SERVICE_ROLE}`,
      `NEXT_PUBLIC_STRIPE_KEY=${STRIPE_LIVE}`,
      'NEXT_PUBLIC_DB_PASSWORD=mypassword',
      'NEXT_PUBLIC_JWT_SECRET=a-real-looking-value-9f8e7d',
      `NEXT_PUBLIC_STRIPE_TEST=${STRIPE_TEST}`,
    ].join('\n');
    for (const file of ['.env.example', '.env.sample', '.env.template', '.env.dist', 'apps/web/.env.local.example']) {
      const findings = checkEnvFile(file, lines);
      expect(findings.map((f) => `${f.line_start} ${f.severity}`), file).toEqual(
        ['1', '2', '3', '4', '5', '6', '7'].map((l) => `${l} medium`),
      );
      for (const f of findings) {
        expect(f.message, f.title).toMatch(/Developers who copy this template/);
        expect(f.message, f.title).toMatch(/drop the (?:NEXT_PUBLIC_|VITE_) prefix/);
        expect(f.message, f.title).not.toMatch(/rotate it at the provider now|already reached the browsers/);
      }
      expect(findings[3]?.title).toBe('NEXT_PUBLIC_STRIPE_KEY: a name for a Stripe live secret key behind the browser prefix NEXT_PUBLIC_');
      expect(findings[4]?.title).toBe('NEXT_PUBLIC_DB_PASSWORD: a name that says secret behind the browser prefix NEXT_PUBLIC_');
    }
    // The same lines in the app's own env file are what their values are.
    expect(checkEnvFile('.env.local', lines).map((f) => `${f.line_start} ${f.severity}`)).toEqual([
      '1 medium',
      '2 medium',
      '3 critical',
      '4 critical',
      '5 critical',
      '6 critical',
      '7 high',
    ]);
  });

  // Fix round 3, item 3: a placeholder is no password, in the app's own file too.
  it('a placeholder is no value: REPLACE_WITH_…, {{…}}, ${VAR:-x}, enter_…, example, changeme, xxx… are a medium "check"', () => {
    const values = [
      'REPLACE_WITH_PASSWORD',
      'REPLACE_ME',
      '{{DB_PASSWORD}}',
      '{{ db_password }}',
      'enter_password',
      'Enter-Your-Password',
      '${DB_PASSWORD}',
      '${DB_PASSWORD:-postgres}',
      '$DB_PASSWORD',
      'example',
      'example-password',
      'changeme',
      'changeme123',
      'xxxxxxxx',
      'XXX-XXX',
      '<password>',
      'your-password',
      'your_db_password',
    ];
    const findings = checkEnvFile('.env.local', values.map((v, i) => `NEXT_PUBLIC_DB${i}_PASSWORD=${v}`).join('\n'));
    expect(findings.map((f) => `${f.line_start} ${f.severity}`)).toEqual(values.map((_, i) => `${i + 1} medium`));
    for (const f of findings) {
      expect(f.message).toMatch(/no real value here/);
      expect(f.message).not.toMatch(/rotate it at the provider now/);
    }
    // A real password that merely contains a word stays one.
    expect(checkEnvFile('.env.local', 'NEXT_PUBLIC_DB_PASSWORD=Center_Field42').map((f) => f.severity)).toEqual(['critical']);
  });

  // Fix round 1, item 2: a name that only PASSES THROUGH a secret word, and a
  // name-only match whose value is plainly not a secret.
  it('a name that only passes through a secret word is no finding; a secret name with a non-secret value is a medium "check"', () => {
    const harmless = [
      'NEXT_PUBLIC_PASSWORD_MIN_LENGTH=8',
      'NEXT_PUBLIC_PASSWORD_RESET_URL=https://app.example.com/reset',
      'VITE_AUTH_TOKEN_KEY=access_token',
      'PUBLIC_SECRET_SANTA_MODE=true',
      'NEXT_PUBLIC_SERVICE_ROLE_ENABLED=false',
      'VITE_DATABASE_URL_LABEL=Primary',
    ].join('\n');
    expect(checkEnvFile('.env.local', harmless)).toEqual([]);

    const nameOnly = checkEnvFile(
      '.env.local',
      ['VITE_ADMIN_KEY=dashboard', 'NEXT_PUBLIC_AUTH_TOKEN=access_token', 'NEXT_PUBLIC_RESEND_API_KEY=resend_key', 'NEXT_PUBLIC_SMTP_PASSWORD=true'].join('\n'),
    );
    expect(nameOnly.map((f) => `${f.line_start} ${f.severity}`)).toEqual(['1 medium', '2 medium', '3 medium', '4 medium']);
    for (const f of nameOnly) {
      expect(f.message).toMatch(/^.*Check what it holds/);
      expect(f.message).not.toMatch(/rotate it at the provider now/);
      expect(f.title).toContain('a name that says secret');
      expect(JSON.stringify(f).includes('dashboard')).toBe(false);
    }
  });

  // Fix round 2, item 3a: a password is whatever a person typed — no entropy test.
  it('a password variable with any real value is critical: hunter2hunter2, Admin@2024, 12345678, a passphrase', () => {
    const pw = ['hunter2', 'hunter2'].join('');
    const findings = checkEnvFile(
      '.env.local',
      [
        `NEXT_PUBLIC_ADMIN_PASSWORD=${pw}`,
        'VITE_DB_PASSWORD=Admin@2024',
        'REACT_APP_ROOT_PASSWD=12345678',
        'NEXT_PUBLIC_DB_PASSWORD=',
        // Fix round 3, item 2: PASSPHRASE is a secret name too.
        `NEXT_PUBLIC_WALLET_PASSPHRASE=${pw}`,
      ].join('\n'),
    );
    expect(findings.map((f) => `${f.line_start} ${f.severity}`)).toEqual(['1 critical', '2 critical', '3 critical', '4 medium', '5 critical']);
    expect(findings[0]?.message).toMatch(/rotate it at the provider now/);
    for (const f of findings) {
      for (const v of [pw, 'Admin@2024', '12345678']) expect(JSON.stringify(f).includes(v)).toBe(false);
    }
  });

  // Fix round 2, item 3b: the decoded role says what a JWT is.
  it('an anon JWT under a service-role name ships no secret: no finding; the real service-role JWT is critical', () => {
    expect(checkEnvFile('.env.local', `VITE_SUPABASE_SERVICE_ROLE=${ANON}`)).toEqual([]);
    const real = checkEnvFile('.env.local', `VITE_SUPABASE_SERVICE_ROLE=${SERVICE_ROLE}`);
    expect(real.map((f) => `${f.severity} ${f.title}`)).toEqual(['critical VITE_SUPABASE_SERVICE_ROLE: a Supabase service-role key behind the browser prefix VITE_']);
  });

  // Fix round 3, item 4: only the anon key — role anon, no subject — is public by design.
  it("a user's access token (a subject) or an authenticated JWT is critical under any name; only role anon with no subject is public", () => {
    expect(jwtClaims(USER_TOKEN)).toEqual({ role: 'authenticated', subject: true });
    expect(classifySecretValue(USER_TOKEN)).toEqual({ label: "a user's access token", live: true });
    expect(classifySecretValue(jwt('authenticated'))).toEqual({ label: 'a Supabase JWT for the role authenticated', live: true });
    const findings = checkEnvFile(
      '.env.local',
      [
        `NEXT_PUBLIC_SUPABASE_AUTH_TOKEN=${USER_TOKEN}`,
        `NEXT_PUBLIC_SUPABASE_ANON_KEY=${USER_TOKEN}`,
        `VITE_SUPABASE_ANON_KEY=${jwt('anon', { sub: 'c0ffee00-0000-4000-8000-000000000001' })}`,
        `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${jwt('authenticated')}`,
        `PUBLIC_SUPABASE_KEY=${jwt('authenticated')}`,
        `NEXT_PUBLIC_SUPABASE_URL=https://abcd.supabase.co`,
        `NEXT_PUBLIC_SUPABASE_KEY=${ANON}`,
      ].join('\n'),
    );
    expect(findings.map((f) => `${f.line_start} ${f.severity} ${f.title.split(': ')[1]}`)).toEqual([
      "1 critical a user's access token behind the browser prefix NEXT_PUBLIC_",
      "2 critical a user's access token behind the browser prefix NEXT_PUBLIC_",
      "3 critical a user's access token behind the browser prefix VITE_",
      '4 critical a Supabase JWT for the role authenticated behind the browser prefix NEXT_PUBLIC_',
      '5 critical a Supabase JWT for the role authenticated behind the browser prefix PUBLIC_',
    ]);
    expect(findings[0]?.message).toMatch(/acts as that user/);
    for (const f of findings) {
      for (const part of USER_TOKEN.split('.')) expect(JSON.stringify(f).includes(part), f.title).toBe(false);
    }
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
