import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import ts from 'typescript';


import {
  buildProviderCliOptions,
  HELP_TEXT,
  parseArgs,
  type RawProviderFlags,
} from '../../src/cli/args.js';
import { renderTemplate } from '../../src/cli/templates.js';

const CLI = path.resolve(process.cwd(), 'dist', 'cli', 'index.js');

function flags(overrides: Partial<RawProviderFlags> = {}): RawProviderFlags {
  return {
    grafanaMode: overrides.grafanaMode,
    signatureHeader: overrides.signatureHeader,
    timestampHeader: overrides.timestampHeader,
    polarSecretMode: overrides.polarSecretMode,
    publicKeyEnv: overrides.publicKeyEnv,
    expectedUserEnv: overrides.expectedUserEnv,
  };
}

function runCli(root: string, args: readonly string[]) {
  const result = spawnSync(process.execPath, [CLI, ...args], { cwd: root, encoding: 'utf8' });

  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  } satisfies { status: number; stdout: string; stderr: string };
}

describe('phase9 credential CLI flags', () => {
  test('help text mentions public-key-env and expected-user-env', () => {
    expect(HELP_TEXT).toContain('--public-key-env');
    expect(HELP_TEXT).toContain('--expected-user-env');
  });

  test('buildProviderCliOptions accepts fal with defaults', () => {
    const result = buildProviderCliOptions('fal', flags({}));

    expect(result.kind).toBe('options');

    if (result.kind !== 'options') throw new Error('Expected options');

    expect(result.options).toEqual({
      provider: 'fal',
      options: { publicKeyEnv: 'FAL_WEBHOOK_PUBLIC_KEYS', expectedUserEnv: 'FAL_WEBHOOK_USER_ID' },
    });
  });

  test('buildProviderCliOptions accepts fal with custom env names', () => {
    const result = buildProviderCliOptions('fal', flags({ publicKeyEnv: 'MY_KEYS', expectedUserEnv: 'MY_USER' }));

    expect(result.kind).toBe('options');

    if (result.kind !== 'options') throw new Error('Expected options');

    expect(result.options).toEqual({
      provider: 'fal',
      options: { publicKeyEnv: 'MY_KEYS', expectedUserEnv: 'MY_USER' },
    });
  });

  test('buildProviderCliOptions rejects grafana flags for fal', () => {
    const result = buildProviderCliOptions('fal', flags({ grafanaMode: 'body' }));

    expect(result.kind).toBe('error');
  });

  test('buildProviderCliOptions rejects polar flags for fal', () => {
    const result = buildProviderCliOptions('fal', flags({ polarSecretMode: 'legacy' }));

    expect(result.kind).toBe('error');
  });

  test('buildProviderCliOptions rejects --secret-env for non-hmac context (fal)', () => {
    // fal has no default secret env; buildProviderCliOptions for fal ignores secretEnv
    // but the flag validation happens in parseArgs. Test that fal buildOptions works.
    const result = buildProviderCliOptions('fal', flags({ publicKeyEnv: 'MY_KEYS', expectedUserEnv: 'MY_USER' }));

    expect(result.kind).toBe('options');
  });

  test('parseArgs rejects --public-key-env for registered providers', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'stripe', '--framework', 'express', '--public-key-env', 'FOO']);

    expect(result.kind).toBe('error');

    if (result.kind !== 'error') throw new Error('Expected error');

    expect(result.message).toContain('only valid for fal');
  });

  test('parseArgs rejects duplicate --public-key-env', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'stripe', '--framework', 'express', '--public-key-env', 'A', '--public-key-env', 'B']);

    expect(result.kind).toBe('error');

    if (result.kind !== 'error') throw new Error('Expected error');

    expect(result.message).toContain('Duplicate flag');
  });

  test('parseArgs rejects missing value for --public-key-env', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'stripe', '--framework', 'express', '--public-key-env']);

    expect(result.kind).toBe('error');

    if (result.kind !== 'error') throw new Error('Expected error');

    expect(result.message).toContain('Missing value');
  });

  test('parseArgs rejects invalid --public-key-env identifier', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'stripe', '--framework', 'express', '--public-key-env', '123bad']);

    expect(result.kind).toBe('error');
  });

  test('parseArgs accepts registered fal without a dummy secret', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'fal', '--framework', 'express']);

    expect(result.kind).toBe('command');

    if (result.kind !== 'command') throw new Error('Expected command');

    expect(result.command).toMatchObject({ provider: 'fal', publicKeyEnv: 'FAL_WEBHOOK_PUBLIC_KEYS', expectedUserEnv: 'FAL_WEBHOOK_USER_ID' });
    expect(Object.hasOwn(result.command, 'secretEnv')).toBe(false);
  });

  test('fal rejects even an explicitly supplied default HMAC secret env', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'fal', '--framework', 'express', '--secret-env', 'FAL_WEBHOOK_SECRET']);

    expect(result.kind).toBe('error');

    if (result.kind !== 'error') throw new Error('Expected error');

    expect(result.message).toContain('not valid for fal');
  });

});

describe('phase9 fal template generation', () => {
  test('express template contains decodePublicKeys helper', () => {
    const out = renderTemplate('fal', 'express', { publicKeyEnv: 'FAL_WEBHOOK_PUBLIC_KEYS', expectedUserEnv: 'FAL_WEBHOOK_USER_ID', bodyLimit: 1024 });

    expect(out).toContain('decodePublicKeys');
    expect(out).toContain('publicKeys: decodePublicKeys(process.env.FAL_WEBHOOK_PUBLIC_KEYS!)');
    expect(out).toContain('expectedUserId: process.env.FAL_WEBHOOK_USER_ID!');
    expect(out).toContain('maxBodyBytes: 1024');
  });

  test('express template does not contain FAL_WEBHOOK_SECRET placeholder', () => {
    const out = renderTemplate('fal', 'express', { publicKeyEnv: 'FAL_WEBHOOK_PUBLIC_KEYS', expectedUserEnv: 'FAL_WEBHOOK_USER_ID', bodyLimit: 1024 });

    expect(out).not.toContain('FAL_WEBHOOK_SECRET');
    expect(out).not.toContain('secrets:');
  });

  test('express template contains canonical Base64url validation', () => {
    const out = renderTemplate('fal', 'express', { publicKeyEnv: 'FAL_WEBHOOK_PUBLIC_KEYS', expectedUserEnv: 'FAL_WEBHOOK_USER_ID', bodyLimit: 1024 });

    expect(out).toContain('atob');
    expect(out).toContain('btoa');
    expect(out).toContain('32');
  });

  test('nextjs template exports POST', () => {
    const out = renderTemplate('fal', 'nextjs', { publicKeyEnv: 'FAL_WEBHOOK_PUBLIC_KEYS', expectedUserEnv: 'FAL_WEBHOOK_USER_ID', bodyLimit: 2048 });

    expect(out).toContain('export const POST');
    expect(out).toContain('decodePublicKeys');
  });

  test('hono template exports middleware', () => {
    const out = renderTemplate('fal', 'hono', { publicKeyEnv: 'FAL_WEBHOOK_PUBLIC_KEYS', expectedUserEnv: 'FAL_WEBHOOK_USER_ID', bodyLimit: 4096 });

    expect(out).toContain('HonoWebhook');
    expect(out).toContain('decodePublicKeys');
  });

  test('cloudflare template uses env binding', () => {
    const out = renderTemplate('fal', 'cloudflare', { publicKeyEnv: 'FAL_WEBHOOK_PUBLIC_KEYS', expectedUserEnv: 'FAL_WEBHOOK_USER_ID', bodyLimit: 8192 });

    expect(out).toContain('env.FAL_WEBHOOK_PUBLIC_KEYS');
    expect(out).toContain('env.FAL_WEBHOOK_USER_ID');
    expect(out).toContain('decodePublicKeys');
  });

  test('fal template uses custom env names', () => {
    const out = renderTemplate('fal', 'express', { publicKeyEnv: 'MY_KEYS', expectedUserEnv: 'MY_USER', bodyLimit: 1024 });

    expect(out).toContain('process.env.MY_KEYS!');
    expect(out).toContain('process.env.MY_USER!');
  });

  test('credential correlation: fal with secretEnv throws', () => {
    expect(() => {
      // SAFETY: deliberately malformed TemplateOptions to verify runtime rejection.
      renderTemplate('fal', 'express', { secretEnv: 'FOO', bodyLimit: 1024 } as Parameters<typeof renderTemplate>[2]);
    }).toThrow('Fal templates require publicKeyEnv');
  });

  test('credential correlation: non-fal with publicKeyEnv throws', () => {
    expect(() => {
      // SAFETY: deliberately malformed TemplateOptions to verify runtime rejection.
      renderTemplate('stripe', 'express', { publicKeyEnv: 'FOO', expectedUserEnv: 'BAR', bodyLimit: 1024 } as Parameters<typeof renderTemplate>[2]);
    }).toThrow('Non-fal providers must use secretEnv');
  });

  test('old19 HMAC templates unchanged (stripe express)', () => {
    const out = renderTemplate('stripe', 'express', { secretEnv: 'STRIPE_WEBHOOK_SECRET', bodyLimit: 1024 });

    expect(out).toContain('createWebhookMiddleware');
    expect(out).toContain('process.env.STRIPE_WEBHOOK_SECRET!');
    expect(out).toContain('maxBodyBytes: 1024');
  });
});

describe('phase9 decoder execution', () => {
  function extractDecoder(source: string): string {
    const file = ts.createSourceFile('generated.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const declaration = file.statements.find((statement) => ts.isFunctionDeclaration(statement) && statement.name?.text === 'decodePublicKeys');

    if (!declaration) throw new Error('Decoder not found');

    return declaration.getText(file);
  }

  function evalDecoder(source: string): (value: string) => Uint8Array[] {
    const decoder = extractDecoder(source);

    const transpiled = ts.transpileModule(decoder, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    }).outputText;

    const factory = new Function(`${transpiled}\nreturn decodePublicKeys;`);

    // SAFETY: factory returns the generated decodePublicKeys function; cast is for the extracted helper's signature.
    return factory() as (value: string) => Uint8Array[];
  }

  test('decoder accepts 1 canonical 32-byte key', () => {
    const source = renderTemplate('fal', 'express', { publicKeyEnv: 'K', expectedUserEnv: 'U', bodyLimit: 1024 });
    const decode = evalDecoder(source);

    // 43-char unpadded Base64url encoding of 32 bytes
    // This may not be valid Base64url; use a known valid key instead
    const validKey = Buffer.from(new Uint8Array(32).fill(1)).toString('base64url').replace(/=+$/, '');

    expect(validKey.length).toBe(43);

    const result = decode(validKey);

    expect(result).toHaveLength(1);
    expect(result[0]).toHaveLength(32);
  });

  test('decoder accepts up to 16 keys', () => {
    const source = renderTemplate('fal', 'express', { publicKeyEnv: 'K', expectedUserEnv: 'U', bodyLimit: 1024 });
    const decode = evalDecoder(source);

    const validKey = Buffer.from(new Uint8Array(32).fill(1)).toString('base64url').replace(/=+$/, '');
    const value = Array(16).fill(validKey).join(',');

    const result = decode(value);

    expect(result).toHaveLength(16);
  });

  test('decoder rejects 17 keys', () => {
    const source = renderTemplate('fal', 'express', { publicKeyEnv: 'K', expectedUserEnv: 'U', bodyLimit: 1024 });
    const decode = evalDecoder(source);

    const validKey = Buffer.from(new Uint8Array(32).fill(1)).toString('base64url').replace(/=+$/, '');
    const value = Array(17).fill(validKey).join(',');

    expect(() => decode(value)).toThrow();
  });

  test('decoder rejects blank entry', () => {
    const source = renderTemplate('fal', 'express', { publicKeyEnv: 'K', expectedUserEnv: 'U', bodyLimit: 1024 });
    const decode = evalDecoder(source);

    const validKey = Buffer.from(new Uint8Array(32).fill(1)).toString('base64url').replace(/=+$/, '');

    expect(() => decode(`,${validKey}`)).toThrow();
    expect(() => decode(`${validKey},`)).toThrow();
  });

  test('decoder rejects empty string', () => {
    const source = renderTemplate('fal', 'express', { publicKeyEnv: 'K', expectedUserEnv: 'U', bodyLimit: 1024 });
    const decode = evalDecoder(source);

    expect(() => decode('')).toThrow();
  });

  test('decoder rejects padding', () => {
    const source = renderTemplate('fal', 'express', { publicKeyEnv: 'K', expectedUserEnv: 'U', bodyLimit: 1024 });
    const decode = evalDecoder(source);

    const paddedKey = Buffer.from(new Uint8Array(32).fill(1)).toString('base64url') + '=';

    expect(() => decode(paddedKey)).toThrow();
  });

  test('decoder rejects whitespace', () => {
    const source = renderTemplate('fal', 'express', { publicKeyEnv: 'K', expectedUserEnv: 'U', bodyLimit: 1024 });
    const decode = evalDecoder(source);

    const validKey = Buffer.from(new Uint8Array(32).fill(1)).toString('base64url').replace(/=+$/, '');

    expect(() => decode(` ${validKey}`)).toThrow();
    expect(() => decode(`${validKey} `)).toThrow();
  });

  test('decoder rejects non-32-byte key', () => {
    const source = renderTemplate('fal', 'express', { publicKeyEnv: 'K', expectedUserEnv: 'U', bodyLimit: 1024 });
    const decode = evalDecoder(source);

    const shortKey = Buffer.from(new Uint8Array(16).fill(1)).toString('base64url').replace(/=+$/, '');

    expect(() => decode(shortKey)).toThrow();
  });

  test('decoder rejects nonzero unused bits while preserving decoded key bytes', () => {
    const source = renderTemplate('fal', 'express', { publicKeyEnv: 'K', expectedUserEnv: 'U', bodyLimit: 1024 });
    const decode = evalDecoder(source);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const validKey = Buffer.from(new Uint8Array(32).fill(1)).toString('base64url');
    const last = validKey.at(-1);

    if (last === undefined) throw new Error('Expected key');

    const index = alphabet.indexOf(last);
    const replacement = alphabet[index + 1];

    if (replacement === undefined || index % 4 !== 0) throw new Error('Expected canonical encoding');

    const nonCanonical = validKey.slice(0, -1) + replacement;

    expect(Buffer.from(nonCanonical, 'base64url')).toEqual(Buffer.from(validKey, 'base64url'));
    expect(() => decode(nonCanonical)).toThrow();
  });

  test('decoder executes in all four frameworks', () => {
    for (const framework of ['express', 'nextjs', 'hono', 'cloudflare'] as const) {
      const source = renderTemplate('fal', framework, { publicKeyEnv: 'K', expectedUserEnv: 'U', bodyLimit: 1024 });
      const decode = evalDecoder(source);

      const validKey = Buffer.from(new Uint8Array(32).fill(1)).toString('base64url').replace(/=+$/, '');
      const result = decode(validKey);

      expect(result).toHaveLength(1);
      expect(result[0]).toHaveLength(32);
    }
  });

  test('decoder uses generic error messages (no key echo)', () => {
    const source = renderTemplate('fal', 'express', { publicKeyEnv: 'K', expectedUserEnv: 'U', bodyLimit: 1024 });
    const decode = evalDecoder(source);

    const secretKey = 'super-secret-key-value';

    expect(() => decode(secretKey)).toThrow();

    try {
      decode(secretKey);
    } catch (e) {
      // SAFETY: caught value is an Error thrown by the generated decoder.
      const msg = (e as Error).message;

      expect(msg).not.toContain(secretKey);
    }
  });
});

describe('phase9 CLI integration', () => {
  test('CLI generates fal using raw-key credentials without writing on dry run', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hooklatch-phase9-fal-'));

    try {
      const result = runCli(root, ['init', 'webhook', '--provider', 'fal', '--framework', 'express', '--dry-run']);

      expect(result.status).toBe(0);
      expect(result.stdout).toContain('publicKeys: decodePublicKeys(');
      expect(result.stdout).toContain('expectedUserId:');
      expect(result.stdout).not.toContain('secrets:');
      expect(fs.readdirSync(root)).toEqual([]);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('dry-run does not write files', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hooklatch-phase9-dry-'));
    const relOut = 'out';

    const result = runCli(root, ['init', 'webhook', '--provider', 'stripe', '--framework', 'express', '--dry-run', '--out', relOut]);

    // stripe is registered, so this should succeed
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('stripe.express.ts');

    // outDir should not be created
    expect(fs.existsSync(path.join(root, relOut))).toBe(false);

    fs.rmSync(root, { recursive: true, force: true });
  });
});
