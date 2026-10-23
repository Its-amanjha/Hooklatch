import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

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

  test('parseArgs rejects --secret-env for fal', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'fal', '--framework', 'express', '--secret-env', 'FOO']);

    expect(result.kind).toBe('error');

    if (result.kind !== 'error') throw new Error('Expected error');

    expect(result.message).toContain('not valid for fal');
  });

  test('parseArgs rejects --public-key-env for non-fal providers', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'stripe', '--framework', 'express', '--public-key-env', 'FOO']);

    expect(result.kind).toBe('error');

    if (result.kind !== 'error') throw new Error('Expected error');

    expect(result.message).toContain('only valid for fal');
  });

  test('parseArgs rejects duplicate --public-key-env', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'fal', '--framework', 'express', '--public-key-env', 'A', '--public-key-env', 'B']);

    expect(result.kind).toBe('error');

    if (result.kind !== 'error') throw new Error('Expected error');

    expect(result.message).toContain('Duplicate flag');
  });

  test('parseArgs rejects missing value for --public-key-env', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'fal', '--framework', 'express', '--public-key-env']);

    expect(result.kind).toBe('error');

    if (result.kind !== 'error') throw new Error('Expected error');

    expect(result.message).toContain('Missing value');
  });

  test('parseArgs accepts fal with defaults', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'fal', '--framework', 'express']);

    expect(result.kind).toBe('command');

    if (result.kind !== 'command') throw new Error('Expected command');

    expect(result.command.provider).toBe('fal');
    expect(result.command.publicKeyEnv).toBe('FAL_WEBHOOK_PUBLIC_KEYS');
    expect(result.command.expectedUserEnv).toBe('FAL_WEBHOOK_USER_ID');
  });

  test('parseArgs accepts fal with custom env names', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'fal', '--framework', 'express', '--public-key-env', 'MY_KEYS', '--expected-user-env', 'MY_USER']);

    expect(result.kind).toBe('command');

    if (result.kind !== 'command') throw new Error('Expected command');

    expect(result.command.publicKeyEnv).toBe('MY_KEYS');
    expect(result.command.expectedUserEnv).toBe('MY_USER');
  });

  test('parseArgs rejects invalid --public-key-env identifier', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'fal', '--framework', 'express', '--public-key-env', '123bad']);

    expect(result.kind).toBe('error');
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
    expect(out).toContain('1 to 16');
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
});

describe('phase9 CLI integration', () => {
  test('CLI generates fal express template', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hooklatch-phase9-'));
    const result = runCli(root, ['init', 'webhook', '--provider', 'fal', '--framework', 'express', '--out', 'out']);

    expect(result.status).toBe(0);

    const generated = fs.readFileSync(path.join(root, 'out', 'fal.express.ts'), 'utf8');

    expect(generated).toContain('decodePublicKeys');
    expect(generated).toContain('publicKeys: decodePublicKeys(process.env.FAL_WEBHOOK_PUBLIC_KEYS!)');
    expect(generated).toContain('expectedUserId: process.env.FAL_WEBHOOK_USER_ID!');
    expect(generated).not.toContain('FAL_WEBHOOK_SECRET');

    fs.rmSync(root, { recursive: true, force: true });
  });

  test('CLI rejects --secret-env for fal', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hooklatch-phase9-'));
    const result = runCli(root, ['init', 'webhook', '--provider', 'fal', '--framework', 'express', '--secret-env', 'FOO']);

    expect(result.status).toBe(2);
    expect(result.stderr).toContain('not valid for fal');

    fs.rmSync(root, { recursive: true, force: true });
  });
});
