import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import ts from 'typescript';

import {
  buildProviderCliOptions,
  HELP_TEXT,
  parseArgs,
  type Framework,
  type ProviderCliOptions,
  type ProviderCliOptionsResult,
  type RawProviderFlags,
} from '../../src/cli/args.js';
import { renderTemplate } from '../../src/cli/templates.js';

const CLI = path.resolve(process.cwd(), 'dist', 'cli', 'index.js');

const EXISTING_PROVIDERS = [
  'stripe',
  'github',
  'shopify',
  'standard-webhooks',
  'clerk',
  'svix',
  'razorpay',
  'paddle',
  'lemon-squeezy',
  'dodo-payments',
  'gitlab',
  'replicate',
  'workos',
  'sentry',
  'doppler',
  'sanity',
] as const;

const FRAMEWORKS = ['express', 'nextjs', 'hono', 'cloudflare'] as const;

const TARGET_NAMES: Readonly<Record<Framework, string>> = {
  express: 'grafana.express.ts',
  nextjs: 'route.ts',
  hono: 'grafana.hono.ts',
  cloudflare: 'grafana.cloudflare.ts',
};

const ADAPTER_MODULES: Readonly<Record<Framework, string>> = {
  express: "hooklatch/express",
  nextjs: "hooklatch/nextjs",
  hono: "hooklatch/hono",
  cloudflare: "hooklatch/cloudflare",
};

const RESERVED_HEADERS = [
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'upgrade',
  'trailer',
  'te',
  'proxy-authorization',
  'proxy-authenticate',
  'authorization',
  'cookie',
  'set-cookie',
] as const;

const INVALID_HEADERS = ['', 'bad name', 'bad:name', 'bad/name', 'bad"name', 'bad\\name', 'bad\nname'] as const;

/** Apostrophe and backtick are valid RFC 9110 token characters. */
const HOSTILE_HEADER = "x-weird'\u0060+inj";
const HOSTILE_LITERAL = `"x-weird'\u0060+inj"`;

const BASE_TEMPLATE_OPTIONS = { secretEnv: 'WEBHOOK_SECRET', bodyLimit: 4096 } as const;

interface FlagOverrides {
  readonly grafanaMode?: string;
  readonly signatureHeader?: string;
  readonly timestampHeader?: string;
  readonly polarSecretMode?: string;
}

function flags(overrides: FlagOverrides = {}): RawProviderFlags {
  return {
    grafanaMode: overrides.grafanaMode,
    signatureHeader: overrides.signatureHeader,
    timestampHeader: overrides.timestampHeader,
    polarSecretMode: overrides.polarSecretMode,
  };
}

function expectOptions(result: ProviderCliOptionsResult): ProviderCliOptions {
  expect(result.kind).toBe('options');

  if (result.kind !== 'options') throw new Error('Expected provider options.');

  return result.options;
}

function expectError(result: ProviderCliOptionsResult): string {
  expect(result.kind).toBe('error');

  if (result.kind !== 'error') throw new Error('Expected a provider options error.');

  return result.message;
}

function syntaxDiagnostics(source: string): readonly ts.Diagnostic[] {
  return ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    fileName: 'generated.ts',
    reportDiagnostics: true,
  }).diagnostics ?? [];
}

interface CliResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

function runCli(root: string, args: readonly string[]): CliResult {
  const result = spawnSync(process.execPath, [CLI, ...args], { cwd: root, encoding: 'utf8' });

  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

function collectFiles(directory: string): readonly string[] {
  if (!fs.existsSync(directory)) return [];

  const files: string[] = [];

  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      for (const nested of collectFiles(full)) files.push(nested);
    } else files.push(full);
  }

  return files;
}

const tempRoots: string[] = [];

function makeTempRoot(label: string): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `hooklatch-phase7b-${label}-`));
  tempRoots.push(root);

  return root;
}

afterEach(() => {
  for (const root of tempRoots) fs.rmSync(root, { recursive: true, force: true });

  tempRoots.length = 0;
});

describe('provider option rules', () => {
  test('Grafana body mode needs no header overrides', () => {
    expect(expectOptions(buildProviderCliOptions('grafana', flags({ grafanaMode: 'body' })))).toEqual({
      provider: 'grafana',
      options: { mode: 'body' },
    });
  });

  test('Grafana timestamped mode preserves exact header names', () => {
    const options = expectOptions(buildProviderCliOptions('grafana', flags({
      grafanaMode: 'timestamped',
      signatureHeader: HOSTILE_HEADER,
      timestampHeader: 'X-Timestamp',
    })));

    expect(options).toEqual({
      provider: 'grafana',
      options: { mode: 'timestamped', signatureHeader: HOSTILE_HEADER, timestampHeader: 'X-Timestamp' },
    });
  });

  test('Polar defaults to current', () => {
    expect(expectOptions(buildProviderCliOptions('polar', flags()))).toEqual({
      provider: 'polar',
      options: { secretMode: 'current' },
    });
  });

  test('Polar forwards legacy explicitly', () => {
    expect(expectOptions(buildProviderCliOptions('polar', flags({ polarSecretMode: 'legacy' })))).toEqual({
      provider: 'polar',
      options: { secretMode: 'legacy' },
    });
  });

  test('Grafana requires an explicit mode and never infers one from a timestamp header', () => {
    expect(expectError(buildProviderCliOptions('grafana', flags()))).toBe('Missing required --grafana-mode for grafana.');
    expect(expectError(buildProviderCliOptions('grafana', flags({ timestampHeader: 'x-ts' })))).toBe(
      'Missing required --grafana-mode for grafana.',
    );
  });

  test('Grafana rejects unsupported modes', () => {
    expect(expectError(buildProviderCliOptions('grafana', flags({ grafanaMode: 'timestamp' })))).toBe(
      'Invalid --grafana-mode: expected body or timestamped.',
    );
  });

  test('Grafana timestamped mode requires its timestamp header', () => {
    expect(expectError(buildProviderCliOptions('grafana', flags({ grafanaMode: 'timestamped' })))).toBe(
      'Missing required --timestamp-header for Grafana timestamped mode.',
    );
  });

  test('Grafana body mode forbids a timestamp header', () => {
    expect(expectError(buildProviderCliOptions('grafana', flags({ grafanaMode: 'body', timestampHeader: 'x-ts' })))).toBe(
      'The --timestamp-header flag is not allowed in Grafana body mode.',
    );
  });

  test('Grafana rejects Polar-only configuration', () => {
    expect(expectError(buildProviderCliOptions('grafana', flags({ grafanaMode: 'body', polarSecretMode: 'legacy' })))).toBe(
      'The --polar-secret-mode flag is only valid for polar.',
    );
  });

  test('Polar rejects Grafana-only configuration', () => {
    expect(expectError(buildProviderCliOptions('polar', flags({ grafanaMode: 'body' })))).toBe(
      'The --grafana-mode flag is only valid for grafana.',
    );
    expect(expectError(buildProviderCliOptions('polar', flags({ signatureHeader: 'x-sig' })))).toBe(
      'The --signature-header flag is only valid for grafana.',
    );
    expect(expectError(buildProviderCliOptions('polar', flags({ timestampHeader: 'x-ts' })))).toBe(
      'The --timestamp-header flag is only valid for grafana.',
    );
  });

  test('existing providers reject new-provider configuration', () => {
    expect(expectError(buildProviderCliOptions('stripe', flags({ grafanaMode: 'body' })))).toBe(
      'The --grafana-mode flag is only valid for grafana.',
    );
    expect(expectError(buildProviderCliOptions('stripe', flags({ signatureHeader: 'x-sig' })))).toBe(
      'The --signature-header flag is only valid for grafana.',
    );
    expect(expectError(buildProviderCliOptions('stripe', flags({ timestampHeader: 'x-ts' })))).toBe(
      'The --timestamp-header flag is only valid for grafana.',
    );
    expect(expectError(buildProviderCliOptions('stripe', flags({ polarSecretMode: 'legacy' })))).toBe(
      'The --polar-secret-mode flag is only valid for polar.',
    );
  });

  test('existing providers without new flags keep no provider options', () => {
    expect(buildProviderCliOptions('stripe', flags())).toEqual({ kind: 'none' });
  });

  test.each(RESERVED_HEADERS)('rejects reserved signature header %s', (name) => {
    const message = expectError(buildProviderCliOptions('grafana', flags({ grafanaMode: 'body', signatureHeader: name })));

    expect(message).toBe('Invalid --signature-header: expected an RFC 9110 field-name token that is not reserved.');
  });

  test.each(RESERVED_HEADERS)('rejects reserved timestamp header %s', (name) => {
    const message = expectError(buildProviderCliOptions('grafana', flags({
      grafanaMode: 'timestamped',
      signatureHeader: 'x-sig',
      timestampHeader: name,
    })));

    expect(message).toBe('Invalid --timestamp-header: expected an RFC 9110 field-name token that is not reserved.');
  });

  test('reserved header checks are case-insensitive', () => {
    expect(expectError(buildProviderCliOptions('grafana', flags({ grafanaMode: 'body', signatureHeader: 'Authorization' })))).toBe(
      'Invalid --signature-header: expected an RFC 9110 field-name token that is not reserved.',
    );
    expect(expectError(buildProviderCliOptions('grafana', flags({
      grafanaMode: 'timestamped',
      signatureHeader: 'x-sig',
      timestampHeader: 'Set-Cookie',
    })))).toBe('Invalid --timestamp-header: expected an RFC 9110 field-name token that is not reserved.');
  });

  test.each(INVALID_HEADERS)('rejects invalid signature header token %p', (header) => {
    const message = expectError(buildProviderCliOptions('grafana', flags({ grafanaMode: 'body', signatureHeader: header })));

    expect(message).toBe('Invalid --signature-header: expected an RFC 9110 field-name token that is not reserved.');
  });

  test.each(INVALID_HEADERS)('rejects invalid timestamp header token %p', (header) => {
    const message = expectError(buildProviderCliOptions('grafana', flags({
      grafanaMode: 'timestamped',
      signatureHeader: 'x-sig',
      timestampHeader: header,
    })));

    expect(message).toBe('Invalid --timestamp-header: expected an RFC 9110 field-name token that is not reserved.');
  });

  test('Grafana header fields must differ case-insensitively', () => {
    expect(expectError(buildProviderCliOptions('grafana', flags({
      grafanaMode: 'timestamped',
      signatureHeader: 'X-Sig',
      timestampHeader: 'x-sig',
    })))).toBe('The Grafana signature and timestamp headers must differ (case-insensitive).');

    expect(expectError(buildProviderCliOptions('grafana', flags({
      grafanaMode: 'timestamped',
      timestampHeader: 'X-Grafana-Alerting-Signature',
    })))).toBe('The Grafana signature and timestamp headers must differ (case-insensitive).');

    expect(expectOptions(buildProviderCliOptions('grafana', flags({
      grafanaMode: 'timestamped',
      signatureHeader: 'X-Sig',
      timestampHeader: 'x-ts',
    })))).toEqual({
      provider: 'grafana',
      options: { mode: 'timestamped', signatureHeader: 'X-Sig', timestampHeader: 'x-ts' },
    });
  });

  test('Polar rejects unsupported secret modes', () => {
    expect(expectError(buildProviderCliOptions('polar', flags({ polarSecretMode: 'previous' })))).toBe(
      'Invalid --polar-secret-mode: expected current or legacy.',
    );
  });
});

describe('argument scanning for provider flags', () => {
  test.each(['--grafana-mode', '--signature-header', '--timestamp-header', '--polar-secret-mode'])(
    'rejects duplicate %s',
    (flag) => {
      const result = parseArgs(['init', 'webhook', '--provider', 'grafana', '--framework', 'express', flag, 'a', flag, 'b']);

      expect(result.kind).toBe('error');

      if (result.kind === 'error') expect(result.message).toBe(`Duplicate flag: ${flag}.`);
    },
  );

  test.each(['--grafana-mode', '--signature-header', '--timestamp-header', '--polar-secret-mode'])(
    'rejects missing value for %s',
    (flag) => {
      const result = parseArgs(['init', 'webhook', '--provider', 'grafana', '--framework', 'express', flag]);

      expect(result.kind).toBe('error');

      if (result.kind === 'error') expect(result.message).toBe(`Missing value for ${flag}.`);
    },
  );

  test('rejects unknown secret-value flags', () => {
    for (const flag of ['--secret', '--token']) {
      const result = parseArgs(['init', 'webhook', '--provider', 'stripe', '--framework', 'express', flag, 'synthetic']);

      expect(result.kind).toBe('error');

      if (result.kind === 'error') expect(result.message).toBe('Unknown flag.');
    }
  });

  test('existing provider command shape is unchanged', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'stripe', '--framework', 'express']);

    expect(result).toEqual({
      kind: 'command',
      command: {
        provider: 'stripe',
        framework: 'express',
        out: 'hooklatch',
        secretEnv: 'STRIPE_WEBHOOK_SECRET',
        bodyLimit: 1048576,
        dryRun: false,
      },
    });
  });

  test('Grafana parses after registry registration or reports the honest base block', () => {
    const result = parseArgs([
      'init',
      'webhook',
      '--provider',
      'grafana',
      '--framework',
      'express',
      '--grafana-mode',
      'timestamped',
      '--signature-header',
      HOSTILE_HEADER,
      '--timestamp-header',
      'x-ts',
    ]);

    if (result.kind === 'error') {
      expect(result.message).toBe('Unsupported provider.');

      return;
    }

    expect(result.kind).toBe('command');

    if (result.kind === 'command') {
      expect(result.command.providerOptions).toEqual({
        provider: 'grafana',
        options: { mode: 'timestamped', signatureHeader: HOSTILE_HEADER, timestampHeader: 'x-ts' },
      });
    }
  });

  test('Polar parses after registry registration or reports the honest base block', () => {
    const result = parseArgs(['init', 'webhook', '--provider', 'polar', '--framework', 'express']);

    if (result.kind === 'error') {
      expect(result.message).toBe('Unsupported provider.');

      return;
    }

    expect(result.kind).toBe('command');

    if (result.kind === 'command') {
      expect(result.command.providerOptions).toEqual({ provider: 'polar', options: { secretMode: 'current' } });
    }
  });
});

describe('generated templates', () => {
  test.each(FRAMEWORKS)('Grafana body layout is explicit and valid TypeScript for %s', (framework) => {
    const output = renderTemplate('grafana', framework, {
      ...BASE_TEMPLATE_OPTIONS,
      providerOptions: { provider: 'grafana', options: { mode: 'body' } },
    });

    expect(output).toContain('providerOptions: { mode: "body" },');
    expect(output).toContain(ADAPTER_MODULES[framework]);
    expect(syntaxDiagnostics(output)).toEqual([]);
  });

  test.each(FRAMEWORKS)('Grafana timestamped layout preserves hostile-but-valid header tokens for %s', (framework) => {
    const providerOptions: ProviderCliOptions = {
      provider: 'grafana',
      options: { mode: 'timestamped', signatureHeader: HOSTILE_HEADER, timestampHeader: 'x-ts' },
    };

    const output = renderTemplate('grafana', framework, { ...BASE_TEMPLATE_OPTIONS, providerOptions });
    const expected = `providerOptions: { mode: "timestamped", signatureHeader: ${HOSTILE_LITERAL}, timestampHeader: "x-ts" },`;

    expect(output).toContain(expected);
    expect(output).not.toContain("providerOptions: { mode: 'body' }");
    expect(syntaxDiagnostics(output)).toEqual([]);
  });

  test.each(['current', 'legacy'] as const)('Polar forwards %s explicitly for every framework', (secretMode) => {
    const providerOptions: ProviderCliOptions = { provider: 'polar', options: { secretMode } };

    for (const framework of FRAMEWORKS) {
      const output = renderTemplate('polar', framework, { ...BASE_TEMPLATE_OPTIONS, providerOptions });

      expect(output).toContain(`providerOptions: { secretMode: "${secretMode}" },`);
      expect(syntaxDiagnostics(output)).toEqual([]);
    }
  });

  test.each(EXISTING_PROVIDERS)('existing provider %s templates stay free of providerOptions', (provider) => {
    for (const framework of FRAMEWORKS) {
      const output = renderTemplate(provider, framework, BASE_TEMPLATE_OPTIONS);

      expect(output).not.toContain('providerOptions');
      expect(syntaxDiagnostics(output)).toEqual([]);
    }
  });

  test('help documents every new configuration flag', () => {
    for (const flag of ['--grafana-mode', '--signature-header', '--timestamp-header', '--polar-secret-mode']) {
      expect(HELP_TEXT).toContain(flag);
    }
  });
});

describe('real CLI child process', () => {
  test('help exits zero and documents new flags', () => {
    const result = runCli(makeTempRoot('help'), ['--help']);

    expect(result.status).toBe(0);

    for (const flag of ['--grafana-mode', '--signature-header', '--timestamp-header', '--polar-secret-mode']) {
      expect(result.stdout).toContain(flag);
    }
  });

  test.each(EXISTING_PROVIDERS)('existing provider %s still generates through the built CLI', (provider) => {
    const root = makeTempRoot(`existing-${provider}`);
    const result = runCli(root, ['init', 'webhook', '--provider', provider, '--framework', 'express']);
    const target = path.join(root, 'hooklatch', `${provider}.express.ts`);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    expect(fs.existsSync(target)).toBe(true);

    const content = fs.readFileSync(target, 'utf8');

    expect(content).toContain(`provider: '${provider}'`);
    expect(content).not.toContain('providerOptions');
    expect(syntaxDiagnostics(content)).toEqual([]);
  });

  test.each(FRAMEWORKS)('Grafana body template reaches the %s target or honestly blocks at the base registry', (framework) => {
    const root = makeTempRoot(`grafana-body-${framework}`);

    const result = runCli(root, [
      'init',
      'webhook',
      '--provider',
      'grafana',
      '--framework',
      framework,
      '--grafana-mode',
      'body',
    ]);

    if (result.status === 2) {
      expect(result.stderr).toBe('Unsupported provider.\n');
      expect(collectFiles(path.join(root, 'hooklatch'))).toEqual([]);

      return;
    }

    expect(result.status).toBe(0);

    const target = path.join(root, 'hooklatch', TARGET_NAMES[framework]);
    const content = fs.readFileSync(target, 'utf8');

    expect(content).toContain('providerOptions: { mode: "body" },');
    expect(content).toContain('process.env.GRAFANA_WEBHOOK_SECRET');
    expect(syntaxDiagnostics(content)).toEqual([]);
  });

  test('Grafana timestamped generation preserves header names or honestly blocks at the base registry', () => {
    const root = makeTempRoot('grafana-timestamped');

    const result = runCli(root, [
      'init',
      'webhook',
      '--provider',
      'grafana',
      '--framework',
      'express',
      '--grafana-mode',
      'timestamped',
      '--signature-header',
      HOSTILE_HEADER,
      '--timestamp-header',
      'x-ts',
    ]);

    if (result.status === 2) {
      expect(result.stderr).toBe('Unsupported provider.\n');
      expect(collectFiles(path.join(root, 'hooklatch'))).toEqual([]);

      return;
    }

    expect(result.status).toBe(0);

    const content = fs.readFileSync(path.join(root, 'hooklatch', 'grafana.express.ts'), 'utf8');

    expect(content).toContain(
      `providerOptions: { mode: "timestamped", signatureHeader: ${HOSTILE_LITERAL}, timestampHeader: "x-ts" },`,
    );
    expect(syntaxDiagnostics(content)).toEqual([]);
  });

  test.each(['current', 'legacy'] as const)(
    'Polar %s generation reaches the target or honestly blocks at the base registry',
    (secretMode) => {
      const root = makeTempRoot(`polar-${secretMode}`);
      const args = ['init', 'webhook', '--provider', 'polar', '--framework', 'express'];

      if (secretMode === 'legacy') args.push('--polar-secret-mode', 'legacy');

      const result = runCli(root, args);

      if (result.status === 2) {
        expect(result.stderr).toBe('Unsupported provider.\n');
        expect(collectFiles(path.join(root, 'hooklatch'))).toEqual([]);

        return;
      }

      expect(result.status).toBe(0);

      const content = fs.readFileSync(path.join(root, 'hooklatch', 'polar.express.ts'), 'utf8');

      expect(content).toContain(`providerOptions: { secretMode: "${secretMode}" },`);
      expect(content).toContain('process.env.POLAR_WEBHOOK_SECRET');
      expect(syntaxDiagnostics(content)).toEqual([]);
    },
  );

  test('wrong-provider flags exit two without writes', () => {
    for (const extra of [
      ['--grafana-mode', 'body'],
      ['--signature-header', 'x-sig'],
      ['--timestamp-header', 'x-ts'],
      ['--polar-secret-mode', 'legacy'],
    ]) {
      const root = makeTempRoot('wrong-provider');
      const result = runCli(root, ['init', 'webhook', '--provider', 'stripe', '--framework', 'express', ...extra]);

      expect(result.status).toBe(2);
      expect(result.stderr).toMatch(/only valid for (grafana|polar)\./);
      expect(collectFiles(path.join(root, 'hooklatch'))).toEqual([]);
    }
  });

  test('missing and duplicate provider flags exit two without writes', () => {
    const missingRoot = makeTempRoot('missing-flag');
    const duplicateRoot = makeTempRoot('duplicate-flag');

    const missing = runCli(missingRoot, [
      'init',
      'webhook',
      '--provider',
      'grafana',
      '--framework',
      'express',
      '--grafana-mode',
    ]);

    const duplicate = runCli(duplicateRoot, [
      'init',
      'webhook',
      '--provider',
      'grafana',
      '--framework',
      'express',
      '--timestamp-header',
      'x-one',
      '--timestamp-header',
      'x-two',
    ]);

    expect(missing.status).toBe(2);
    expect(missing.stderr).toBe('Missing value for --grafana-mode.\n');
    expect(duplicate.status).toBe(2);
    expect(duplicate.stderr).toBe('Duplicate flag: --timestamp-header.\n');

    for (const root of [missingRoot, duplicateRoot]) {
      expect(collectFiles(path.join(root, 'hooklatch'))).toEqual([]);
    }
  });

  test('reserved and colliding header options exit two without writes', () => {
    const cases = [
      ['--grafana-mode', 'timestamped', '--signature-header', 'authorization', '--timestamp-header', 'x-ts'],
      ['--grafana-mode', 'timestamped', '--signature-header', 'X-Sig', '--timestamp-header', 'x-sig'],
    ];

    for (const extra of cases) {
      const root = makeTempRoot('bad-header');
      const result = runCli(root, ['init', 'webhook', '--provider', 'grafana', '--framework', 'express', ...extra]);

      expect(result.status).toBe(2);
      expect(collectFiles(path.join(root, 'hooklatch'))).toEqual([]);
    }
  });

  test('secret-value flags are rejected without echoing their value', () => {
    const root = makeTempRoot('secret-flag');

    const result = runCli(root, [
      'init',
      'webhook',
      '--provider',
      'stripe',
      '--framework',
      'express',
      '--secret',
      'synthetic-not-a-real-secret',
    ]);

    expect(result.status).toBe(2);
    expect(result.stderr).toBe('Unknown flag.\n');
    expect(result.stderr).not.toContain('synthetic-not-a-real-secret');
    expect(collectFiles(path.join(root, 'hooklatch'))).toEqual([]);
  });
});
