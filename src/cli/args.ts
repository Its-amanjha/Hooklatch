import { SUPPORTED_PROVIDERS } from '../providers/index.js';
import type { Provider } from '../types.js';

export type Framework = 'express' | 'nextjs' | 'hono' | 'cloudflare';

export const FRAMEWORKS = ['express', 'nextjs', 'hono', 'cloudflare'] as const;

export type GrafanaMode = 'body' | 'timestamped';

export type PolarSecretMode = 'current' | 'legacy';

export interface GrafanaCliOptions {
  readonly mode: GrafanaMode;
  readonly signatureHeader?: string;
  readonly timestampHeader?: string;
}

export interface PolarCliOptions {
  readonly secretMode: PolarSecretMode;
}

export type ProviderCliOptions =
  | { readonly provider: 'grafana'; readonly options: GrafanaCliOptions }
  | { readonly provider: 'polar'; readonly options: PolarCliOptions };

/** Raw flag values collected by the argument scanner, before provider rules. */
export interface RawProviderFlags {
  readonly grafanaMode: string | undefined;
  readonly signatureHeader: string | undefined;
  readonly timestampHeader: string | undefined;
  readonly polarSecretMode: string | undefined;
}

export type ProviderCliOptionsResult =
  | { readonly kind: 'none' }
  | { readonly kind: 'options'; readonly options: ProviderCliOptions }
  | { readonly kind: 'error'; readonly message: string };

export interface WebhookCommand {
  readonly provider: string;
  readonly framework: Framework;
  readonly out: string;
  readonly secretEnv: string;
  readonly bodyLimit: number;
  readonly dryRun: boolean;
  readonly providerOptions?: ProviderCliOptions;
}

export type ParseResult =
  | { readonly kind: 'help' }
  | { readonly kind: 'command'; readonly command: WebhookCommand }
  | { readonly kind: 'error'; readonly exitCode: 2; readonly message: string };

const DEFAULT_BODY_LIMIT = 1048576;
const DEFAULT_OUT = 'hooklatch';
const SECRET_ENV_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Grafana's own default signature header name, matching the provider factory. */
const DEFAULT_SIGNATURE_HEADER = 'x-grafana-alerting-signature';

/** RFC 9110 field-name token characters, matching the Grafana provider factory. */
const FIELD_NAME_TOKEN = /^[!#$%&'*+.^_`|~\dA-Za-z-]+$/;

/**
 * Header names that configured Grafana fields must not replace. This is
 * Hooklatch configuration policy, not a Grafana rule; it matches the Grafana
 * provider factory exactly.
 */
const RESERVED_HEADER_NAMES: ReadonlySet<string> = new Set([
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
]);

const DEFAULT_SECRET_ENV = {
  stripe: 'STRIPE_WEBHOOK_SECRET',
  github: 'GITHUB_WEBHOOK_SECRET',
  shopify: 'SHOPIFY_WEBHOOK_SECRET',
  'standard-webhooks': 'STANDARD_WEBHOOKS_SECRET',
  clerk: 'CLERK_WEBHOOK_SIGNING_SECRET',
  svix: 'SVIX_WEBHOOK_SECRET',
  razorpay: 'RAZORPAY_WEBHOOK_SECRET',
  paddle: 'PADDLE_WEBHOOK_SECRET',
  'lemon-squeezy': 'LEMON_SQUEEZY_WEBHOOK_SECRET',
  'dodo-payments': 'DODO_WEBHOOK_SECRET',
  gitlab: 'GITLAB_WEBHOOK_SECRET',
  replicate: 'REPLICATE_WEBHOOK_SECRET',
  workos: 'WORKOS_WEBHOOK_SECRET',
  sentry: 'SENTRY_WEBHOOK_SECRET',
  doppler: 'DOPPLER_WEBHOOK_SECRET',
  sanity: 'SANITY_WEBHOOK_SECRET',
  grafana: 'GRAFANA_WEBHOOK_SECRET',
  polar: 'POLAR_WEBHOOK_SECRET',
} satisfies Readonly<Record<Provider | 'grafana' | 'polar', string>>;

export const HELP_TEXT = `Usage: hooklatch init webhook --provider <id> --framework <id> [options]

Generate one TypeScript webhook endpoint file from an existing Hooklatch adapter.

Required:
  --provider <id>       Implemented provider id.
  --framework <id>      One of: express, nextjs, hono, cloudflare.

Options:
  --out <dir>           Output directory (default: ${DEFAULT_OUT}).
  --secret-env <NAME>   Environment variable holding the secret (default by provider).
  --body-limit <bytes>  Positive safe integer body limit (default: ${DEFAULT_BODY_LIMIT}).
  --grafana-mode <mode> Grafana only: body or timestamped (required for grafana).
  --signature-header <NAME>
                        Grafana only: RFC 9110 header token (default ${DEFAULT_SIGNATURE_HEADER}).
  --timestamp-header <NAME>
                        Grafana only: required with timestamped; forbidden with body.
  --polar-secret-mode <mode>
                        Polar only: current (default) or legacy.
  --dry-run             Print the target path and contents without writing.
  -h, --help            Show this help.

Exit codes:
  0  Success, dry run, or help.
  1  Unexpected generation or I/O error.
  2  Invalid arguments or unsafe path.
  3  Target file already exists.
`;

function isFramework(value: string): value is Framework {
  // SAFETY: FRAMEWORKS is a fixed readonly tuple of literal framework names; widening to string[] only supports Array.includes.
  return (FRAMEWORKS as readonly string[]).includes(value);
}

function isProvider(value: string): value is Provider {
  // SAFETY: SUPPORTED_PROVIDERS is a fixed readonly tuple of implemented provider ids; widening to string[] only supports Array.includes.
  return (SUPPORTED_PROVIDERS as readonly string[]).includes(value);
}

function isPositiveSafeInteger(value: string): boolean {
  if (!/^[0-9]+$/.test(value)) return false;
  const number = Number(value);

  return Number.isSafeInteger(number) && number > 0;
}

function optionsError(message: string): ProviderCliOptionsResult {
  return { kind: 'error', message };
}

/** A nonempty RFC 9110 field-name token that is not reserved by Hooklatch policy. */
function isConfiguredHeaderName(value: string): boolean {
  return FIELD_NAME_TOKEN.test(value) && !RESERVED_HEADER_NAMES.has(value.toLowerCase());
}

function firstGrafanaFlag(flags: RawProviderFlags): string | null {
  if (flags.grafanaMode !== undefined) return '--grafana-mode';

  if (flags.signatureHeader !== undefined) return '--signature-header';

  if (flags.timestampHeader !== undefined) return '--timestamp-header';

  return null;
}

function buildGrafanaOptions(flags: RawProviderFlags): ProviderCliOptionsResult {
  if (flags.polarSecretMode !== undefined) {
    return optionsError('The --polar-secret-mode flag is only valid for polar.');
  }

  const mode = flags.grafanaMode;

  if (mode === undefined) return optionsError('Missing required --grafana-mode for grafana.');

  if (mode !== 'body' && mode !== 'timestamped') {
    return optionsError('Invalid --grafana-mode: expected body or timestamped.');
  }

  if (flags.signatureHeader !== undefined && !isConfiguredHeaderName(flags.signatureHeader)) {
    return optionsError('Invalid --signature-header: expected an RFC 9110 field-name token that is not reserved.');
  }

  if (mode === 'body') {
    if (flags.timestampHeader !== undefined) {
      return optionsError('The --timestamp-header flag is not allowed in Grafana body mode.');
    }

    if (flags.signatureHeader === undefined) {
      return { kind: 'options', options: { provider: 'grafana', options: { mode: 'body' } } };
    }

    return {
      kind: 'options',
      options: { provider: 'grafana', options: { mode: 'body', signatureHeader: flags.signatureHeader } },
    };
  }

  const timestampHeader = flags.timestampHeader;

  if (timestampHeader === undefined) {
    return optionsError('Missing required --timestamp-header for Grafana timestamped mode.');
  }

  if (!isConfiguredHeaderName(timestampHeader)) {
    return optionsError('Invalid --timestamp-header: expected an RFC 9110 field-name token that is not reserved.');
  }

  const signatureHeader = flags.signatureHeader;
  const effectiveSignatureHeader = signatureHeader === undefined ? DEFAULT_SIGNATURE_HEADER : signatureHeader;

  if (effectiveSignatureHeader.toLowerCase() === timestampHeader.toLowerCase()) {
    return optionsError('The Grafana signature and timestamp headers must differ (case-insensitive).');
  }

  if (signatureHeader === undefined) {
    return {
      kind: 'options',
      options: { provider: 'grafana', options: { mode: 'timestamped', timestampHeader } },
    };
  }

  return {
    kind: 'options',
    options: { provider: 'grafana', options: { mode: 'timestamped', signatureHeader, timestampHeader } },
  };
}

function buildPolarOptions(flags: RawProviderFlags): ProviderCliOptionsResult {
  const grafanaFlag = firstGrafanaFlag(flags);

  if (grafanaFlag !== null) return optionsError(`The ${grafanaFlag} flag is only valid for grafana.`);

  const mode = flags.polarSecretMode;

  if (mode === undefined) {
    return { kind: 'options', options: { provider: 'polar', options: { secretMode: 'current' } } };
  }

  if (mode !== 'current' && mode !== 'legacy') {
    return optionsError('Invalid --polar-secret-mode: expected current or legacy.');
  }

  return { kind: 'options', options: { provider: 'polar', options: { secretMode: mode } } };
}

/**
 * Apply provider-specific flag rules. Registration stays coordinator-owned:
 * a provider that is not yet in the public registry is rejected by
 * `parseArgs` before this function runs.
 */
export function buildProviderCliOptions(provider: string, flags: RawProviderFlags): ProviderCliOptionsResult {
  if (provider === 'grafana') return buildGrafanaOptions(flags);

  if (provider === 'polar') return buildPolarOptions(flags);

  const grafanaFlag = firstGrafanaFlag(flags);

  if (grafanaFlag !== null) return optionsError(`The ${grafanaFlag} flag is only valid for grafana.`);

  if (flags.polarSecretMode !== undefined) {
    return optionsError('The --polar-secret-mode flag is only valid for polar.');
  }

  return { kind: 'none' };
}

export function parseArgs(argv: readonly string[]): ParseResult {
  if (argv.length === 0) return { kind: 'help' };

  if (argv.includes('--help') || argv.includes('-h')) {
    // Help is allowed only as a standalone/global request.
    if (argv.length === 1) return { kind: 'help' };

    // Allow "init webhook --help" specifically.
    if (argv[0] === 'init' && argv[1] === 'webhook' && argv.length === 3 && (argv[2] === '--help' || argv[2] === '-h')) {
      return { kind: 'help' };
    }

    return { kind: 'error', exitCode: 2, message: 'Invalid arguments.' };
  }

  if (argv[0] !== 'init' || argv[1] !== 'webhook') {
    return { kind: 'error', exitCode: 2, message: 'Invalid command. Use: hooklatch init webhook ...' };
  }

  const rest = argv.slice(2);
  const seen = new Set<string>();
  let provider: string | undefined;
  let framework: string | undefined;
  let out = DEFAULT_OUT;
  let secretEnv: string | undefined;
  let bodyLimit = DEFAULT_BODY_LIMIT;
  let dryRun = false;
  let grafanaMode: string | undefined;
  let signatureHeader: string | undefined;
  let timestampHeader: string | undefined;
  let polarSecretMode: string | undefined;

  for (let i = 0; i < rest.length; i += 1) {
    const flag = rest[i];

    if (flag === '--dry-run') {
      if (seen.has(flag)) return { kind: 'error', exitCode: 2, message: 'Duplicate flag: --dry-run.' };
      seen.add(flag);
      dryRun = true;
      continue;
    }

    if (flag === '--provider' || flag === '--framework' || flag === '--out' || flag === '--secret-env' || flag === '--body-limit'
      || flag === '--grafana-mode' || flag === '--signature-header' || flag === '--timestamp-header' || flag === '--polar-secret-mode') {
      if (seen.has(flag)) return { kind: 'error', exitCode: 2, message: `Duplicate flag: ${flag}.` };
      seen.add(flag);
      const value = rest[i + 1];

      if (value === undefined || value.startsWith('--') || value === '-h') {
        return { kind: 'error', exitCode: 2, message: `Missing value for ${flag}.` };
      }

      i += 1;

      if (flag === '--provider') provider = value;
      else if (flag === '--framework') framework = value;
      else if (flag === '--out') out = value;
      else if (flag === '--secret-env') secretEnv = value;
      else if (flag === '--grafana-mode') grafanaMode = value;
      else if (flag === '--signature-header') signatureHeader = value;
      else if (flag === '--timestamp-header') timestampHeader = value;
      else if (flag === '--polar-secret-mode') polarSecretMode = value;
      else if (flag === '--body-limit') {
        if (!isPositiveSafeInteger(value)) {
          return { kind: 'error', exitCode: 2, message: 'Invalid --body-limit: expected a positive safe integer.' };
        }

        bodyLimit = Number(value);
      }

      continue;
    }

    return { kind: 'error', exitCode: 2, message: 'Unknown flag.' };
  }

  if (!provider) return { kind: 'error', exitCode: 2, message: 'Missing required --provider.' };

  if (!framework) return { kind: 'error', exitCode: 2, message: 'Missing required --framework.' };

  if (!isProvider(provider)) {
    return { kind: 'error', exitCode: 2, message: 'Unsupported provider.' };
  }

  if (!isFramework(framework)) {
    return { kind: 'error', exitCode: 2, message: 'Unsupported framework.' };
  }

  const providerOptionsResult = buildProviderCliOptions(provider, {
    grafanaMode,
    signatureHeader,
    timestampHeader,
    polarSecretMode,
  });

  if (providerOptionsResult.kind === 'error') {
    return { kind: 'error', exitCode: 2, message: providerOptionsResult.message };
  }

  if (out.length === 0) return { kind: 'error', exitCode: 2, message: 'Invalid --out: empty path.' };

  const defaultSecretEnv = DEFAULT_SECRET_ENV[provider];
  const resolvedSecretEnv = secretEnv ?? defaultSecretEnv;

  if (resolvedSecretEnv === undefined || !SECRET_ENV_PATTERN.test(resolvedSecretEnv)) {
    return { kind: 'error', exitCode: 2, message: 'Invalid --secret-env: expected an identifier.' };
  }

  const baseCommand = {
    provider,
    framework,
    out,
    secretEnv: resolvedSecretEnv,
    bodyLimit,
    dryRun,
  } satisfies WebhookCommand;

  if (providerOptionsResult.kind === 'none') {
    return { kind: 'command', command: baseCommand };
  }

  return { kind: 'command', command: { ...baseCommand, providerOptions: providerOptionsResult.options } };
}
