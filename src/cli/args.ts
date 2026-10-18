import { SUPPORTED_PROVIDERS } from '../providers/index.js';
import type { Provider } from '../types.js';

export type Framework = 'express' | 'nextjs' | 'hono' | 'cloudflare';

export const FRAMEWORKS = ['express', 'nextjs', 'hono', 'cloudflare'] as const;

export interface WebhookCommand {
  readonly provider: string;
  readonly framework: Framework;
  readonly out: string;
  readonly secretEnv: string;
  readonly bodyLimit: number;
  readonly dryRun: boolean;
}

export type ParseResult =
  | { readonly kind: 'help' }
  | { readonly kind: 'command'; readonly command: WebhookCommand }
  | { readonly kind: 'error'; readonly exitCode: 2; readonly message: string };

const DEFAULT_BODY_LIMIT = 1048576;
const DEFAULT_OUT = 'hooklatch';
const SECRET_ENV_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

const DEFAULT_SECRET_ENV = {
  stripe: 'STRIPE_WEBHOOK_SECRET',
  github: 'GITHUB_WEBHOOK_SECRET',
  shopify: 'SHOPIFY_WEBHOOK_SECRET',
  'standard-webhooks': 'STANDARD_WEBHOOKS_SECRET',
  clerk: 'CLERK_WEBHOOK_SIGNING_SECRET',
  svix: 'SVIX_WEBHOOK_SECRET',
} satisfies Readonly<Record<string, string>>;

export const HELP_TEXT = `Usage: hooklatch init webhook --provider <id> --framework <id> [options]

Generate one TypeScript webhook endpoint file from an existing Hooklatch adapter.

Required:
  --provider <id>       Implemented provider id.
  --framework <id>      One of: express, nextjs, hono, cloudflare.

Options:
  --out <dir>           Output directory (default: ${DEFAULT_OUT}).
  --secret-env <NAME>   Environment variable holding the secret (default by provider).
  --body-limit <bytes>  Positive safe integer body limit (default: ${DEFAULT_BODY_LIMIT}).
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

  for (let i = 0; i < rest.length; i += 1) {
    const flag = rest[i];

    if (flag === '--dry-run') {
      if (seen.has(flag)) return { kind: 'error', exitCode: 2, message: 'Duplicate flag: --dry-run.' };
      seen.add(flag);
      dryRun = true;
      continue;
    }

    if (flag === '--provider' || flag === '--framework' || flag === '--out' || flag === '--secret-env' || flag === '--body-limit') {
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

  if (out.length === 0) return { kind: 'error', exitCode: 2, message: 'Invalid --out: empty path.' };

  const defaultSecretEnv = DEFAULT_SECRET_ENV[provider];
  const resolvedSecretEnv = secretEnv ?? defaultSecretEnv;

  if (resolvedSecretEnv === undefined || !SECRET_ENV_PATTERN.test(resolvedSecretEnv)) {
    return { kind: 'error', exitCode: 2, message: 'Invalid --secret-env: expected an identifier.' };
  }

  return {
    kind: 'command',
    command: {
      provider,
      framework,
      out,
      secretEnv: resolvedSecretEnv,
      bodyLimit,
      dryRun,
    },
  };
}
