/**
 * Phase10 public-API freeze matrix.
 *
 * This module owns only the pinned expectations: the provider/error/reason
 * inventories, disposable consumer environments, independent strict consumer
 * programs, and the control mutations. The driver
 * `scripts/phase10/api-freeze.mjs` owns packing, compilation, classification,
 * reporting and cleanup.
 *
 * Rules for the programs below:
 *   - They are independent consumers of the packed `hooklatch` package; they
 *     never import repository `src/`.
 *   - A positive program must compile with zero diagnostics.
 *   - A negative program carries `// @expect-error TSxxxx` on the exact line
 *     where TypeScript must report that diagnostic. The driver requires an
 *     exact code/line set match and rejects unmarked diagnostics.
 *   - No `@ts-ignore`, `@ts-expect-error`, `any`, mirror declarations or casts
 *     exist to manufacture an outcome.
 *
 * Deliberately compile-valid (runtime validation by design, not type errors):
 * empty secret arrays, non-positive tolerance/limit values, and body size
 * values that exceed any platform limit.
 */

/** Provider IDs in registry order at base 4b748a2. The driver also compares this to the built registry. */
export const PROVIDER_IDS = Object.freeze([
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
  'grafana',
  'polar',
  'linear',
  'vercel',
  'fal',
]);

/** Public verification failure reasons at base 4b748a2. */
export const FAILURE_REASONS = Object.freeze([
  'missing-signature',
  'malformed-signature',
  'unsupported-scheme',
  'invalid-signature',
  'missing-identity',
  'missing-timestamp',
  'timestamp-expired',
  'timestamp-future',
  'body-too-large',
]);

/** Public setup/runtime error codes at base 4b748a2. */
export const ERROR_CODES = Object.freeze([
  'unknown-provider',
  'missing-secrets',
  'invalid-secret',
  'invalid-options',
  'invalid-input',
  'body-consumed',
  'body-read-failed',
  'crypto-unavailable',
  'internal',
]);

export const CORE_LIBS = Object.freeze(['lib.es2022.d.ts', 'lib.dom.d.ts', 'lib.dom.iterable.d.ts']);

/**
 * One disposable install root per environment. `links` are read-only
 * junctions into this checkout's pinned node_modules and are created only
 * when the environment genuinely needs the optional peer.
 */
export const ENVIRONMENTS = Object.freeze({
  core: Object.freeze({
    id: 'core',
    packageName: 'phase10-freeze-core',
    libs: CORE_LIBS,
    types: Object.freeze([]),
    links: Object.freeze([]),
    description:
      'Web core: ES2022 + DOM + DOM.Iterable, types:[], no Node types, no Express/Hono. '
      + 'Root, diagnostics, Next.js and Cloudflare consumers run here.',
  }),
  express: Object.freeze({
    id: 'express',
    packageName: 'phase10-freeze-express',
    libs: Object.freeze(['lib.es2022.d.ts']),
    types: Object.freeze(['node', 'express']),
    links: Object.freeze([
      Object.freeze({ name: 'express', target: 'node_modules/express' }),
      Object.freeze({ name: '@types', target: 'node_modules/@types' }),
    ]),
    description:
      'Express consumer: ES2022 only, explicit node + express types, real pinned express/@types '
      + 'trees exposed read-only. Node ambient types stay isolated here.',
  }),
  hono: Object.freeze({
    id: 'hono',
    packageName: 'phase10-freeze-hono',
    libs: CORE_LIBS,
    types: Object.freeze([]),
    links: Object.freeze([Object.freeze({ name: 'hono', target: 'node_modules/hono' })]),
    description:
      'Hono consumer: ES2022 + DOM libs, types:[], real pinned hono tree exposed read-only, '
      + 'no Node ambient types.',
  }),
});

const EQUALITY_HELPERS = `
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Expect<T extends true> = T;
`;

const providerList = PROVIDER_IDS.map((provider) => `  '${provider}',`).join('\n');
const reasonList = FAILURE_REASONS.map((reason) => `  '${reason}',`).join('\n');
const errorCodeList = ERROR_CODES.map((code) => `  '${code}',`).join('\n');

const diagnosticCodeList = [...FAILURE_REASONS, ...ERROR_CODES]
  .map((code) => `  '${code}',`)
  .join('\n');

export const CASES = Object.freeze([
  /* ------------------------------------------------------------------------ */
  /* positive: pinned inventories and exact public unions                     */
  /* ------------------------------------------------------------------------ */
  {
    id: 'core/positive-provider-and-union-pins',
    kind: 'positive',
    environment: 'core',
    file: 'positive-provider-pins.ts',
    description:
      'Pins all 21 provider IDs in registry order plus the exact failure-reason and error-code unions. '
      + 'The driver also compares PROVIDER_IDS to the built registry.',
    source: `
import type { Provider, VerificationFailureReason, HooklatchErrorCode } from 'hooklatch';
${EQUALITY_HELPERS}
export const PROVIDER_IDS = [
${providerList}
] as const satisfies readonly Provider[];

export const FAILURE_REASONS = [
${reasonList}
] as const satisfies readonly VerificationFailureReason[];

export const ERROR_CODES = [
${errorCodeList}
] as const satisfies readonly HooklatchErrorCode[];

export type ProviderUnionIsExact = Expect<Equal<Provider, (typeof PROVIDER_IDS)[number]>>;
export type FailureReasonsAreExact = Expect<Equal<VerificationFailureReason, (typeof FAILURE_REASONS)[number]>>;
export type ErrorCodesAreExact = Expect<Equal<HooklatchErrorCode, (typeof ERROR_CODES)[number]>>;
`,
  },
  {
    id: 'core/positive-hmac-apis',
    kind: 'positive',
    environment: 'core',
    file: 'positive-hmac-apis.ts',
    description:
      'Literal HMAC arms, readonly accept-set, all three root APIs, exact synchronous createVerifier '
      + 'typing, asynchronous request APIs and genuine result narrowing.',
    source: `
import { verify, verifyRequest, createVerifier } from 'hooklatch';
import type {
  VerificationResult, VerificationSuccess, VerificationFailure, VerifyOptions, WebhookRequest,
} from 'hooklatch';
${EQUALITY_HELPERS}
const secrets = ['synthetic-current', 'synthetic-previous'] as const;
const options = {
  provider: 'stripe',
  secrets,
  toleranceSeconds: 300,
  maxBodyBytes: 1_048_576,
  now: () => 1_700_000_000,
} as const satisfies VerifyOptions;

export const hmacProviders = [
  { provider: 'github', secrets },
  { provider: 'shopify', secrets },
  { provider: 'standard-webhooks', secrets },
  { provider: 'linear', secrets },
  { provider: 'vercel', secrets },
] as const satisfies readonly VerifyOptions[];

export const verifier = createVerifier(options);
export type VerifierIsSynchronous = Expect<
  Equal<typeof verifier, (request: WebhookRequest) => Promise<VerificationResult>>
>;
export type VerifyIsAsync = Expect<
  Equal<typeof verify, (request: WebhookRequest, options: VerifyOptions) => Promise<VerificationResult>>
>;
export type VerifyRequestIsAsync = Expect<
  Equal<typeof verifyRequest, (request: Request, options: VerifyOptions) => Promise<VerificationResult>>
>;

const request: WebhookRequest = {
  rawBody: new Uint8Array([1, 2, 3]),
  headers: { 'stripe-signature': 't=1700000000,v1=synthetic' },
};

export async function exercise(): Promise<string> {
  const first: VerificationResult = await verify(request, options);
  const second: VerificationResult = await verifier(request);
  const third: VerificationResult = await verifyRequest(
    new Request('https://example.test/webhook', { method: 'POST', body: new Uint8Array([4]) }),
    { provider: 'github', secrets },
  );

  if (first.ok) {
    const success: VerificationSuccess = first;
    const fields: readonly string[] = success.identity.authenticatedFields;
    return success.provider + ':' + success.rawBody.byteLength + ':' + fields.length;
  }

  const failure: VerificationFailure = first;
  const reason: string = failure.reason;
  return failure.provider + ':' + reason + ':' + second.ok + ':' + third.ok;
}
`,
  },
  {
    id: 'core/positive-readonly-inputs',
    kind: 'positive',
    environment: 'core',
    file: 'positive-readonly-inputs.ts',
    description:
      'Readonly record, readonly tuple list and Web Headers all satisfy HeaderInput; frozen options '
      + 'and frozen requests are accepted without casts.',
    source: `
import { createVerifier } from 'hooklatch';
import type { HeaderInput, VerifyOptions, WebhookRequest } from 'hooklatch';

const headerRecord = Object.freeze({
  'x-signature': 'synthetic',
  'x-multi': Object.freeze(['a', 'b']),
});
const tupleHeaders = Object.freeze([
  Object.freeze(['x-signature', 'synthetic'] as const),
  Object.freeze(['x-multi', 'a'] as const),
]);
const webHeaders: HeaderInput = new Headers({ 'x-signature': 'synthetic' });

export const recordInput: HeaderInput = headerRecord;
export const tupleInput: HeaderInput = tupleHeaders;
export const inputs: readonly HeaderInput[] = [recordInput, tupleInput, webHeaders];

const baseOptions: VerifyOptions = { provider: 'stripe', secrets: ['synthetic'] };
const readonlyOptions: Readonly<VerifyOptions> = baseOptions;
export const frozenRequest: WebhookRequest = Object.freeze({
  rawBody: new Uint8Array([1, 2, 3]),
  headers: headerRecord,
});

export const verifier = createVerifier(readonlyOptions);
export const pending = verifier(frozenRequest);
`,
  },
  {
    id: 'core/positive-grafana-modes',
    kind: 'positive',
    environment: 'core',
    file: 'positive-grafana-modes.ts',
    description:
      'Grafana body and timestamped modes, with default and configured header names, remain '
      + 'provider-correlated through VerifyOptions.',
    source: `
import { createVerifier, verify } from 'hooklatch';
import type { GrafanaOptions, VerifyOptions, WebhookRequest } from 'hooklatch';

const body: GrafanaOptions = { mode: 'body' };
const bodyNamed: GrafanaOptions = { mode: 'body', signatureHeader: 'x-grafana-signature' };
const timestamped: GrafanaOptions = { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' };
const timestampedNamed: GrafanaOptions = {
  mode: 'timestamped',
  timestampHeader: 'x-grafana-timestamp',
  signatureHeader: 'x-grafana-signature',
};

export const settings = [
  { provider: 'grafana', secrets: ['synthetic'], providerOptions: body },
  { provider: 'grafana', secrets: ['synthetic'], providerOptions: bodyNamed },
  { provider: 'grafana', secrets: ['synthetic'], providerOptions: timestamped },
  { provider: 'grafana', secrets: ['synthetic'], providerOptions: timestampedNamed },
] as const satisfies readonly VerifyOptions[];

export const verifier = createVerifier({
  provider: 'grafana',
  secrets: ['synthetic'],
  providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
} satisfies VerifyOptions);

export async function exercise(request: WebhookRequest): Promise<number> {
  let accepted = 0;

  for (const options of settings) {
    const result = await verify(request, options);
    accepted += result.ok ? 1 : 0;
  }

  return accepted;
}
`,
  },
  {
    id: 'core/positive-polar-modes',
    kind: 'positive',
    environment: 'core',
    file: 'positive-polar-modes.ts',
    description:
      'Polar current, legacy and omitted providerOptions remain assignable; one mode applies to the '
      + 'whole accept-set at runtime.',
    source: `
import type { PolarOptions, VerifyOptions } from 'hooklatch';

const current: PolarOptions = { secretMode: 'current' };
const legacy: PolarOptions = { secretMode: 'legacy' };

export const settings = [
  { provider: 'polar', secrets: ['synthetic'] },
  { provider: 'polar', secrets: ['synthetic'], providerOptions: current },
  { provider: 'polar', secrets: ['synthetic'], providerOptions: legacy },
] as const satisfies readonly VerifyOptions[];
`,
  },
  {
    id: 'core/positive-fal-keys-account',
    kind: 'positive',
    environment: 'core',
    file: 'positive-fal-keys-account.ts',
    description:
      'fal uses raw Uint8Array public keys and a required expected account, with no HMAC secrets and '
      + 'no providerOptions.',
    source: `
import { createVerifier, verify } from 'hooklatch';
import type { FalVerifyOptions, VerifyOptions, WebhookRequest } from 'hooklatch';

const keys: readonly Uint8Array[] = [new Uint8Array(32), new Uint8Array(32).fill(7)];
export const fal: FalVerifyOptions = {
  provider: 'fal',
  publicKeys: keys,
  expectedUserId: 'synthetic-user',
  toleranceSeconds: 300,
  now: () => 1_700_000_000,
};
export const options: VerifyOptions = fal;
export const verifier = createVerifier(fal);

export async function exercise(request: WebhookRequest): Promise<string> {
  const result = await verifier(request);
  const again = await verify(request, options);

  if (result.ok) return String(result.identity.timestamp) + ':' + result.identity.authenticatedFields.length;

  return result.reason + ':' + again.ok;
}
`,
  },
  {
    id: 'core/positive-migration-narrowing',
    kind: 'positive',
    environment: 'core',
    file: 'positive-migration-narrowing.ts',
    description:
      'Honest broad-Provider migration: generic correlated wrappers and switch narrowing compile, while '
      + 'the negative matrix records that broad Provider + secrets alone is not assignable.',
    source: `
import { createVerifier } from 'hooklatch';
import type { Provider, VerifyOptions } from 'hooklatch';

export function hmacOptions<P extends Exclude<Provider, 'grafana' | 'polar' | 'fal'>>(
  provider: P,
  secrets: readonly string[],
): VerifyOptions {
  return { provider, secrets } satisfies VerifyOptions;
}

export function optionsFor(
  provider: Provider,
  secrets: readonly string[],
  publicKeys: readonly Uint8Array[],
  expectedUserId: string,
): VerifyOptions {
  switch (provider) {
    case 'grafana':
      return { provider, secrets, providerOptions: { mode: 'body' } };
    case 'polar':
      return { provider, secrets, providerOptions: { secretMode: 'current' } };
    case 'fal':
      return { provider, publicKeys, expectedUserId };
    default:
      return { provider, secrets };
  }
}

export const presets = {
  stripe: { provider: 'stripe', secrets: ['synthetic'] },
  github: { provider: 'github', secrets: ['synthetic'] },
  fal: { provider: 'fal', publicKeys: [new Uint8Array(32)], expectedUserId: 'synthetic-user' },
} satisfies Record<string, VerifyOptions>;

export const stripeVerifier = createVerifier(hmacOptions('stripe', ['synthetic']));
`,
  },
  {
    id: 'core/positive-diagnostics',
    kind: 'positive',
    environment: 'core',
    file: 'positive-diagnostics.ts',
    description:
      'Diagnostics subpath accepts validated failures and HooklatchError only, returns readonly '
      + 'guidance, and pins the exact DiagnosticCode union.',
    source: `
import { diagnose } from 'hooklatch/diagnostics';
import type { Diagnostic, DiagnosticCode, DiagnosticOptions } from 'hooklatch/diagnostics';
import { HooklatchError } from 'hooklatch';
import type { VerificationFailure, VerificationResult } from 'hooklatch';
${EQUALITY_HELPERS}
export const DIAGNOSTIC_CODES = [
${diagnosticCodeList}
] as const satisfies readonly DiagnosticCode[];

export type DiagnosticCodesAreExact = Expect<Equal<DiagnosticCode, (typeof DIAGNOSTIC_CODES)[number]>>;

export function fromResult(result: VerificationResult): Diagnostic | null {
  if (result.ok) return null;

  const failure: VerificationFailure = result;
  const options: DiagnosticOptions = { provider: failure.provider, verbose: true };
  const diagnostic: Diagnostic = diagnose(failure, options);

  return diagnostic;
}

export function fromSetup(error: HooklatchError): Diagnostic {
  return diagnose(error, { provider: 'stripe', verbose: true });
}
`,
  },
  {
    id: 'core/positive-nextjs-adapter',
    kind: 'positive',
    environment: 'core',
    file: 'positive-nextjs-adapter.ts',
    description:
      'Next.js adapter compiles in the Web-only environment without next or Node types; handler '
      + 'parameters and return type are pinned.',
    source: `
import { createWebhookHandler } from 'hooklatch/nextjs';
import type { NextWebhookHandlerOptions } from 'hooklatch/nextjs';
import type { VerificationSuccess } from 'hooklatch';

const options: NextWebhookHandlerOptions = {
  provider: 'github',
  secrets: ['synthetic'],
  handler: (request, success) => {
    const bytes: Uint8Array = success.rawBody;
    const provider: string = success.provider;
    return new Response(request.url + ':' + bytes.byteLength + ':' + provider);
  },
};

export const handler = createWebhookHandler(options);
export const callable: (request: Request) => Promise<Response> = handler;
export function verified(success: VerificationSuccess): Uint8Array {
  return success.rawBody;
}
`,
  },
  {
    id: 'core/positive-cloudflare-adapter',
    kind: 'positive',
    environment: 'core',
    file: 'positive-cloudflare-adapter.ts',
    description:
      'Cloudflare adapter compiles without Workers types: explicit Env generic, '
      + 'ExecutionContextLike and Response return type are pinned.',
    source: `
import { createWebhookHandler } from 'hooklatch/cloudflare';
import type { ExecutionContextLike, WorkerWebhookHandlerOptions } from 'hooklatch/cloudflare';

interface Env {
  readonly WEBHOOK_SECRET: string;
  readonly REGION: string;
}

const options: WorkerWebhookHandlerOptions<Env> = {
  options: (env) => ({ provider: 'github', secrets: [env.WEBHOOK_SECRET] }),
  handler: (request, env, ctx, success) => {
    ctx.waitUntil?.(Promise.resolve(env.REGION));
    ctx.passThroughOnException?.();
    return new Response(request.url + ':' + success.rawBody.byteLength + ':' + env.REGION);
  },
};

export const handler = createWebhookHandler<Env>(options);
export const callable: (request: Request, env: Env, ctx: ExecutionContextLike) => Promise<Response> = handler;
`,
  },
  {
    id: 'express/positive-express-adapter',
    kind: 'positive',
    environment: 'express',
    file: 'positive-express-adapter.ts',
    description:
      'Express adapter with the real pinned express/@types trees: RequestHandler assignment, '
      + 'configured Grafana options and the Request.webhook augmentation.',
    source: `
import { createWebhookMiddleware } from 'hooklatch/express';
import type { Request, RequestHandler } from 'express';
import type { VerifyOptions } from 'hooklatch';

export const literal: RequestHandler = createWebhookMiddleware({
  provider: 'stripe',
  secrets: ['synthetic'],
} satisfies VerifyOptions);
export const configured: RequestHandler = createWebhookMiddleware({
  provider: 'grafana',
  secrets: ['synthetic'],
  providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
} satisfies VerifyOptions);

export function verifiedBytes(request: Request): number {
  return request.webhook?.rawBody.byteLength ?? 0;
}
`,
  },
  {
    id: 'hono/positive-hono-adapter',
    kind: 'positive',
    environment: 'hono',
    file: 'positive-hono-adapter.ts',
    description:
      'Hono adapter with the real pinned hono tree: MiddlewareHandler assignment and the '
      + 'WebhookVariables augmentation.',
    source: `
import { createWebhookMiddleware } from 'hooklatch/hono';
import type { WebhookVariables } from 'hooklatch/hono';
import type { MiddlewareHandler } from 'hono';
import type { VerificationSuccess } from 'hooklatch';

export const middleware: MiddlewareHandler = createWebhookMiddleware({
  provider: 'github',
  secrets: ['synthetic'],
});

export function verified(variables: WebhookVariables): Uint8Array {
  const success: VerificationSuccess = variables.webhook;
  return success.rawBody;
}
`,
  },

  /* ------------------------------------------------------------------------ */
  /* negative: credential discrimination, configuration, migration and typing */
  /* ------------------------------------------------------------------------ */
  {
    id: 'core/negative-broad-provider-secrets',
    kind: 'negative',
    environment: 'core',
    file: 'negative-broad-provider-secrets.ts',
    description:
      'A broad Provider plus secrets is not a VerifyOptions: the provider could be fal or a configured '
      + 'provider, so consumers must narrow first.',
    source: `
import type { Provider, VerifyOptions } from 'hooklatch';

export function optionsFor(provider: Provider): VerifyOptions {
  return { provider, secrets: ['synthetic'] }; // @expect-error TS2322
}
`,
  },
  {
    id: 'core/negative-fal-missing-account',
    kind: 'negative',
    environment: 'core',
    file: 'negative-fal-missing-account.ts',
    description: 'fal requires expectedUserId; public keys alone are insufficient.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'fal', publicKeys: [new Uint8Array(32)] }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-fal-missing-keys',
    kind: 'negative',
    environment: 'core',
    file: 'negative-fal-missing-keys.ts',
    description: 'fal requires at least one raw public key in the public type.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'fal', expectedUserId: 'synthetic-user' }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-fal-secrets',
    kind: 'negative',
    environment: 'core',
    file: 'negative-fal-secrets.ts',
    description: 'fal is asymmetric: HMAC secrets are a different credential arm and are rejected.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'fal', publicKeys: [new Uint8Array(32)], expectedUserId: 'synthetic-user', secrets: ['synthetic'] }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-fal-provider-options',
    kind: 'negative',
    environment: 'core',
    file: 'negative-fal-provider-options.ts',
    description: 'fal takes no providerOptions; keys and the expected account are top-level.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'fal', publicKeys: [new Uint8Array(32)], expectedUserId: 'synthetic-user', providerOptions: {} }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-hmac-public-keys',
    kind: 'negative',
    environment: 'core',
    file: 'negative-hmac-public-keys.ts',
    description: 'An HMAC provider cannot carry fal public keys or an expected account.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'stripe', secrets: ['synthetic'], publicKeys: [new Uint8Array(32)], expectedUserId: 'synthetic-user' }; // @expect-error TS2353
`,
  },
  {
    id: 'core/negative-hmac-provider-options',
    kind: 'negative',
    environment: 'core',
    file: 'negative-hmac-provider-options.ts',
    description: 'A non-configured provider cannot borrow Grafana providerOptions.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'stripe', secrets: ['synthetic'], providerOptions: { mode: 'body' } }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-own-undefined',
    kind: 'negative',
    environment: 'core',
    file: 'negative-own-undefined.ts',
    description:
      'With exactOptionalPropertyTypes an own providerOptions: undefined is not the same as omitting '
      + 'the property; consumers must omit it.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'stripe', secrets: ['synthetic'], providerOptions: undefined }; // @expect-error TS2375
`,
  },
  {
    id: 'core/negative-missing-grafana-config',
    kind: 'negative',
    environment: 'core',
    file: 'negative-missing-grafana-config.ts',
    description: 'Grafana requires explicit trusted providerOptions.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'grafana', secrets: ['synthetic'] }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-grafana-unknown-mode',
    kind: 'negative',
    environment: 'core',
    file: 'negative-grafana-unknown-mode.ts',
    description: 'Grafana mode is a closed body/timestamped union.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'grafana', secrets: ['synthetic'], providerOptions: { mode: 'auto' } }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-grafana-timestamp-required',
    kind: 'negative',
    environment: 'core',
    file: 'negative-grafana-timestamp-required.ts',
    description: 'Timestamped Grafana mode requires the configured timestamp header name.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'grafana', secrets: ['synthetic'], providerOptions: { mode: 'timestamped' } }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-grafana-body-timestamp-header',
    kind: 'negative',
    environment: 'core',
    file: 'negative-grafana-body-timestamp-header.ts',
    description: 'Body mode signs only the raw body and forbids a timestamp header.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'grafana', secrets: ['synthetic'], providerOptions: { mode: 'body', timestampHeader: 'x-timestamp' } }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-forbidden-legacy-config',
    kind: 'negative',
    environment: 'core',
    file: 'negative-forbidden-legacy-config.ts',
    description: 'A non-configured provider cannot borrow Polar providerOptions.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'github', secrets: ['synthetic'], providerOptions: { secretMode: 'legacy' } }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-polar-unknown-mode',
    kind: 'negative',
    environment: 'core',
    file: 'negative-polar-unknown-mode.ts',
    description: 'Polar secretMode is a closed current/legacy union.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'polar', secrets: ['synthetic'], providerOptions: { secretMode: 'dual' } }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-interface-extension',
    kind: 'negative',
    environment: 'core',
    file: 'negative-interface-extension.ts',
    description:
      'VerifyOptions is a discriminated union of intersections; interface extension is not statically '
      + 'known and must be migrated to narrowing or an intersection type alias.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export interface Extended extends VerifyOptions { // @expect-error TS2312
  readonly extra: true;
}

export type ExtendedAlias = VerifyOptions & { readonly extra: true };
`,
  },
  {
    id: 'core/negative-unsafe-result-narrowing',
    kind: 'negative',
    environment: 'core',
    file: 'negative-unsafe-result-narrowing.ts',
    description: 'Authenticated bytes are unreachable until the result union is narrowed to success.',
    source: `
import type { VerificationResult } from 'hooklatch';

export function bytesOf(result: VerificationResult): number {
  return result.rawBody.byteLength; // @expect-error TS2339
}
`,
  },
  {
    id: 'core/negative-unknown-provider-id',
    kind: 'negative',
    environment: 'core',
    file: 'negative-unknown-provider-id.ts',
    description: 'The Provider union is closed at the 21 pinned IDs.',
    source: `
import type { Provider } from 'hooklatch';

export const provider: Provider = 'not-a-provider'; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-unknown-reason',
    kind: 'negative',
    environment: 'core',
    file: 'negative-unknown-reason.ts',
    description: 'VerificationFailureReason is closed at the nine pinned reasons.',
    source: `
import type { VerificationFailureReason } from 'hooklatch';

export const reason: VerificationFailureReason = 'not-a-reason'; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-unknown-error-code',
    kind: 'negative',
    environment: 'core',
    file: 'negative-unknown-error-code.ts',
    description: 'HooklatchErrorCode is closed at the nine pinned setup/runtime codes.',
    source: `
import { HooklatchError } from 'hooklatch';

export const error = new HooklatchError('not-a-code', 'synthetic'); // @expect-error TS2345
`,
  },
  {
    id: 'diagnostics/negative-success-input',
    kind: 'negative',
    environment: 'core',
    file: 'negative-diagnostics-success.ts',
    description: 'diagnose accepts failures and HooklatchError only, never a successful result.',
    source: `
import { diagnose } from 'hooklatch/diagnostics';

export const diagnostic = diagnose({
  ok: true, // @expect-error TS2322
  provider: 'stripe',
  rawBody: new Uint8Array(),
  identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
});
`,
  },
]);

/**
 * Controls mutate or extend a known-valid consumer and assert the exact
 * diagnostic/classification. They exist so a green matrix cannot be produced
 * by a compiler that never ran, an unresolved package, or a classifier that
 * accepts missing diagnostics.
 */
export const CONTROLS = Object.freeze([
  Object.freeze({
    id: 'control/mutate-valid-to-invalid-arm',
    baseCaseId: 'core/positive-fal-keys-account',
    description:
      'Mutating the valid fal consumer to add HMAC secrets must yield one TS2322 on the mutated line.',
    replacements: Object.freeze([
      Object.freeze({
        from: "expectedUserId: 'synthetic-user',\n  toleranceSeconds: 300,",
        to: "expectedUserId: 'synthetic-user',\n  secrets: ['synthetic-secret'],\n  toleranceSeconds: 300,",
      }),
    ]),
    expectedCode: 2322,
    expectedLineContains: "secrets: ['synthetic-secret']",
  }),
  Object.freeze({
    id: 'control/missing-export',
    baseCaseId: 'core/positive-hmac-apis',
    description:
      'Appending an import of a non-exported helper must yield TS2305 on that import line, proving the '
      + 'export surface is read from the packed declarations.',
    append: "\nimport { noSuchPublicHelper } from 'hooklatch';\nexport const missing = noSuchPublicHelper;\n",
    expectedCode: 2305,
    expectedLineContains: 'import { noSuchPublicHelper }',
  }),
  Object.freeze({
    id: 'control/ts2322-not-silently-accepted',
    baseCaseId: 'core/positive-hmac-apis',
    description:
      'An unmarked TS2322 injected into a valid consumer must be classified as a case failure, never '
      + 'as a passing positive or negative case.',
    append: '\nexport const broken: string = 42;\n',
    expectedCode: 2322,
    expectedLineContains: 'broken: string = 42',
    classification: 'case-failure',
  }),
  Object.freeze({
    id: 'control/unresolved-package-is-infrastructure',
    baseCaseId: null,
    description:
      'A consumer whose hooklatch import does not resolve to the installed packed package must be '
      + 'classified as infrastructure, never as a type rejection or a pass.',
    source: "import { verify } from 'hooklatch';\nexport const exported = verify;\n",
    classification: 'infrastructure',
  }),
  Object.freeze({
    id: 'control/negative-without-diagnostics-fails',
    baseCaseId: null,
    description:
      'A negative expectation with no actual diagnostics must fail classification; an absent compiler '
      + 'result is never diagnostic evidence.',
    source: "import type { VerifyOptions } from 'hooklatch';\nexport const options: VerifyOptions = { provider: 'stripe', secrets: ['synthetic'] }; // @expect-error TS2322\n",
    classification: 'case-failure',
  }),
]);

/** Docs samples are excerpts of named matrix cases; every fenced sample carries this marker. */
export const DOCS_PATH = 'docs/api-stability.md';
