/**
 * Declarative fixture programs for the packed public-contract harness.
 *
 * This module owns only what is being qualified: provider coverage data,
 * consumer environments and the exact programs/expectations. The harness owns
 * packaging, compiler execution, classification, reporting and cleanup.
 *
 * Expectations are pinned to the CURRENT public declarations at the assigned
 * base. Negative programs carry `// @expect-error TSxxxx` markers on the line
 * where TypeScript must report the diagnostic; the harness requires an exact
 * code/line match and no unmarked diagnostics. No marker means "must compile
 * with zero diagnostics".
 *
 * Deliberately NOT demanded as compile errors (runtime validation by design):
 *   - empty `secrets` arrays;
 *   - negative `toleranceSeconds` / `maxBodyBytes`.
 * These stay compile-valid and are documented in the runtime-validation
 * positive program instead of being forced into an impossible type rejection.
 */

/** All provider IDs implemented at the assigned base. Harness compares this to the built registry. */
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
]);

export const CORE_LIBS = Object.freeze(['lib.es2022.d.ts', 'lib.dom.d.ts', 'lib.dom.iterable.d.ts']);

/**
 * One disposable install root per environment so a core-only consumer can
 * never see framework or ambient Node type trees. `links` are read-only
 * junctions into this checkout's pinned node_modules, created only when the
 * environment genuinely needs the peer.
 */
export const ENVIRONMENTS = Object.freeze({
  core: Object.freeze({
    id: 'core',
    packageName: 'consumer-core-web',
    libs: CORE_LIBS,
    types: [],
    links: [],
    description:
      'Web core: ES2022 + DOM + DOM.Iterable, types:[], no Node types, no Express/Hono. '
      + 'Contains the root, diagnostics, Next.js and Cloudflare declaration consumers, '
      + 'including the intentional missing-peer failures.',
  }),
  express: Object.freeze({
    id: 'express',
    packageName: 'consumer-express',
    libs: Object.freeze(['lib.es2022.d.ts']),
    types: Object.freeze(['node', 'express']),
    links: Object.freeze([
      Object.freeze({ name: 'express', target: 'node_modules/express' }),
      Object.freeze({ name: '@types', target: 'node_modules/@types' }),
    ]),
    description:
      'Express consumer: ES2022 only, explicit node + express types, real pinned express/@types '
      + 'trees exposed read-only. Node ambient types are isolated to this environment.',
  }),
  hono: Object.freeze({
    id: 'hono',
    packageName: 'consumer-hono',
    libs: CORE_LIBS,
    types: [],
    links: Object.freeze([Object.freeze({ name: 'hono', target: 'node_modules/hono' })]),
    description:
      'Hono consumer: ES2022 + DOM libs, types:[], real pinned hono tree exposed read-only, '
      + 'no Node ambient types.',
  }),
});

/* -------------------------------------------------------------------------- */
/* positive programs                                                           */
/* -------------------------------------------------------------------------- */

const providerList = PROVIDER_IDS.map((provider) => `  '${provider}',`).join('\n');

export const CASES = Object.freeze([
  {
    id: 'core/positive-public-api',
    kind: 'positive',
    environment: 'core',
    file: 'positive-public-api.ts',
    description:
      'Root imports, readonly secrets/options, record/tuple/Headers inputs, all three entry '
      + 'functions and genuine ok-narrowing on VerificationResult.',
    source: `
import {
  verify, verifyRequest, createVerifier, HooklatchError,
} from 'hooklatch';
import type {
  Provider, HeaderInput, WebhookRequest, VerifyOptions, IdentityField, EventIdentity,
  VerificationFailureReason, VerificationSuccess, VerificationFailure, VerificationResult,
  HooklatchErrorCode, FailureDetails,
} from 'hooklatch';

const secrets: readonly string[] = ['synthetic-secret-a', 'synthetic-secret-b'];
const options: VerifyOptions = {
  provider: 'stripe',
  secrets,
  toleranceSeconds: 300,
  maxBodyBytes: 4096,
  now: () => 1700000000,
};

const recordHeaders: HeaderInput = { 'stripe-signature': 't=1,v1=synthetic' };
const tupleHeaders: HeaderInput = [['stripe-signature', 't=1,v1=synthetic'], ['x-extra', 'value']];
const headersInstance: HeaderInput = new Headers({ 'stripe-signature': 't=1,v1=synthetic' });

const recordInput: WebhookRequest = { rawBody: new TextEncoder().encode('{}'), headers: recordHeaders };
const tupleInput: WebhookRequest = { rawBody: new Uint8Array([1, 2, 3]), headers: tupleHeaders };
const headersInput: WebhookRequest = { rawBody: new Uint8Array([4]), headers: headersInstance };

const reason: VerificationFailureReason = 'invalid-signature';
const failureDetails: FailureDetails = { ok: false, reason, message: 'synthetic' };
const errorCode: HooklatchErrorCode = 'invalid-input';

export function describeFailure(failure: VerificationFailure): string {
  return failure.provider + ':' + failure.reason + ':' + failure.message;
}

export function describeSuccess(success: VerificationSuccess): string {
  const identity: EventIdentity = success.identity;
  const fields: readonly IdentityField[] = identity.authenticatedFields;
  return success.provider + ':' + success.rawBody.byteLength + ':' + fields.length;
}

export function narrow(result: VerificationResult): string {
  if (result.ok) return describeSuccess(result);
  return describeFailure(result);
}

export async function exercise(): Promise<string[]> {
  const verifier = createVerifier(options);
  const results: VerificationResult[] = [
    await verify(recordInput, options),
    await verifier(tupleInput),
    await verifier(headersInput),
    await verifyRequest(new Request('https://example.test/hook', { method: 'POST', body: '{}' }), options),
  ];

  const error = new HooklatchError(errorCode, 'synthetic');
  return [...results.map(narrow), error.code, failureDetails.reason];
}

export type PublicProvider = Provider;
`,
  },
  {
    id: 'core/positive-provider-coverage',
    kind: 'positive',
    environment: 'core',
    file: 'positive-provider-coverage.ts',
    description:
      'Every implemented provider literal is assignable to Provider. The harness also compares '
      + 'this list against the built registry so a newly registered provider fails actionably.',
    source: `
import type { Provider } from 'hooklatch';

export const PROVIDERS = [
${providerList}
] as const satisfies readonly Provider[];

export const COUNT: number = PROVIDERS.length;
`,
  },
  {
    id: 'core/positive-runtime-validation-only',
    kind: 'positive',
    environment: 'core',
    file: 'positive-runtime-validation-only.ts',
    description:
      'Documents inputs that intentionally remain compile-valid because validation is runtime: '
      + 'empty secrets and non-positive limits. No type rejection is demanded for these.',
    source: `
import type { VerifyOptions } from 'hooklatch';

// Runtime validation rejects these with HooklatchError('missing-secrets'/'invalid-options').
export const emptySecrets: VerifyOptions = { provider: 'stripe', secrets: [] };
export const negativeLimits: VerifyOptions = {
  provider: 'stripe',
  secrets: ['synthetic'],
  toleranceSeconds: -1,
  maxBodyBytes: -5,
};
export const zeroTolerance: VerifyOptions = { provider: 'github', secrets: ['synthetic'], toleranceSeconds: 0 };
`,
  },
  {
    id: 'core/positive-diagnostics',
    kind: 'positive',
    environment: 'core',
    file: 'positive-diagnostics.ts',
    description:
      'Installed hooklatch/diagnostics: valid verification failure and HooklatchError inputs, '
      + 'readonly outputs and optional verbose detail.',
    source: `
import { diagnose } from 'hooklatch/diagnostics';
import type { Diagnostic, DiagnosticCode, DiagnosticOptions } from 'hooklatch/diagnostics';
import { HooklatchError } from 'hooklatch';
import type { VerificationFailure } from 'hooklatch';

const failure: VerificationFailure = {
  ok: false,
  provider: 'stripe',
  reason: 'invalid-signature',
  message: 'synthetic-only',
};
const options: DiagnosticOptions = { provider: 'stripe', verbose: true };
const diagnostic: Diagnostic = diagnose(failure, options);
const code: DiagnosticCode = diagnostic.code;
const causes: readonly string[] = diagnostic.possibleCauses;
const suggestions: readonly string[] = diagnostic.suggestions;
const headerDetail: string | undefined = diagnostic.detail?.grammar;
const optionalDetail: Diagnostic['detail'] = diagnose(failure).detail;
const setup: Diagnostic = diagnose(new HooklatchError('invalid-secret', 'synthetic'), { verbose: false });

export { code, causes, suggestions, headerDetail, optionalDetail, setup };
`,
  },
  {
    id: 'core/positive-nextjs',
    kind: 'positive',
    environment: 'core',
    file: 'positive-nextjs.ts',
    description:
      'Next.js subpath in the Web-only environment: Request/Response handler inference with no '
      + 'next/Node packages installed.',
    source: `
import { createWebhookHandler } from 'hooklatch/nextjs';
import type { NextWebhookHandlerOptions } from 'hooklatch/nextjs';

const options: NextWebhookHandlerOptions = {
  provider: 'github',
  secrets: ['synthetic'],
  handler: (request, success) => {
    const url: string = request.url;
    const bytes: Uint8Array = success.rawBody;
    const provider: string = success.provider;
    return new Response(url + ':' + bytes.byteLength + ':' + provider);
  },
};

export const handler = createWebhookHandler(options);
export const callable: (request: Request) => Promise<Response> = handler;
export const viaRequest: Promise<Response> = handler(new Request('https://example.test/hook'));
`,
  },
  {
    id: 'core/positive-cloudflare',
    kind: 'positive',
    environment: 'core',
    file: 'positive-cloudflare.ts',
    description:
      'Cloudflare subpath in the Web-only environment: explicit Env generic, handler parameters, '
      + 'ExecutionContextLike and return type inference without Workers types.',
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
export const viaRequest: Promise<Response> = handler(
  new Request('https://example.test/hook'),
  { WEBHOOK_SECRET: 'synthetic', REGION: 'synthetic-region' },
  {},
);
`,
  },
  {
    id: 'express/positive-middleware',
    kind: 'positive',
    environment: 'express',
    file: 'positive-express.ts',
    description:
      'Express subpath with the real pinned express/@types trees: RequestHandler assignment and the '
      + 'Request.webhook augmentation. Async/value-returning handlers are not asserted as rejected.',
    source: `
import { createWebhookMiddleware } from 'hooklatch/express';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

const middleware: RequestHandler = createWebhookMiddleware({ provider: 'github', secrets: ['synthetic'] });

export const reuse = (handler: RequestHandler): RequestHandler => handler;
export const chained = reuse(middleware);

export function readVerified(req: Request): number {
  const webhook = req.webhook;
  if (webhook === undefined) return 0;
  const bytes: Uint8Array = webhook.rawBody;
  const provider: string = webhook.provider;
  return bytes.byteLength + provider.length;
}

// The existing express types permit async middleware; this is recorded as
// permitted, not qualified as a rejection.
export const asyncHandler = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  readVerified(req);
  res.status(200).end();
  next();
};
`,
  },
  {
    id: 'hono/positive-middleware',
    kind: 'positive',
    environment: 'hono',
    file: 'positive-hono.ts',
    description:
      'Hono subpath with the real pinned hono tree: MiddlewareHandler assignment, Hono route '
      + 'wiring and ContextVariableMap webhook inference, without Node ambient types.',
    source: `
import { Hono } from 'hono';
import type { MiddlewareHandler } from 'hono';
import { createWebhookMiddleware } from 'hooklatch/hono';
import type { WebhookVariables } from 'hooklatch/hono';

const middleware: MiddlewareHandler = createWebhookMiddleware({ provider: 'stripe', secrets: ['synthetic'] });

const app = new Hono<{ Variables: WebhookVariables }>();
app.post('/webhook', middleware, (c) => {
  const webhook = c.get('webhook');
  const bytes: Uint8Array = webhook.rawBody;
  return c.text(String(bytes.byteLength));
});

export { app, middleware };
`,
  },

  {
    id: 'core/positive-configured-providers', kind: 'positive', environment: 'core',
    file: 'positive-configured-providers.ts',
    description: 'Public configured option types preserve provider/mode correlation across all three root APIs.',
    source: `
import { verify, verifyRequest, createVerifier } from 'hooklatch';
import type { VerifyOptions, GrafanaOptions, PolarOptions, WebhookRequest } from 'hooklatch';
const body: GrafanaOptions = { mode: 'body', signatureHeader: 'x-signature' };
const timestamped: GrafanaOptions = { mode: 'timestamped', timestampHeader: 'x-timestamp' };
const legacy: PolarOptions = { secretMode: 'legacy' };
const settings: readonly VerifyOptions[] = [
  { provider: 'grafana', secrets: ['synthetic'], providerOptions: body },
  { provider: 'grafana', secrets: ['synthetic'], providerOptions: timestamped },
  { provider: 'polar', secrets: ['synthetic'], providerOptions: legacy },
  { provider: 'polar', secrets: ['synthetic'] },
];
export async function exercise(input: WebhookRequest, request: Request): Promise<void> {
  for (const options of settings) {
    await verify(input, options);
    await createVerifier(options)(input);
    await verifyRequest(request.clone(), options);
  }
}
`,
  },
  {
    id: 'core/negative-missing-grafana-options', kind: 'negative', environment: 'core',
    file: 'negative-missing-grafana-options.ts',
    description: 'Rejects a configuration outside the provider-discriminated public contract.',
    source: `
import type { VerifyOptions } from 'hooklatch';
export const options: VerifyOptions = { provider: 'grafana', secrets: ['synthetic'] }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-grafana-unknown-mode', kind: 'negative', environment: 'core',
    file: 'negative-grafana-unknown-mode.ts',
    description: 'Rejects a configuration outside the provider-discriminated public contract.',
    source: `
import type { VerifyOptions } from 'hooklatch';
export const options: VerifyOptions = { provider: 'grafana', secrets: ['synthetic'], providerOptions: { mode: 'auto' } }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-grafana-timestamp-header-required', kind: 'negative', environment: 'core',
    file: 'negative-grafana-timestamp-header-required.ts',
    description: 'Rejects a configuration outside the provider-discriminated public contract.',
    source: `
import type { VerifyOptions } from 'hooklatch';
export const options: VerifyOptions = { provider: 'grafana', secrets: ['synthetic'], providerOptions: { mode: 'timestamped' } }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-grafana-body-forbids-timestamp-header', kind: 'negative', environment: 'core',
    file: 'negative-grafana-body-forbids-timestamp-header.ts',
    description: 'Rejects a configuration outside the provider-discriminated public contract.',
    source: `
import type { VerifyOptions } from 'hooklatch';
export const options: VerifyOptions = { provider: 'grafana', secrets: ['synthetic'], providerOptions: { mode: 'body', timestampHeader: 'x-timestamp' } }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-legacy-provider-forbids-options', kind: 'negative', environment: 'core',
    file: 'negative-legacy-provider-forbids-options.ts',
    description: 'Rejects a configuration outside the provider-discriminated public contract.',
    source: `
import type { VerifyOptions } from 'hooklatch';
export const options: VerifyOptions = { provider: 'github', secrets: ['synthetic'], providerOptions: { secretMode: 'legacy' } }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-polar-unknown-mode', kind: 'negative', environment: 'core',
    file: 'negative-polar-unknown-mode.ts',
    description: 'Rejects a configuration outside the provider-discriminated public contract.',
    source: `
import type { VerifyOptions } from 'hooklatch';
export const options: VerifyOptions = { provider: 'polar', secrets: ['synthetic'], providerOptions: { secretMode: 'dual' } }; // @expect-error TS2322
`,
  },

  /* ---- negatives: root public API, one class per program ------------------ */
  {
    id: 'core/negative-unknown-provider',
    kind: 'negative',
    environment: 'core',
    file: 'negative-unknown-provider.ts',
    description: 'Unknown provider literal is rejected at the options boundary.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'not-a-provider', secrets: ['synthetic'] }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-raw-body-string',
    kind: 'negative',
    environment: 'core',
    file: 'negative-raw-body-string.ts',
    description: 'rawBody must be Uint8Array, never a string.',
    source: `
import { verify } from 'hooklatch';

export const pending = verify({ rawBody: 'raw text', headers: {} }, { provider: 'stripe', secrets: ['synthetic'] }); // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-numeric-header',
    kind: 'negative',
    environment: 'core',
    file: 'negative-numeric-header.ts',
    description: 'Record header values must be strings (or string arrays), never numbers.',
    source: `
import type { WebhookRequest } from 'hooklatch';

export const input: WebhookRequest = { rawBody: new Uint8Array(), headers: { 'x-signature': 42 } }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-max-body-string',
    kind: 'negative',
    environment: 'core',
    file: 'negative-max-body-string.ts',
    description: 'maxBodyBytes is numeric and cannot be a string.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'stripe', secrets: ['synthetic'], maxBodyBytes: '1024' }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-clock-string',
    kind: 'negative',
    environment: 'core',
    file: 'negative-clock-string.ts',
    description: 'The injected clock must return a number.',
    source: `
import type { VerifyOptions } from 'hooklatch';

export const options: VerifyOptions = { provider: 'stripe', secrets: ['synthetic'], now: () => '1700000000' }; // @expect-error TS2322
`,
  },
  {
    id: 'core/negative-reason-without-narrowing',
    kind: 'negative',
    environment: 'core',
    file: 'negative-reason-without-narrowing.ts',
    description: 'Failure reason is unreachable on the un-narrowed VerificationResult union.',
    source: `
import type { VerificationResult } from 'hooklatch';

export function reasonOf(result: VerificationResult): string {
  return result.reason; // @expect-error TS2339
}
`,
  },
  {
    id: 'core/negative-identity-without-narrowing',
    kind: 'negative',
    environment: 'core',
    file: 'negative-identity-without-narrowing.ts',
    description: 'Authenticated identity is unreachable without narrowing to success.',
    source: `
import type { VerificationResult } from 'hooklatch';

export function bytesOf(result: VerificationResult): number {
  return result.identity.authenticatedFields.length; // @expect-error TS2339
}
`,
  },
  {
    id: 'core/negative-bad-error-code',
    kind: 'negative',
    environment: 'core',
    file: 'negative-bad-error-code.ts',
    description: 'HooklatchErrorCode is a closed union.',
    source: `
import { HooklatchError } from 'hooklatch';

export const error = new HooklatchError('not-a-code', 'synthetic'); // @expect-error TS2345
`,
  },
  {
    id: 'core/negative-node-globals-absent',
    kind: 'negative',
    environment: 'core',
    file: 'negative-node-globals-absent.ts',
    description:
      'No ambient Node types leak into the Web core environment: the Node-only process global '
      + 'is unavailable.',
    source: `
export const secret = process.env.WEBHOOK_SECRET; // @expect-error TS2591
`,
  },
  {
    id: 'core/negative-missing-express-peer',
    kind: 'negative-external',
    environment: 'core',
    file: 'negative-missing-express-peer.ts',
    description:
      'The Express subpath cannot be typed when its required express/@types peer is absent. The '
      + 'diagnostic is reported inside the installed declaration file, not the consumer.',
    source: `
import { createWebhookMiddleware } from 'hooklatch/express';

export const middleware = createWebhookMiddleware({ provider: 'github', secrets: ['synthetic'] });
`,
    externalDiagnostics: [
      {
        code: 2307,
        fileSuffix: 'node_modules/hooklatch/dist/adapters/express.d.ts',
        messageIncludes: "Cannot find module 'express'",
      },
    ],
  },
  {
    id: 'core/negative-missing-hono-peer',
    kind: 'negative-external',
    environment: 'core',
    file: 'negative-missing-hono-peer.ts',
    description:
      'The Hono subpath cannot be typed when its required hono peer is absent; the diagnostic is '
      + 'reported inside the installed declaration file.',
    source: `
import { createWebhookMiddleware } from 'hooklatch/hono';

export const middleware = createWebhookMiddleware({ provider: 'github', secrets: ['synthetic'] });
`,
    externalDiagnostics: [
      {
        code: 2307,
        fileSuffix: 'node_modules/hooklatch/dist/adapters/hono.d.ts',
        messageIncludes: "Cannot find module 'hono'",
      },
    ],
  },

  /* ---- negatives: diagnostics subpath ------------------------------------- */
  {
    id: 'diagnostics/negative-success-object',
    kind: 'negative',
    environment: 'core',
    file: 'negative-diagnostics-success.ts',
    description: 'diagnose() accepts failures and HooklatchError only, never a success result.',
    source: `
import { diagnose } from 'hooklatch/diagnostics';

const result = diagnose({
  ok: true, // @expect-error TS2322
  provider: 'stripe',
  rawBody: new Uint8Array(),
  identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
});

export { result };
`,
  },
  {
    id: 'diagnostics/negative-unknown-provider',
    kind: 'negative',
    environment: 'core',
    file: 'negative-diagnostics-provider.ts',
    description: 'A failure with an unknown provider is rejected by the public failure type.',
    source: `
import { diagnose } from 'hooklatch/diagnostics';
import type { VerificationFailure } from 'hooklatch';

const failure: VerificationFailure = {
  ok: false,
  provider: 'not-a-provider', // @expect-error TS2322
  reason: 'invalid-signature',
  message: 'synthetic',
};

export const diagnostic = diagnose(failure);
`,
  },
  {
    id: 'diagnostics/negative-unknown-reason',
    kind: 'negative',
    environment: 'core',
    file: 'negative-diagnostics-reason.ts',
    description: 'An unknown verification reason cannot form a VerificationFailure.',
    source: `
import { diagnose } from 'hooklatch/diagnostics';
import type { VerificationFailure } from 'hooklatch';

const failure: VerificationFailure = {
  ok: false,
  provider: 'stripe',
  reason: 'not-a-reason', // @expect-error TS2322
  message: 'synthetic',
};

export const diagnostic = diagnose(failure);
`,
  },
  {
    id: 'diagnostics/negative-bad-code',
    kind: 'negative',
    environment: 'core',
    file: 'negative-diagnostics-code.ts',
    description: 'An unknown HooklatchErrorCode cannot be constructed.',
    source: `
import { diagnose } from 'hooklatch/diagnostics';
import { HooklatchError } from 'hooklatch';

export const diagnostic = diagnose(new HooklatchError('not-a-code', 'synthetic')); // @expect-error TS2345
`,
  },
  {
    id: 'diagnostics/negative-verbose-string',
    kind: 'negative',
    environment: 'core',
    file: 'negative-diagnostics-verbose.ts',
    description: 'DiagnosticOptions.verbose is boolean.',
    source: `
import { diagnose } from 'hooklatch/diagnostics';
import { HooklatchError } from 'hooklatch';

export const diagnostic = diagnose(new HooklatchError('invalid-secret', 'synthetic'), { verbose: 'yes' }); // @expect-error TS2322
`,
  },
  {
    id: 'diagnostics/negative-readonly-output',
    kind: 'negative',
    environment: 'core',
    file: 'negative-diagnostics-readonly.ts',
    description: 'Diagnostic guidance arrays are readonly.',
    source: `
import { diagnose } from 'hooklatch/diagnostics';
import { HooklatchError } from 'hooklatch';

const diagnostic = diagnose(new HooklatchError('invalid-secret', 'synthetic'));
diagnostic.possibleCauses.push('synthetic'); // @expect-error TS2339

export { diagnostic };
`,
  },

  /* ---- negatives: Next.js adapter ----------------------------------------- */
  {
    id: 'nextjs/negative-missing-handler',
    kind: 'negative',
    environment: 'core',
    file: 'negative-nextjs-missing-handler.ts',
    description: 'NextWebhookHandlerOptions requires the user handler callback.',
    source: `
import { createWebhookHandler } from 'hooklatch/nextjs';

export const handler = createWebhookHandler({ provider: 'github', secrets: ['synthetic'] }); // @expect-error TS2345
`,
  },
  {
    id: 'nextjs/negative-handler-return',
    kind: 'negative',
    environment: 'core',
    file: 'negative-nextjs-return.ts',
    description: 'The Next.js user handler must return Response or Promise<Response>.',
    source: `
import { createWebhookHandler } from 'hooklatch/nextjs';

export const handler = createWebhookHandler({
  provider: 'github',
  secrets: ['synthetic'],
  handler: () => 'not-a-response', // @expect-error TS2322
});
`,
  },

  /* ---- negatives: Cloudflare adapter -------------------------------------- */
  {
    id: 'cloudflare/negative-missing-options',
    kind: 'negative',
    environment: 'core',
    file: 'negative-cloudflare-missing-options.ts',
    description: 'WorkerWebhookHandlerOptions requires the per-env options resolver.',
    source: `
import { createWebhookHandler } from 'hooklatch/cloudflare';

export const handler = createWebhookHandler({ handler: () => new Response('ok') }); // @expect-error TS2345
`,
  },
  {
    id: 'cloudflare/negative-env-not-inferred',
    kind: 'negative',
    environment: 'core',
    file: 'negative-cloudflare-env.ts',
    description:
      'Env is not inferred from the handler; without an explicit generic the parameter is unknown. '
      + 'This documents that no Env inference is promised.',
    source: `
import { createWebhookHandler } from 'hooklatch/cloudflare';

export const handler = createWebhookHandler({
  options: (env) => ({ provider: 'github', secrets: [env.WEBHOOK_SECRET] }), // @expect-error TS18046
  handler: (request) => new Response(request.url),
});
`,
  },
  {
    id: 'cloudflare/negative-handler-return',
    kind: 'negative',
    environment: 'core',
    file: 'negative-cloudflare-return.ts',
    description: 'The Workers handler must return Response or Promise<Response>.',
    source: `
import { createWebhookHandler } from 'hooklatch/cloudflare';

interface Env { readonly WEBHOOK_SECRET: string }

export const handler = createWebhookHandler<Env>({
  options: (env) => ({ provider: 'github', secrets: [env.WEBHOOK_SECRET] }),
  handler: () => 42, // @expect-error TS2322
});
`,
  },

  /* ---- negatives: Express adapter ----------------------------------------- */
  {
    id: 'express/negative-missing-options',
    kind: 'negative',
    environment: 'express',
    file: 'negative-express-missing-options.ts',
    description: 'createWebhookMiddleware requires VerifyOptions.',
    source: `
import { createWebhookMiddleware } from 'hooklatch/express';

export const middleware = createWebhookMiddleware(); // @expect-error TS2554
`,
  },
  {
    id: 'express/negative-bad-provider',
    kind: 'negative',
    environment: 'express',
    file: 'negative-express-provider.ts',
    description: 'Express options share the closed Provider union.',
    source: `
import { createWebhookMiddleware } from 'hooklatch/express';

export const middleware = createWebhookMiddleware({ provider: 'not-a-provider', secrets: ['synthetic'] }); // @expect-error TS2322
`,
  },

  /* ---- negatives: Hono adapter ------------------------------------------- */
  {
    id: 'hono/negative-missing-options',
    kind: 'negative',
    environment: 'hono',
    file: 'negative-hono-missing-options.ts',
    description: 'createWebhookMiddleware requires VerifyOptions.',
    source: `
import { createWebhookMiddleware } from 'hooklatch/hono';

export const middleware = createWebhookMiddleware(); // @expect-error TS2554
`,
  },
  {
    id: 'hono/negative-bad-provider',
    kind: 'negative',
    environment: 'hono',
    file: 'negative-hono-provider.ts',
    description: 'Hono options share the closed Provider union.',
    source: `
import { createWebhookMiddleware } from 'hooklatch/hono';

export const middleware = createWebhookMiddleware({ provider: 'not-a-provider', secrets: ['synthetic'] }); // @expect-error TS2322
`,
  },
]);

/**
 * Runtime import-boundary checks executed in the core-only install root. The
 * harness writes/runs the driver; these entries are the expected outcomes.
 * Internal subpaths must be blocked by the package `exports` map (encapsulation,
 * not a security sandbox). ESM only: no CommonJS support claim is made.
 */
export const RUNTIME_BOUNDARY = Object.freeze({
  root: 'hooklatch',
  diagnostics: 'hooklatch/diagnostics',
  expectedRootExports: Object.freeze(['verify', 'verifyRequest', 'createVerifier', 'HooklatchError']),
  blockedSubpaths: Object.freeze([
    'hooklatch/dist/internal/crypto.js',
    'hooklatch/src/index.js',
    'hooklatch/package.json',
  ]),
  absentPeers: Object.freeze(['express', 'hono']),
});

/** Cases that must be rejected as infrastructure, never as a passing negative. */
export const SELF_TEST = Object.freeze({
  unresolvedSpecifier: 'hooklatch/selftest-package-not-installed',
  validProgramSource: 'export const ok: number = 1;\n',
  mismatchedMarkerCode: 'TS2322',
});
