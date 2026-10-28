/**
 * Phase11 packed-declaration compatibility matrix (owner: deepseek-normal).
 *
 * This module owns only the frozen expectations:
 *   - the pinned provider/reason/error/diagnostic inventories;
 *   - the six public entries and their expected declaration targets;
 *   - the disposable consumer environments and their compiler definitions;
 *   - the independent strict consumer programs rendered for `.mts`/`.cts`
 *     (NodeNext and Node16) plus the neutral Bundler/Workers program;
 *   - the frozen documentation samples copied from tasks/phase-11/doc-examples.json
 *     (this file is embedded on purpose: the delivered driver never reads the
 *     authoring manifest at runtime);
 *   - the negative controls and the package export-policy shape.
 *
 * The driver `scripts/phase11/types-compatibility.mjs` owns installation,
 * compilation, classification, evidence and cleanup.
 *
 * Rules for the programs below:
 *   - They are independent consumers of the INSTALLED packed package; they never
 *     import repository `src/`.
 *   - A positive program must compile with zero diagnostics at `skipLibCheck:false`.
 *   - A negative program carries `// @expect-error TSxxxx` on the exact line where
 *     TypeScript must report that diagnostic. The driver requires an exact
 *     code/line set match and rejects unmarked or out-of-file diagnostics.
 *   - `.cts` bodies never use top-level value exports: with `verbatimModuleSyntax`
 *     a CommonJS file may only export types. The driver turns this into proof that
 *     the CJS declaration graph is read, not that a program shape was avoided.
 *   - No `@ts-ignore`, `@ts-expect-error`, `any`, mirror declarations or stub
 *     packages exist to manufacture an outcome.
 */

/** Provider IDs in registry order at the accepted Phase10 base. */
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

/** Public verification failure reasons. */
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

/** Public setup/runtime error codes. */
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

/** DiagnosticCode is the union of the nine reasons and nine setup codes. */
export const DIAGNOSTIC_CODES = Object.freeze([...FAILURE_REASONS, ...ERROR_CODES]);

export const CORE_LIBS = Object.freeze(['lib.es2022.d.ts', 'lib.dom.d.ts', 'lib.dom.iterable.d.ts']);

/**
 * The six public entries and the declarations each one must reach. `base` is the
 * same-relative-base used by the frozen dist layout.
 */
export const PUBLIC_ENTRIES = Object.freeze([
  Object.freeze({
    subpath: '.',
    base: 'index',
    specifier: 'hooklatch',
    values: Object.freeze(['HooklatchError', 'createVerifier', 'verify', 'verifyRequest']),
    types: Object.freeze([
      'Provider', 'HeaderInput', 'WebhookRequest', 'VerifyOptions', 'FalVerifyOptions', 'GrafanaOptions', 'PolarOptions',
      'IdentityField', 'EventIdentity', 'VerificationFailureReason', 'VerificationSuccess', 'VerificationFailure',
      'VerificationResult', 'HooklatchErrorCode', 'FailureDetails',
    ]),
  }),
  Object.freeze({
    subpath: './diagnostics',
    base: 'diagnostics/index',
    specifier: 'hooklatch/diagnostics',
    values: Object.freeze(['diagnose']),
    types: Object.freeze(['Diagnostic', 'DiagnosticOptions', 'DiagnosticCode']),
  }),
  Object.freeze({
    subpath: './express',
    base: 'adapters/express',
    specifier: 'hooklatch/express',
    values: Object.freeze(['createWebhookMiddleware']),
    types: Object.freeze([]),
  }),
  Object.freeze({
    subpath: './nextjs',
    base: 'adapters/nextjs',
    specifier: 'hooklatch/nextjs',
    values: Object.freeze(['createWebhookHandler']),
    types: Object.freeze(['NextWebhookHandlerOptions']),
  }),
  Object.freeze({
    subpath: './cloudflare',
    base: 'adapters/cloudflare',
    specifier: 'hooklatch/cloudflare',
    values: Object.freeze(['createWebhookHandler']),
    types: Object.freeze(['ExecutionContextLike', 'WorkerWebhookHandlerOptions']),
  }),
  Object.freeze({
    subpath: './hono',
    base: 'adapters/hono',
    specifier: 'hooklatch/hono',
    values: Object.freeze(['createWebhookMiddleware']),
    types: Object.freeze(['WebhookVariables']),
  }),
]);

export const PUBLIC_ENTRY_BY_SPECIFIER = Object.freeze(
  Object.fromEntries(PUBLIC_ENTRIES.map((entry) => [entry.specifier, entry])),
);

/**
 * Frozen export-policy shape the installed artifact must implement before the
 * matrix may run. Key order is significant: `node` must precede the top-level
 * `types` fallback, and `import` must precede `require`.
 */
export const PACKAGE_POLICY = Object.freeze({
  name: 'hooklatch',
  type: 'module',
  main: './dist/cjs/index.cjs',
  types: './dist/index.d.ts',
  bin: Object.freeze({ hooklatch: './dist/cli/index.js' }),
  engines: Object.freeze({ node: '>=22' }),
  exportKeys: Object.freeze(['node', 'types', 'import', 'default']),
  nodeKeys: Object.freeze(['import', 'require']),
  leafKeys: Object.freeze(['types', 'import', 'default']),
  peerDependencies: Object.freeze({ express: '^4.18.0 || ^5.0.0', hono: '^4.0.0' }),
});

const nodeTypes = (base) => Object.freeze({
  types: `./dist/node/${base}.d.ts`,
  default: `./dist/node/${base}.js`,
});

const cjsTypes = (base) => Object.freeze({
  types: `./dist/cjs/${base}.d.cts`,
  default: `./dist/cjs/${base}.cjs`,
});

const originalTypes = (base) => Object.freeze({
  types: `./dist/${base}.d.ts`,
  import: `./dist/${base}.js`,
  default: `./dist/${base}.js`,
});

/** Full expected `exports` map for the six entries, in frozen key order. */
export const EXPECTED_EXPORT_MAP = Object.freeze(
  Object.fromEntries(PUBLIC_ENTRIES.map((entry) => [
    entry.subpath,
    Object.freeze({
      node: Object.freeze({ import: nodeTypes(entry.base), require: cjsTypes(entry.base) }),
      ...originalTypes(entry.base),
    }),
  ])),
);

/**
 * Disposable install roots. Every environment gets its own package.json and
 * node_modules; peer environments link the pinned read-only dependency trees.
 */
export const ENVIRONMENTS = Object.freeze({
  'nodenext-core': Object.freeze({
    id: 'nodenext-core',
    packageName: 'phase11-types-nodenext-core',
    module: 'nodenext',
    distribution: 'node',
    formats: Object.freeze(['.mts', '.cts']),
    libs: CORE_LIBS,
    types: Object.freeze([]),
    links: Object.freeze([]),
    description:
      'Core Web consumer under NodeNext: ES2022 + DOM libs, types:[], no @types at all, both .mts and .cts.',
  }),
  'node16-core': Object.freeze({
    id: 'node16-core',
    packageName: 'phase11-types-node16-core',
    module: 'node16',
    distribution: 'node',
    formats: Object.freeze(['.mts', '.cts']),
    libs: CORE_LIBS,
    types: Object.freeze([]),
    links: Object.freeze([]),
    description:
      'Core Web consumer under Node16: ES2022 + DOM libs, types:[], no @types at all, both .mts and .cts.',
  }),
  'nodenext-express': Object.freeze({
    id: 'nodenext-express',
    packageName: 'phase11-types-nodenext-express',
    module: 'nodenext',
    distribution: 'node',
    formats: Object.freeze(['.mts', '.cts']),
    libs: Object.freeze(['lib.es2022.d.ts']),
    types: Object.freeze(['node', 'express']),
    links: Object.freeze([
      Object.freeze({ name: 'express', target: 'node_modules/express' }),
      Object.freeze({ name: '@types', target: 'node_modules/@types' }),
    ]),
    description:
      'Express peer consumer under NodeNext: real pinned express 5.3.0 and @types/express 5.0.6 trees, both formats.',
  }),
  'node16-express': Object.freeze({
    id: 'node16-express',
    packageName: 'phase11-types-node16-express',
    module: 'node16',
    distribution: 'node',
    formats: Object.freeze(['.mts', '.cts']),
    libs: Object.freeze(['lib.es2022.d.ts']),
    types: Object.freeze(['node', 'express']),
    links: Object.freeze([
      Object.freeze({ name: 'express', target: 'node_modules/express' }),
      Object.freeze({ name: '@types', target: 'node_modules/@types' }),
    ]),
    description:
      'Express peer consumer under Node16: real pinned express 5.3.0 and @types/express 5.0.6 trees, both formats.',
  }),
  'nodenext-hono': Object.freeze({
    id: 'nodenext-hono',
    packageName: 'phase11-types-nodenext-hono',
    module: 'nodenext',
    distribution: 'node',
    formats: Object.freeze(['.mts', '.cts']),
    libs: CORE_LIBS,
    types: Object.freeze([]),
    links: Object.freeze([Object.freeze({ name: 'hono', target: 'node_modules/hono' })]),
    description:
      'Hono peer consumer under NodeNext: real pinned hono 4.13.13 tree, ES2022 + DOM libs, no Node ambient types.',
  }),
  'node16-hono': Object.freeze({
    id: 'node16-hono',
    packageName: 'phase11-types-node16-hono',
    module: 'node16',
    distribution: 'node',
    formats: Object.freeze(['.mts', '.cts']),
    libs: CORE_LIBS,
    types: Object.freeze([]),
    links: Object.freeze([Object.freeze({ name: 'hono', target: 'node_modules/hono' })]),
    description:
      'Hono peer consumer under Node16: real pinned hono 4.13.13 tree, ES2022 + DOM libs, no Node ambient types.',
  }),
  'bundler-worker': Object.freeze({
    id: 'bundler-worker',
    packageName: 'phase11-types-bundler-worker',
    module: 'bundler',
    distribution: 'neutral',
    formats: Object.freeze(['.ts']),
    libs: CORE_LIBS,
    types: Object.freeze([]),
    links: Object.freeze([]),
    description:
      'Neutral Workers/bundler consumer: module ESNext + moduleResolution Bundler, ES2022 + DOM libs, types:[]. '
      + 'No Node condition is selected; no Node ambient global may resolve.',
  }),
  'docs-node': Object.freeze({
    id: 'docs-node',
    packageName: 'phase11-types-docs-node',
    module: 'nodenext',
    distribution: 'node',
    formats: Object.freeze(['.mjs', '.mts', '.cjs', '.cts']),
    libs: CORE_LIBS,
    types: Object.freeze(['node']),
    links: Object.freeze([Object.freeze({ name: '@types', target: 'node_modules/@types' })]),
    description:
      'Documentation-sample consumer: NodeNext, real pinned @types/node, allowJs/checkJs so the frozen .mjs and '
      + '.cjs samples compile exactly as published. This is the only environment that intentionally has Node ambient types.',
    allowJs: true,
  }),
});

/** Logical target groups expanded into per-environment/per-format cases. */
export const TARGETS = Object.freeze({
  core: Object.freeze([
    Object.freeze({ environment: 'nodenext-core', format: '.mts' }),
    Object.freeze({ environment: 'nodenext-core', format: '.cts' }),
    Object.freeze({ environment: 'node16-core', format: '.mts' }),
    Object.freeze({ environment: 'node16-core', format: '.cts' }),
  ]),
  express: Object.freeze([
    Object.freeze({ environment: 'nodenext-express', format: '.mts' }),
    Object.freeze({ environment: 'nodenext-express', format: '.cts' }),
    Object.freeze({ environment: 'node16-express', format: '.mts' }),
    Object.freeze({ environment: 'node16-express', format: '.cts' }),
  ]),
  hono: Object.freeze([
    Object.freeze({ environment: 'nodenext-hono', format: '.mts' }),
    Object.freeze({ environment: 'nodenext-hono', format: '.cts' }),
    Object.freeze({ environment: 'node16-hono', format: '.mts' }),
    Object.freeze({ environment: 'node16-hono', format: '.cts' }),
  ]),
  worker: Object.freeze([Object.freeze({ environment: 'bundler-worker', format: '.ts' })]),
});

const providerList = PROVIDER_IDS.map((provider) => `  '${provider}',`).join('\n');
const reasonList = FAILURE_REASONS.map((reason) => `  '${reason}',`).join('\n');
const errorCodeList = ERROR_CODES.map((code) => `  '${code}',`).join('\n');
const diagnosticCodeList = DIAGNOSTIC_CODES.map((code) => `  '${code}',`).join('\n');

const EQUALITY_HELPERS = `type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Expect<T extends true> = T;`;

const FAMILIES = [
  /* ------------------------------ core positives ------------------------- */
  {
    id: 'positive-inventories',
    target: 'core',
    kind: 'positive',
    description:
      'Pins all 21 provider arms, 9 failure reasons and 9 error codes as exact unions through both module formats.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['Provider', 'VerificationFailureReason', 'HooklatchErrorCode'] }],
    body: `${EQUALITY_HELPERS}

const PROVIDERS = [
${providerList}
] as const satisfies readonly Provider[];

const REASONS = [
${reasonList}
] as const satisfies readonly VerificationFailureReason[];

const ERROR_CODES = [
${errorCodeList}
] as const satisfies readonly HooklatchErrorCode[];

type ProvidersAreExact = Expect<Equal<Provider, (typeof PROVIDERS)[number]>>;
type ReasonsAreExact = Expect<Equal<VerificationFailureReason, (typeof REASONS)[number]>>;
type ErrorCodesAreExact = Expect<Equal<HooklatchErrorCode, (typeof ERROR_CODES)[number]>>;

const evidence = [PROVIDERS, REASONS, ERROR_CODES] as const;`,
  },
  {
    id: 'positive-hmac-apis',
    target: 'core',
    kind: 'positive',
    description:
      'Literal HMAC arms, readonly accept-set, all three root APIs, exact synchronous createVerifier typing and genuine '
      + 'result narrowing.',
    imports: [{
      specifier: 'hooklatch',
      alias: 'hooklatch',
      values: ['verify', 'verifyRequest', 'createVerifier'],
      types: ['VerificationResult', 'VerificationSuccess', 'VerificationFailure', 'VerifyOptions', 'WebhookRequest'],
    }],
    body: `${EQUALITY_HELPERS}
const secrets = ['synthetic-current', 'synthetic-previous'] as const;
const options = {
  provider: 'stripe',
  secrets,
  toleranceSeconds: 300,
  maxBodyBytes: 1_048_576,
  now: () => 1_700_000_000,
} as const satisfies VerifyOptions;

const hmacProviders = [
  { provider: 'github', secrets },
  { provider: 'shopify', secrets },
  { provider: 'standard-webhooks', secrets },
  { provider: 'linear', secrets },
  { provider: 'vercel', secrets },
] as const satisfies readonly VerifyOptions[];

const verifier = createVerifier(options);

type VerifierIsSynchronous = Expect<Equal<typeof verifier, (request: WebhookRequest) => Promise<VerificationResult>>>;
type VerifyIsAsync = Expect<Equal<typeof verify, (request: WebhookRequest, options: VerifyOptions) => Promise<VerificationResult>>>;
type VerifyRequestIsAsync = Expect<Equal<typeof verifyRequest, (request: Request, options: VerifyOptions) => Promise<VerificationResult>>>;

const request: WebhookRequest = {
  rawBody: new Uint8Array([1, 2, 3]),
  headers: { 'stripe-signature': 't=1700000000,v1=synthetic' },
};

async function exercise(): Promise<string> {
  const first: VerificationResult = await verify(request, options);
  const second: VerificationResult = await verifier(request);
  const third: VerificationResult = await verifyRequest(
    new Request('https://example.test/webhook', { method: 'POST', body: new Uint8Array([4]) }),
    { provider: 'github', secrets },
  );

  if (first.ok) {
    const success: VerificationSuccess = first;
    const fields: readonly string[] = success.identity.authenticatedFields;

    return success.provider + ':' + success.rawBody.byteLength + ':' + fields.length + ':' + second.ok + ':' + third.ok;
  }

  const failure: VerificationFailure = first;
  const reason: string = failure.reason;

  return failure.provider + ':' + reason + ':' + second.ok + ':' + third.ok;
}

const evidence = { verifier, hmacProviders, exercise };`,
  },
  {
    id: 'positive-fal-keys-account',
    target: 'core',
    kind: 'positive',
    description:
      'fal uses raw Uint8Array public keys and a required expected account, with no HMAC secrets and no providerOptions.',
    imports: [{
      specifier: 'hooklatch',
      alias: 'hooklatch',
      values: ['createVerifier', 'verify'],
      types: ['FalVerifyOptions', 'VerifyOptions', 'WebhookRequest'],
    }],
    body: `const keys: readonly Uint8Array[] = [new Uint8Array(32), new Uint8Array(32).fill(7)];
const fal: FalVerifyOptions = {
  provider: 'fal',
  publicKeys: keys,
  expectedUserId: 'synthetic-user',
  toleranceSeconds: 300,
  now: () => 1_700_000_000,
};
const options: VerifyOptions = fal;
const verifier = createVerifier(fal);

async function exercise(request: WebhookRequest): Promise<string> {
  const result = await verifier(request);
  const again = await verify(request, options);

  if (result.ok) return String(result.identity.timestamp) + ':' + result.identity.authenticatedFields.length;

  return result.reason + ':' + again.ok;
}

const evidence = { fal, verifier, exercise };`,
  },
  {
    id: 'positive-grafana-config',
    target: 'core',
    kind: 'positive',
    description:
      'Grafana body and timestamped modes, default and configured header names, remain provider-correlated through VerifyOptions.',
    imports: [{
      specifier: 'hooklatch',
      alias: 'hooklatch',
      values: ['createVerifier', 'verify'],
      types: ['GrafanaOptions', 'VerifyOptions', 'WebhookRequest'],
    }],
    body: `const body: GrafanaOptions = { mode: 'body' };
const bodyNamed: GrafanaOptions = { mode: 'body', signatureHeader: 'x-grafana-signature' };
const timestamped: GrafanaOptions = { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' };
const timestampedNamed: GrafanaOptions = {
  mode: 'timestamped',
  timestampHeader: 'x-grafana-timestamp',
  signatureHeader: 'x-grafana-signature',
};

const settings = [
  { provider: 'grafana', secrets: ['synthetic'], providerOptions: body },
  { provider: 'grafana', secrets: ['synthetic'], providerOptions: bodyNamed },
  { provider: 'grafana', secrets: ['synthetic'], providerOptions: timestamped },
  { provider: 'grafana', secrets: ['synthetic'], providerOptions: timestampedNamed },
] as const satisfies readonly VerifyOptions[];

const verifier = createVerifier({
  provider: 'grafana',
  secrets: ['synthetic'],
  providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
} satisfies VerifyOptions);

async function exercise(request: WebhookRequest): Promise<number> {
  let accepted = 0;

  for (const options of settings) {
    const result = await verify(request, options);
    accepted += result.ok ? 1 : 0;
  }

  return accepted;
}

const evidence = { verifier, settings, exercise };`,
  },
  {
    id: 'positive-polar-settings',
    target: 'core',
    kind: 'positive',
    description: 'Polar current, legacy and omitted providerOptions remain assignable; one mode applies to the accept-set.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['PolarOptions', 'VerifyOptions'] }],
    body: `const current: PolarOptions = { secretMode: 'current' };
const legacy: PolarOptions = { secretMode: 'legacy' };

const settings = [
  { provider: 'polar', secrets: ['synthetic'] },
  { provider: 'polar', secrets: ['synthetic'], providerOptions: current },
  { provider: 'polar', secrets: ['synthetic'], providerOptions: legacy },
] as const satisfies readonly VerifyOptions[];

const evidence = { current, legacy, settings };`,
  },
  {
    id: 'positive-diagnostics',
    target: 'core',
    kind: 'positive',
    description:
      'Diagnostics accepts validated failures and HooklatchError only, returns guidance, and pins the exact 18-code union '
      + 'composed from the nine reasons and nine setup codes.',
    imports: [
      {
        specifier: 'hooklatch',
        alias: 'hooklatch',
        values: ['HooklatchError'],
        types: ['VerificationFailure', 'VerificationResult'],
      },
      {
        specifier: 'hooklatch/diagnostics',
        alias: 'hooklatchDiagnostics',
        values: ['diagnose'],
        types: ['Diagnostic', 'DiagnosticCode', 'DiagnosticOptions'],
      },
    ],
    body: `${EQUALITY_HELPERS}
const DIAGNOSTIC_CODES = [
${diagnosticCodeList}
] as const satisfies readonly DiagnosticCode[];

type DiagnosticCodesAreExact = Expect<Equal<DiagnosticCode, (typeof DIAGNOSTIC_CODES)[number]>>;

function fromResult(result: VerificationResult): Diagnostic | null {
  if (result.ok) return null;

  const failure: VerificationFailure = result;
  const options: DiagnosticOptions = { provider: failure.provider, verbose: true };

  return diagnose(failure, options);
}

function fromSetup(error: InstanceType<typeof HooklatchError>): Diagnostic {
  return diagnose(error, { provider: 'stripe', verbose: true });
}

const evidence = { DIAGNOSTIC_CODES, fromResult, fromSetup };`,
  },
  {
    id: 'positive-nextjs-adapter',
    target: 'core',
    kind: 'positive',
    description:
      'Next.js adapter compiles in the Web-only environment without next or Node types; handler parameters and return type are pinned.',
    imports: [
      { specifier: 'hooklatch/nextjs', alias: 'hooklatchNextJs', values: ['createWebhookHandler'], types: ['NextWebhookHandlerOptions'] },
      { specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerificationSuccess'] },
    ],
    body: `const options: NextWebhookHandlerOptions = {
  provider: 'github',
  secrets: ['synthetic'],
  handler: (request, success) => {
    const bytes: Uint8Array = success.rawBody;
    const provider: string = success.provider;

    return new Response(request.url + ':' + bytes.byteLength + ':' + provider);
  },
};

const handler = createWebhookHandler(options);
const callable: (request: Request) => Promise<Response> = handler;

function verified(success: VerificationSuccess): Uint8Array {
  return success.rawBody;
}

const evidence = { handler, callable, verified };`,
  },
  {
    id: 'positive-cloudflare-adapter',
    target: 'core',
    kind: 'positive',
    description:
      'Cloudflare adapter compiles without Workers types: explicit Env generic, ExecutionContextLike and Response return type are pinned.',
    imports: [{
      specifier: 'hooklatch/cloudflare',
      alias: 'hooklatchCloudflare',
      values: ['createWebhookHandler'],
      types: ['ExecutionContextLike', 'WorkerWebhookHandlerOptions'],
    }],
    body: `interface Env {
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

const handler = createWebhookHandler<Env>(options);
const callable: (request: Request, env: Env, ctx: ExecutionContextLike) => Promise<Response> = handler;

const evidence = { handler, callable };`,
  },

  /* ------------------------------ core negatives ------------------------- */
  {
    id: 'negative-broad-provider',
    target: 'core',
    kind: 'negative',
    description: 'A broad Provider plus secrets is not VerifyOptions; consumers must narrow first.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['Provider', 'VerifyOptions'] }],
    body: `function optionsFor(provider: Provider): VerifyOptions {
  return { provider, secrets: ['synthetic'] }; // @expect-error TS2322
}

const evidence = optionsFor;`,
  },
  {
    id: 'negative-fal-missing-account',
    target: 'core',
    kind: 'negative',
    description: 'fal requires expectedUserId; public keys alone are insufficient.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'fal', publicKeys: [new Uint8Array(32)] }; // @expect-error TS2322

const evidence = options;`,
  },
  {
    id: 'negative-fal-missing-keys',
    target: 'core',
    kind: 'negative',
    description: 'fal requires publicKeys; the expected account alone is insufficient.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'fal', expectedUserId: 'synthetic-user' }; // @expect-error TS2322

const evidence = options;`,
  },
  {
    id: 'negative-fal-secrets',
    target: 'core',
    kind: 'negative',
    description: 'fal is asymmetric: HMAC secrets are a different credential arm and are rejected.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'fal', publicKeys: [new Uint8Array(32)], expectedUserId: 'synthetic-user', secrets: ['synthetic'] }; // @expect-error TS2322

const evidence = options;`,
  },
  {
    id: 'negative-fal-provider-options',
    target: 'core',
    kind: 'negative',
    description: 'fal takes no providerOptions; keys and the expected account are top-level.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'fal', publicKeys: [new Uint8Array(32)], expectedUserId: 'synthetic-user', providerOptions: {} }; // @expect-error TS2322

const evidence = options;`,
  },
  {
    id: 'negative-hmac-public-keys',
    target: 'core',
    kind: 'negative',
    description: 'An HMAC provider cannot carry fal public keys or an expected account.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'stripe', secrets: ['synthetic'], publicKeys: [new Uint8Array(32)], expectedUserId: 'synthetic-user' }; // @expect-error TS2353

const evidence = options;`,
  },
  {
    id: 'negative-hmac-provider-options',
    target: 'core',
    kind: 'negative',
    description: 'A non-configured provider cannot borrow Grafana providerOptions.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'stripe', secrets: ['synthetic'], providerOptions: { mode: 'body' } }; // @expect-error TS2322

const evidence = options;`,
  },
  {
    id: 'negative-own-undefined',
    target: 'core',
    kind: 'negative',
    description:
      'With exactOptionalPropertyTypes an own providerOptions: undefined is not the same as omitting the property.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'stripe', secrets: ['synthetic'], providerOptions: undefined }; // @expect-error TS2375

const evidence = options;`,
  },
  {
    id: 'negative-missing-grafana-config',
    target: 'core',
    kind: 'negative',
    description: 'Grafana requires explicit trusted providerOptions.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'grafana', secrets: ['synthetic'] }; // @expect-error TS2322

const evidence = options;`,
  },
  {
    id: 'negative-grafana-unknown-mode',
    target: 'core',
    kind: 'negative',
    description: 'Grafana mode is a closed body/timestamped union.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'grafana', secrets: ['synthetic'], providerOptions: { mode: 'auto' } }; // @expect-error TS2322

const evidence = options;`,
  },
  {
    id: 'negative-grafana-timestamp-required',
    target: 'core',
    kind: 'negative',
    description: 'Timestamped Grafana mode requires the configured timestamp header name.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'grafana', secrets: ['synthetic'], providerOptions: { mode: 'timestamped' } }; // @expect-error TS2322

const evidence = options;`,
  },
  {
    id: 'negative-grafana-body-timestamp-header',
    target: 'core',
    kind: 'negative',
    description: 'Body mode signs only the raw body and forbids a timestamp header.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'grafana', secrets: ['synthetic'], providerOptions: { mode: 'body', timestampHeader: 'x-timestamp' } }; // @expect-error TS2322

const evidence = options;`,
  },
  {
    id: 'negative-forbidden-legacy-config',
    target: 'core',
    kind: 'negative',
    description: 'A non-configured provider cannot borrow Polar providerOptions.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'github', secrets: ['synthetic'], providerOptions: { secretMode: 'legacy' } }; // @expect-error TS2322

const evidence = options;`,
  },
  {
    id: 'negative-polar-unknown-mode',
    target: 'core',
    kind: 'negative',
    description: 'Polar secretMode is a closed current/legacy union.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `const options: VerifyOptions = { provider: 'polar', secrets: ['synthetic'], providerOptions: { secretMode: 'dual' } }; // @expect-error TS2322

const evidence = options;`,
  },
  {
    id: 'negative-interface-extension',
    target: 'core',
    kind: 'negative',
    description: 'VerifyOptions is a discriminated union of intersections; interface extension must migrate to narrowing.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerifyOptions'] }],
    body: `interface Extended extends VerifyOptions { // @expect-error TS2312
  readonly extra: true;
}

type ExtendedAlias = VerifyOptions & { readonly extra: true };

const evidence = {} as ExtendedAlias;`,
  },
  {
    id: 'negative-unsafe-result-narrowing',
    target: 'core',
    kind: 'negative',
    description: 'Authenticated bytes are unreachable until the result union is narrowed to success.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerificationResult'] }],
    body: `function bytesOf(result: VerificationResult): number {
  return result.rawBody.byteLength; // @expect-error TS2339
}

const evidence = bytesOf;`,
  },
  {
    id: 'negative-invalid-provider',
    target: 'core',
    kind: 'negative',
    description: 'The Provider union is closed at the 21 pinned IDs.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['Provider'] }],
    body: `const provider: Provider = 'not-a-provider'; // @expect-error TS2322

const evidence = provider;`,
  },
  {
    id: 'negative-unknown-reason',
    target: 'core',
    kind: 'negative',
    description: 'VerificationFailureReason is closed at the nine pinned reasons.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: [], types: ['VerificationFailureReason'] }],
    body: `const reason: VerificationFailureReason = 'not-a-reason'; // @expect-error TS2322

const evidence = reason;`,
  },
  {
    id: 'negative-unknown-error-code',
    target: 'core',
    kind: 'negative',
    description: 'HooklatchErrorCode is closed at the nine pinned setup/runtime codes.',
    imports: [{ specifier: 'hooklatch', alias: 'hooklatch', values: ['HooklatchError'], types: [] }],
    body: `const error = new HooklatchError('not-a-code', 'synthetic'); // @expect-error TS2345

const evidence = error;`,
  },
  {
    id: 'negative-diagnostics-success-input',
    target: 'core',
    kind: 'negative',
    description: 'diagnose accepts failures and HooklatchError only, never a successful result.',
    imports: [{ specifier: 'hooklatch/diagnostics', alias: 'hooklatchDiagnostics', values: ['diagnose'], types: [] }],
    body: `const diagnostic = diagnose({
  ok: true, // @expect-error TS2322
  provider: 'stripe',
  rawBody: new Uint8Array(),
  identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
});

const evidence = diagnostic;`,
  },
  {
    id: 'negative-no-node-ambient',
    target: 'core',
    kind: 'negative',
    description:
      'Core-only and neutral consumers must not receive Node ambient globals: process, Buffer and require are all unresolved.',
    imports: [],
    body: `const pid = process.pid; // @expect-error TS2591
const bytes = Buffer.from('synthetic'); // @expect-error TS2591
const needed = require; // @expect-error TS2591

const evidence = { pid, bytes, needed };`,
  },
  {
    id: 'negative-deep-import',
    target: 'core',
    kind: 'negative',
    allowUnresolved: true,
    description:
      'Deep imports are rejected by the package exports map instead of resolving a second declaration graph.',
    imports: [],
    body: `import 'hooklatch/dist/index.js'; // @expect-error TS2882

const evidence = 1;`,
  },

  /* ------------------------------- both formats --------------------------- */
  {
    id: 'positive-both-formats',
    target: 'core',
    formats: Object.freeze(['.cts']),
    kind: 'positive',
    description:
      'One CommonJS consumer requires the CJS graph and dynamically imports the ESM facade: identical error class, '
      + 'verifier and diagnose declarations must be reached from both formats in the same program.',
    imports: [
      { specifier: 'hooklatch', alias: 'hooklatch', values: [], types: [] },
      { specifier: 'hooklatch/diagnostics', alias: 'hooklatchDiagnostics', values: [], types: [] },
    ],
    body: `${EQUALITY_HELPERS}
async function both(): Promise<string> {
  const esm = await import('hooklatch');
  const esmDiagnostics = await import('hooklatch/diagnostics');
  const sameError: Expect<Equal<typeof esm.HooklatchError, typeof hooklatch.HooklatchError>> = true;
  const sameVerifier: Expect<Equal<typeof esm.createVerifier, typeof hooklatch.createVerifier>> = true;
  const sameDiagnose: Expect<Equal<typeof esmDiagnostics.diagnose, typeof hooklatchDiagnostics.diagnose>> = true;
  const error = new hooklatch.HooklatchError('invalid-input', 'synthetic');
  const esmError = new esm.HooklatchError('invalid-input', 'synthetic');
  const diagnostic = hooklatchDiagnostics.diagnose(error, { provider: 'stripe' });
  const esmDiagnostic = esmDiagnostics.diagnose(esmError, { provider: 'stripe' });

  void sameError;
  void sameVerifier;
  void sameDiagnose;
  void esmDiagnostic;

  return diagnostic.code;
}

const evidence = both;`,
  },

  /* ------------------------------ express peer ---------------------------- */
  {
    id: 'positive-express-augmentation',
    target: 'express',
    kind: 'positive',
    description:
      'Express adapter with the real pinned express/@types trees: RequestHandler assignment, configured Grafana options and '
      + 'the global Request.webhook augmentation from this format.',
    imports: [{ specifier: 'hooklatch/express', alias: 'hooklatchExpress', values: ['createWebhookMiddleware'], types: [] }],
    typeImports: [{ module: 'express', names: ['Request', 'RequestHandler'] }, { module: 'hooklatch', names: ['VerifyOptions'] }],
    body: `${EQUALITY_HELPERS}
const literal: RequestHandler = createWebhookMiddleware({
  provider: 'stripe',
  secrets: ['synthetic'],
} satisfies VerifyOptions);
const configured: RequestHandler = createWebhookMiddleware({
  provider: 'grafana',
  secrets: ['synthetic'],
  providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
} satisfies VerifyOptions);

function verifiedBytes(request: Request): number {
  return request.webhook?.rawBody.byteLength ?? 0;
}

type AugmentationIsOptional = Expect<Equal<Request['webhook'], import('hooklatch').VerificationSuccess | undefined>>;

const evidence = { literal, configured, verifiedBytes };`,
  },
  {
    id: 'positive-express-both-formats',
    target: 'express',
    formats: Object.freeze(['.cts']),
    kind: 'positive',
    description:
      'Express program importing BOTH formats together: requires the CJS middleware and dynamically imports the ESM facade, '
      + 'then reads Request.webhook once in the shared program.',
    imports: [{ specifier: 'hooklatch/express', alias: 'hooklatchExpress', values: [], types: [] }],
    typeImports: [{ module: 'express', names: ['Request', 'RequestHandler'] }],
    body: `${EQUALITY_HELPERS}
async function both(): Promise<number> {
  const esm = await import('hooklatch/express');
  const cjs: RequestHandler = hooklatchExpress.createWebhookMiddleware({ provider: 'github', secrets: ['synthetic'] });
  const esmHandler: RequestHandler = esm.createWebhookMiddleware({ provider: 'github', secrets: ['synthetic'] });
  const sameCtor: Expect<Equal<typeof esm.createWebhookMiddleware, typeof hooklatchExpress.createWebhookMiddleware>> = true;

  void sameCtor;

  return cjs === esmHandler ? 1 : 0;
}

function bytes(request: Request): number {
  return request.webhook?.rawBody.byteLength ?? 0;
}

type AugmentationIsOptional = Expect<Equal<Request['webhook'], import('hooklatch').VerificationSuccess | undefined>>;

const evidence = { both, bytes };`,
  },

  /* -------------------------------- hono peer ----------------------------- */
  {
    id: 'positive-hono-augmentation',
    target: 'hono',
    kind: 'positive',
    description:
      'Hono adapter with the real pinned hono tree: MiddlewareHandler assignment, required WebhookVariables and the optional '
      + 'ContextVariableMap.webhook augmentation from this format.',
    imports: [{ specifier: 'hooklatch/hono', alias: 'hooklatchHono', values: ['createWebhookMiddleware'], types: ['WebhookVariables'] }],
    typeImports: [{ module: 'hono', names: ['ContextVariableMap', 'MiddlewareHandler'] }, { module: 'hooklatch', names: ['VerificationSuccess'] }],
    body: `${EQUALITY_HELPERS}
const middleware: MiddlewareHandler = createWebhookMiddleware({
  provider: 'github',
  secrets: ['synthetic'],
});

function verified(variables: WebhookVariables): Uint8Array {
  const success: VerificationSuccess = variables.webhook;

  return success.rawBody;
}

type AugmentationIsOptional = Expect<Equal<ContextVariableMap['webhook'], VerificationSuccess | undefined>>;
type VariablesAreRequired = Expect<Equal<WebhookVariables['webhook'], VerificationSuccess>>;

const evidence = { middleware, verified };`,
  },
  {
    id: 'positive-hono-both-formats',
    target: 'hono',
    formats: Object.freeze(['.cts']),
    kind: 'positive',
    description:
      'Hono program importing BOTH formats together: requires the CJS middleware and dynamically imports the ESM facade, '
      + 'then reads ContextVariableMap.webhook once in the shared program.',
    imports: [{ specifier: 'hooklatch/hono', alias: 'hooklatchHono', values: [], types: ['WebhookVariables'] }],
    typeImports: [{ module: 'hono', names: ['ContextVariableMap', 'MiddlewareHandler'] }],
    body: `${EQUALITY_HELPERS}
async function both(): Promise<number> {
  const esm = await import('hooklatch/hono');
  const cjs: MiddlewareHandler = hooklatchHono.createWebhookMiddleware({ provider: 'github', secrets: ['synthetic'] });
  const esmHandler: MiddlewareHandler = esm.createWebhookMiddleware({ provider: 'github', secrets: ['synthetic'] });
  const sameCtor: Expect<Equal<typeof esm.createWebhookMiddleware, typeof hooklatchHono.createWebhookMiddleware>> = true;
  const required: Expect<Equal<undefined extends WebhookVariables['webhook'] ? true : false, false>> = true;

  void sameCtor;
  void required;

  return cjs === esmHandler ? 1 : 0;
}

type AugmentationIsOptional = Expect<Equal<ContextVariableMap['webhook'], import('hooklatch').VerificationSuccess | undefined>>;

const evidence = { both };`,
  },

  /* ------------------------------ worker/neutral -------------------------- */
  {
    id: 'positive-worker-neutral',
    target: 'worker',
    kind: 'positive',
    description:
      'Bundler/Workers consumer exercises the neutral declarations with ES2022 + DOM and no Node ambient globals: root, '
      + 'diagnostics and the Next.js adapter.',
    imports: [
      { specifier: 'hooklatch', alias: 'hooklatch', values: ['createVerifier'], types: ['VerificationResult', 'VerifyOptions'] },
      { specifier: 'hooklatch/diagnostics', alias: 'hooklatchDiagnostics', values: ['diagnose'], types: ['Diagnostic'] },
      { specifier: 'hooklatch/nextjs', alias: 'hooklatchNextJs', values: ['createWebhookHandler'], types: [] },
    ],
    body: `const options = { provider: 'github', secrets: ['synthetic'] } satisfies VerifyOptions;
const verifier = createVerifier(options);

const nextHandler = createWebhookHandler({
  provider: 'github',
  secrets: ['synthetic'],
  handler: (request, success) => new Response(request.url + ':' + success.rawBody.byteLength),
});

const diagnostic: Diagnostic = diagnose(
  { ok: false, provider: 'github', reason: 'invalid-signature', message: 'synthetic' },
  { provider: 'github' },
);

async function verifyInWorker(request: Request): Promise<VerificationResult> {
  return await verifier({ rawBody: new Uint8Array(await request.arrayBuffer()), headers: request.headers });
}

const response: Response = new Response('ok');
const evidence = { verifier, nextHandler, diagnostic, verifyInWorker, response };`,
  },
  {
    id: 'positive-worker-cloudflare',
    target: 'worker',
    kind: 'positive',
    description:
      'Bundler/Workers consumer exercises the neutral Cloudflare adapter: explicit Env generic, ExecutionContextLike and '
      + 'Response return type, without Workers or Node ambient types.',
    imports: [{
      specifier: 'hooklatch/cloudflare',
      alias: 'hooklatchCloudflare',
      values: ['createWebhookHandler'],
      types: ['ExecutionContextLike', 'WorkerWebhookHandlerOptions'],
    }],
    body: `interface Env {
  readonly WEBHOOK_SECRET: string;
  readonly REGION: string;
}

const options: WorkerWebhookHandlerOptions<Env> = {
  options: (env) => ({ provider: 'github', secrets: [env.WEBHOOK_SECRET] }),
  handler: (request, env, ctx, success) => {
    ctx.waitUntil?.(Promise.resolve(env.REGION));

    return new Response(request.url + ':' + success.rawBody.byteLength + ':' + env.REGION);
  },
};

const handler = createWebhookHandler<Env>(options);
const callable: (request: Request, env: Env, ctx: ExecutionContextLike) => Promise<Response> = handler;

const evidence = { handler, callable };`,
  },
  {
    id: 'negative-worker-no-process',
    target: 'worker',
    kind: 'negative',
    description: 'The Bundler/Workers declaration graph must not leak the Node process global.',
    imports: [],
    body: `const pid = process.pid; // @expect-error TS2591

const evidence = pid;`,
  },
  {
    id: 'negative-worker-no-node-builtin',
    target: 'worker',
    kind: 'negative',
    description: 'The Bundler/Workers declaration graph must not resolve Node builtin modules.',
    imports: [],
    body: `import { readFileSync } from 'node:fs'; // @expect-error TS2591

const evidence = readFileSync;`,
  },
];

/** Expand each family over its logical target environments and formats. */
function buildCases() {
  const cases = [];

  for (const family of FAMILIES) {
    for (const target of TARGETS[family.target]) {
      if (family.formats !== undefined && !family.formats.includes(target.format)) continue;

      const source = renderCase(family, target.format);

      cases.push(Object.freeze({
        id: `${target.environment}/${target.format.slice(1)}/${family.id}`,
        familyId: family.id,
        kind: family.kind,
        description: family.description,
        environment: target.environment,
        format: target.format,
        fileName: `${family.id}${target.format}`,
        allowUnresolved: family.allowUnresolved === true,
        source,
      }));
    }
  }

  return Object.freeze(cases);
}

function renderCase(family, format) {
  const sections = [];

  if (family.imports.length > 0) sections.push(renderImports(family.imports, format));

  if (family.typeImports !== undefined && family.typeImports.length > 0) {
    sections.push(family.typeImports.map((entry) => `import type { ${entry.names.join(', ')} } from '${entry.module}';`).join('\n'));
  }

  sections.push(family.body.trim());

  return `${sections.join('\n\n')}\n`;
}

function renderImports(imports, format) {
  const lines = [];

  for (const entry of imports) {
    if (format === '.mts' || format === '.ts') {
      if (entry.values.length > 0) lines.push(`import { ${entry.values.join(', ')} } from '${entry.specifier}';`);

      if (entry.types.length > 0) lines.push(`import type { ${entry.types.join(', ')} } from '${entry.specifier}';`);

      continue;
    }

    // The value graph must go through `import = require`; type-only imports stay
    // in the type namespace so generic public types keep their parameters.
    lines.push(`import ${entry.alias} = require('${entry.specifier}');`);

    if (entry.values.length > 0) lines.push(`const { ${entry.values.join(', ')} } = ${entry.alias};`);

    if (entry.types.length > 0) lines.push(`import type { ${entry.types.join(', ')} } from '${entry.specifier}';`);
  }

  return lines.join('\n');
}

export const CASES = buildCases();

/**
 * Frozen documentation samples, copied verbatim from tasks/phase-11/doc-examples.json.
 * `tasks/phase-11/doc-examples.json` is an authoring input only; this embedded copy
 * is what the delivered driver compiles.
 */
export const DOC_SAMPLES = Object.freeze({
  'esm-javascript': Object.freeze({
    extension: '.mjs',
    language: 'js',
    code: "import { createVerifier, HooklatchError } from 'hooklatch';\nconst verifier = createVerifier({ provider: 'github', secrets: ['synthetic-example-only'] });\nconst setupError = new HooklatchError('invalid-input', 'Example only.');\nvoid verifier;\nvoid setupError;",
  }),
  'cjs-javascript': Object.freeze({
    extension: '.cjs',
    language: 'js',
    code: "const { createVerifier, HooklatchError } = require('hooklatch');\nconst verifier = createVerifier({ provider: 'github', secrets: ['synthetic-example-only'] });\nconst setupError = new HooklatchError('invalid-input', 'Example only.');\nvoid verifier;\nvoid setupError;",
  }),
  'esm-typescript': Object.freeze({
    extension: '.mts',
    language: 'ts',
    code: "import { createVerifier, type VerifyOptions } from 'hooklatch';\nconst options = { provider: 'github', secrets: ['synthetic-example-only'] } satisfies VerifyOptions;\nconst verifier = createVerifier(options);\nvoid verifier;",
  }),
  'cjs-typescript': Object.freeze({
    extension: '.cts',
    language: 'ts',
    code: "import hooklatch = require('hooklatch');\nconst options = { provider: 'github', secrets: ['synthetic-example-only'] } satisfies hooklatch.VerifyOptions;\nconst verifier = hooklatch.createVerifier(options);\nvoid verifier;",
  }),
});

export const DOC_ENVIRONMENT = 'docs-node';

/** Expected declaration target for one entry under one environment/format. */
export function expectedDeclaration(environmentId, format, base) {
  const environment = ENVIRONMENTS[environmentId];

  if (environment.distribution === 'neutral') return `dist/${base}.d.ts`;

  if (format === '.mts' || format === '.mjs') return `dist/node/${base}.d.ts`;

  return `dist/cjs/${base}.d.cts`;
}

/**
 * Negative controls. Each mutating control copies the installed package into an
 * isolated OS-temp root, mutates the copy, and runs the real compiler runner.
 * They exist so a green matrix cannot come from a skipped compiler, a resolver
 * that silently picks repository sources, or a classifier that accepts a
 * missing diagnostic.
 */
export const CONTROLS = Object.freeze([
  Object.freeze({
    id: 'control/removed-declaration-target',
    kind: 'mutate-package',
    description:
      'Deleting dist/cjs/index.d.cts in an isolated copy must make the runner reject the negative case as a wrong '
      + 'declaration resolution, never as a pass or a type rejection.',
    mutation: Object.freeze({ type: 'delete-file', file: 'dist/cjs/index.d.cts' }),
    case: Object.freeze({ familyId: 'negative-invalid-provider', environment: 'nodenext-core', format: '.cts' }),
    expect: 'wrong-resolution',
  }),
  Object.freeze({
    id: 'control/removed-export',
    kind: 'mutate-package',
    description:
      'Removing the FalVerifyOptions export from the copied CJS declarations must surface declaration-file diagnostics '
      + 'that differ from the case marker, so the exact diagnostic classifier cannot accept it.',
    mutation: Object.freeze({ type: 'unexport', file: 'dist/cjs/types.d.cts', symbol: 'FalVerifyOptions' }),
    case: Object.freeze({ familyId: 'negative-fal-secrets', environment: 'nodenext-core', format: '.cts' }),
    expect: 'mismatch',
  }),
  Object.freeze({
    id: 'control/negative-becomes-silent-success',
    kind: 'mutate-package',
    description:
      'Widening Provider to string in an isolated copy makes the invalid-provider negative compile cleanly; the real '
      + 'compiler runner must detect the silent success and fail the case.',
    mutation: Object.freeze({ type: 'widen-provider' }),
    case: Object.freeze({ familyId: 'negative-invalid-provider', environment: 'nodenext-core', format: '.cts' }),
    expect: 'silent-success',
  }),
  Object.freeze({
    id: 'control/unresolved-package',
    kind: 'unresolved-package',
    description:
      'A consumer whose hooklatch import does not resolve to an installed package must be classified as infrastructure, '
      + 'never as a type rejection or a pass.',
    case: Object.freeze({ familyId: 'positive-hmac-apis', environment: 'nodenext-core', format: '.mts' }),
    expect: 'infrastructure',
  }),
  Object.freeze({
    id: 'control/negative-without-diagnostics',
    kind: 'classifier',
    description:
      'A negative expectation with no actual diagnostics must fail classification; an absent compiler result is never '
      + 'diagnostic evidence.',
    case: Object.freeze({ familyId: 'negative-invalid-provider', environment: 'nodenext-core', format: '.cts' }),
    expect: 'classifier-failure',
  }),
  Object.freeze({
    id: 'control/nodenext-express-isolated-augmentation',
    kind: 'mutate-package',
    description: 'Moving augmentation into the ESM facade must not repair an isolated CommonJS consumer.',
    mutation: Object.freeze({ type: 'move-augmentation', provider: 'express' }),
    case: Object.freeze({ familyId: 'positive-express-augmentation', environment: 'nodenext-express', format: '.cts' }),
    expect: 'positive-diagnostics',
    expectedDiagnostic: 2339,
    lineText: 'return request.webhook',
  }),
  Object.freeze({
    id: 'control/node16-express-isolated-augmentation',
    kind: 'mutate-package',
    description: 'Moving augmentation into the ESM facade must not repair an isolated CommonJS consumer.',
    mutation: Object.freeze({ type: 'move-augmentation', provider: 'express' }),
    case: Object.freeze({ familyId: 'positive-express-augmentation', environment: 'node16-express', format: '.cts' }),
    expect: 'positive-diagnostics',
    expectedDiagnostic: 2339,
    lineText: 'return request.webhook',
  }),
  Object.freeze({
    id: 'control/nodenext-hono-isolated-augmentation',
    kind: 'mutate-package',
    description: 'Moving augmentation into the ESM facade must not repair an isolated CommonJS consumer.',
    mutation: Object.freeze({ type: 'move-augmentation', provider: 'hono' }),
    case: Object.freeze({ familyId: 'positive-hono-augmentation', environment: 'nodenext-hono', format: '.cts' }),
    expect: 'positive-diagnostics',
    expectedDiagnostic: 2339,
    lineText: "ContextVariableMap['webhook']",
  }),
  Object.freeze({
    id: 'control/node16-hono-isolated-augmentation',
    kind: 'mutate-package',
    description: 'Moving augmentation into the ESM facade must not repair an isolated CommonJS consumer.',
    mutation: Object.freeze({ type: 'move-augmentation', provider: 'hono' }),
    case: Object.freeze({ familyId: 'positive-hono-augmentation', environment: 'node16-hono', format: '.cts' }),
    expect: 'positive-diagnostics',
    expectedDiagnostic: 2339,
    lineText: "ContextVariableMap['webhook']",
  }),
]);

export const ALL_FAMILY_IDS = Object.freeze(FAMILIES.map((family) => family.id));
