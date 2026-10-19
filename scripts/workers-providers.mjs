import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';

/**
 * Real-workerd qualification for every provider in the built registry.
 *
 * Required coverage is derived from `dist/providers/index.js`
 * `SUPPORTED_PROVIDERS` (an internal file import; no public registry export is
 * added or assumed). Registering a provider together with its fixture extends
 * this check automatically; the exact registry/covered-provider equality below
 * refuses to pass if a registered provider has no fixture or no passing anchor.
 *
 * The fixture layer is Node-only and uses `node:crypto` solely to prepare
 * synthetic cases. The bundled Worker imports the built-in verification code
 * and never imports a Node module, a provider SDK, or this harness.
 *
 * Clerk/Svix branded cases are the pinned published Standard Webhooks vector
 * (`reference-vector-sign-works`) with only the three `webhook-*` header names
 * renamed to `svix-*`. The body, secret, timestamp, expected signature, and
 * source attribution are unchanged. The same vector is published with branded
 * headers at https://docs.svix.com/receiving/verifying-payloads/how. This is an
 * explicit header-name transformation, not a live capture or a locally
 * generated reference signature.
 */

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WORKER_CONDITIONS = ['workerd', 'worker', 'browser'];
const COMPATIBILITY_DATE = '2026-08-06';
const COMPATIBILITY_FLAGS = [];
const UNSIGNED_OR_NULL = 'unsigned-or-null';

/**
 * Explicit header names for the legacy `unsigned-or-null` identity sentinel.
 * Any sentinel for a provider absent here fails loudly instead of guessing, so
 * a new fixture schema cannot be silently treated as an existing one.
 */
const SENTINEL_HEADER = {
  github: { deliveryId: 'x-github-delivery' },
  shopify: { deliveryId: 'x-shopify-webhook-id', eventId: 'x-shopify-event-id' },
  razorpay: { eventId: 'x-razorpay-event-id' },
};

/** Provider-specific synthetic binary/rotating-key recipes (never inferred). */
const BINARY_SUPPLEMENT_PROVIDERS = ['razorpay', 'paddle', 'lemon-squeezy'];

const cases = [];

/** Load the built internal registry; no new public export is created here. */
async function loadRegistryProviders() {
  const registryPath = join(root, 'dist', 'providers', 'index.js');

  if (!existsSync(registryPath)) {
    throw new Error('Built provider registry is missing: dist/providers/index.js. Run npm run build before npm run test:workers.');
  }

  const module = await import(pathToFileURL(registryPath).href);
  const providers = module.SUPPORTED_PROVIDERS;

  assert(Array.isArray(providers) && providers.length > 0,
    'The built registry did not expose a nonempty SUPPORTED_PROVIDERS array.');

  return [...providers];
}

async function fixtureFile(provider) {
  const path = resolve(root, 'tests/fixtures', `${provider}.json`);

  if (!existsSync(path)) {
    throw new Error(`Registered provider ${provider} has no fixture file: tests/fixtures/${provider}.json.`);
  }

  const file = JSON.parse(await readFile(path, 'utf8'));

  assert(Array.isArray(file.cases) && file.cases.length > 0,
    `Fixture for ${provider} has no cases; workerd coverage would silently shrink.`);

  return file;
}

function tamperedBody(bodyBase64) {
  return Buffer.concat([Buffer.from(bodyBase64, 'base64'), Buffer.from('!')]).toString('base64');
}

function headerValue(headers, name) {
  const wanted = name.toLowerCase();
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === wanted);

  if (entry === undefined) return null;
  const value = entry[1];

  return Array.isArray(value) ? value.join(', ') : value;
}

function resolveFixtureIdentity(provider, fixture) {
  const expected = fixture.expected.identity;

  if (expected === undefined) return undefined;

  const resolved = { ...expected };

  for (const field of ['deliveryId', 'eventId']) {
    if (resolved[field] !== UNSIGNED_OR_NULL) continue;
    const headerName = SENTINEL_HEADER[provider]?.[field];

    if (headerName === undefined) {
      throw new Error(`Unhandled ${UNSIGNED_OR_NULL} sentinel for ${provider}.${field}; add an explicit header mapping.`);
    }

    resolved[field] = headerValue(fixture.request.headers, headerName);

    // A Web Request normalizes surrounding header whitespace before the SDK
    // sees it; this checks transport-visible metadata rather than record input.
    if (provider === 'razorpay' && field === 'eventId' && resolved[field] !== null) resolved[field] = resolved[field].trim();
  }

  return resolved;
}

function pushCase(entry) {
  cases.push(entry);
}

/** Replay one fixture case verbatim, preserving supplied now/omitted tolerance. */
function fixtureRuntimeCases(provider, file) {
  const positive = file.cases.find((entry) => entry.expected.ok && entry.request && entry.request.bodyBase64 !== undefined);

  assert(positive, `Fixture for ${provider} has no positive runtime anchor (expected.ok with bodyBase64).`);

  const entries = [];

  for (const fixture of file.cases) {
    entries.push({
      id: `${provider}: ${fixture.id}`,
      provider,
      headers: fixture.request.headers,
      bodyBase64: fixture.request.bodyBase64,
      options: fixture.options,
      expected: fixture.expected.ok
        ? { ok: true, identity: resolveFixtureIdentity(provider, fixture) }
        : { ok: false, reason: fixture.expected.reason },
    });
  }

  // Every provider must exercise at least one tampered body, even when its
  // fixture corpus omits a negative case.
  entries.push({
    id: `${provider}: synthesized body tamper`,
    provider,
    headers: positive.request.headers,
    bodyBase64: tamperedBody(positive.request.bodyBase64),
    options: positive.options,
    expected: { ok: false, reason: 'invalid-signature' },
  });

  return entries;
}

/** Independent node:crypto recipe; never used to imply an unknown v1 form. */
function binarySupplementCases(provider) {
  const body = Buffer.from([0xff, 0, 0xc3, 0x28, 0x80, 13, 10]);
  const retiringSecret = 'runtime_retiring_synthetic_key';
  const activeSecret = 'runtime_active_synthetic_key';
  const timestamp = 1700000500;

  const signed = provider === 'paddle'
    ? Buffer.concat([Buffer.from(`${timestamp}:`), body]) : body;

  const signature = createHmac('sha256', retiringSecret).update(signed).digest('hex');

  const headers = provider === 'paddle'
    ? { 'paddle-signature': `ts=${timestamp};h1=${signature}` }
    : { [provider === 'razorpay' ? 'x-razorpay-signature' : 'x-signature']: signature };

  const identity = {
    deliveryId: null,
    eventId: null,
    timestamp: provider === 'paddle' ? timestamp : null,
    authenticatedFields: provider === 'paddle' ? ['timestamp'] : [],
  };

  return [
    {
      id: `${provider}: binary bytes with retiring key in accept set`,
      provider,
      headers,
      bodyBase64: body.toString('base64'),
      options: { secrets: [activeSecret, retiringSecret], now: timestamp },
      expected: { ok: true, identity },
    },
    {
      id: `${provider}: removed retiring key rejects binary bytes`,
      provider,
      headers,
      bodyBase64: body.toString('base64'),
      options: { secrets: [activeSecret], now: timestamp },
      expected: { ok: false, reason: 'invalid-signature' },
    },
  ];
}

const requiredProviders = await loadRegistryProviders();
const fixtures = new Map();

for (const provider of requiredProviders) fixtures.set(provider, await fixtureFile(provider));

for (const provider of requiredProviders) {
  for (const entry of fixtureRuntimeCases(provider, fixtures.get(provider))) pushCase(entry);
}

for (const provider of requiredProviders) {
  if (BINARY_SUPPLEMENT_PROVIDERS.includes(provider)) {
    for (const entry of binarySupplementCases(provider)) pushCase(entry);
  }
}

// Preserve the published Clerk/Svix branded-family matrix (alias, conflicting
// family, rotation and two-sided freshness cases) exactly as before.
const standardWebhooks = fixtures.get('standard-webhooks');

assert(standardWebhooks, 'The published Standard Webhooks reference vector requires the standard-webhooks fixture.');

const vector = standardWebhooks.cases.find((entry) => entry.id === 'reference-vector-sign-works');

assert(vector, 'Missing pinned Standard Webhooks reference vector.');

const PUBLIC_SECRET = vector.options.secrets[0];
const PUBLIC_ID = headerValue(vector.request.headers, 'webhook-id');
const PUBLIC_TIMESTAMP = Number(headerValue(vector.request.headers, 'webhook-timestamp'));
const PUBLIC_BODY_BASE64 = vector.request.bodyBase64;
const PUBLIC_BODY = Buffer.from(PUBLIC_BODY_BASE64, 'base64');
const PUBLIC_SIGNATURE = headerValue(vector.request.headers, 'webhook-signature');

const PUBLIC_IDENTITY = {
  deliveryId: null,
  eventId: PUBLIC_ID,
  timestamp: PUBLIC_TIMESTAMP,
  authenticatedFields: ['eventId', 'timestamp'],
};

const OTHER_SECRET = `whsec_${Buffer.alloc(24, 7).toString('base64')}`;

function brandedHeaders(signature = PUBLIC_SIGNATURE, id = PUBLIC_ID, timestamp = PUBLIC_TIMESTAMP) {
  return {
    'svix-id': id,
    'svix-timestamp': String(timestamp),
    'svix-signature': signature,
  };
}

function canonicalHeaders(signature = PUBLIC_SIGNATURE, id = PUBLIC_ID, timestamp = PUBLIC_TIMESTAMP) {
  return {
    'webhook-id': id,
    'webhook-timestamp': String(timestamp),
    'webhook-signature': signature,
  };
}

/** Test-only HMAC preparation; never imported by the Worker. */
function hmacSignature(secret, id, timestamp, body) {
  const key = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
  const signedContent = Buffer.concat([Buffer.from(`${id}.${timestamp}.`, 'utf8'), body]);

  return `v1,${createHmac('sha256', key).update(signedContent).digest('base64')}`;
}

const OTHER_SIGNATURE = hmacSignature(OTHER_SECRET, PUBLIC_ID, PUBLIC_TIMESTAMP, PUBLIC_BODY);

function providerCase(id, provider, headers, expected, overrides = {}) {
  return {
    id: `${provider}: ${id}`,
    provider,
    headers,
    bodyBase64: overrides.bodyBase64 ?? PUBLIC_BODY_BASE64,
    options: {
      secrets: overrides.secrets ?? [PUBLIC_SECRET],
      toleranceSeconds: overrides.toleranceSeconds ?? 300,
      now: overrides.now ?? PUBLIC_TIMESTAMP,
    },
    expected,
  };
}

const success = { ok: true, identity: PUBLIC_IDENTITY };

pushCase(providerCase('branded published vector', 'clerk', brandedHeaders(), success));

pushCase(providerCase('branded published vector', 'svix', brandedHeaders(), success));

pushCase(providerCase('canonical published vector', 'svix', canonicalHeaders(), success));

pushCase(providerCase('identical complete dual families', 'svix', {
  ...brandedHeaders(),
  ...canonicalHeaders(),
}, success));

pushCase(providerCase('conflicting id names', 'svix', {
  ...brandedHeaders(),
  ...canonicalHeaders(PUBLIC_SIGNATURE, 'msg_other'),
}, { ok: false, reason: 'malformed-signature' }));

pushCase(providerCase('conflicting timestamp names', 'svix', {
  ...brandedHeaders(),
  ...canonicalHeaders(PUBLIC_SIGNATURE, PUBLIC_ID, PUBLIC_TIMESTAMP + 1),
}, { ok: false, reason: 'malformed-signature' }));

pushCase(providerCase('conflicting signature names', 'svix', {
  ...brandedHeaders(),
  ...canonicalHeaders(OTHER_SIGNATURE),
}, { ok: false, reason: 'malformed-signature' }));

pushCase(providerCase('mixed partial families', 'svix', {
  'svix-id': PUBLIC_ID,
  'webhook-timestamp': String(PUBLIC_TIMESTAMP),
  'webhook-signature': PUBLIC_SIGNATURE,
}, { ok: false, reason: 'malformed-signature' }));

pushCase(providerCase('malformed branded family is not repaired by canonical', 'svix', {
  'svix-signature': 'v1,@@@',
  ...canonicalHeaders(),
}, { ok: false, reason: 'malformed-signature' }));

pushCase(providerCase('canonical-only headers are ignored', 'clerk', canonicalHeaders(),
  { ok: false, reason: 'missing-signature' }));

pushCase(providerCase('canonical family does not repair missing branded id', 'clerk', {
  'svix-signature': PUBLIC_SIGNATURE,
  'webhook-id': PUBLIC_ID,
  'webhook-timestamp': String(PUBLIC_TIMESTAMP),
}, { ok: false, reason: 'missing-identity' }));

pushCase(providerCase('canonical family does not repair malformed branded signature', 'clerk', {
  'svix-signature': 'v1,@@@',
  ...canonicalHeaders(),
}, { ok: false, reason: 'malformed-signature' }));

for (const provider of ['clerk', 'svix']) {
  pushCase(providerCase('past window boundary is inclusive', provider, brandedHeaders(), success,
    { now: PUBLIC_TIMESTAMP + 300 }));
  pushCase(providerCase('future window boundary is inclusive', provider, brandedHeaders(), success,
    { now: PUBLIC_TIMESTAMP - 300 }));
  pushCase(providerCase('one second past the window is expired', provider, brandedHeaders(),
    { ok: false, reason: 'timestamp-expired' }, { now: PUBLIC_TIMESTAMP + 301 }));
  pushCase(providerCase('one second before the future window is future', provider, brandedHeaders(),
    { ok: false, reason: 'timestamp-future' }, { now: PUBLIC_TIMESTAMP - 301 }));
  pushCase(providerCase('zero tolerance at the current instant', provider, brandedHeaders(), success,
    { toleranceSeconds: 0 }));
  pushCase(providerCase('zero tolerance rejects a one-second-old delivery', provider, brandedHeaders(),
    { ok: false, reason: 'timestamp-expired' }, { toleranceSeconds: 0, now: PUBLIC_TIMESTAMP + 1 }));
  pushCase(providerCase('wrong signature wins over a stale timestamp', provider,
    brandedHeaders(OTHER_SIGNATURE), { ok: false, reason: 'invalid-signature' },
    { now: PUBLIC_TIMESTAMP + 301 }));
  pushCase(providerCase('rotation list accepts a matching token', provider,
    brandedHeaders(`${OTHER_SIGNATURE} ${PUBLIC_SIGNATURE}`), success));
  pushCase(providerCase('rotation secret set accepts the retiring key', provider,
    brandedHeaders(OTHER_SIGNATURE), success, { secrets: [PUBLIC_SECRET, OTHER_SECRET] }));
  pushCase(providerCase('a removed rotation key is rejected', provider,
    brandedHeaders(OTHER_SIGNATURE), { ok: false, reason: 'invalid-signature' }));
  pushCase(providerCase('tampered body bytes', provider, brandedHeaders(),
    { ok: false, reason: 'invalid-signature' }, { bodyBase64: tamperedBody(PUBLIC_BODY_BASE64) }));
}

const coveredProviders = [...new Set(cases.map((entry) => entry.provider))].sort();

assert.deepEqual(coveredProviders, [...requiredProviders].sort(),
  'Workerd qualification must cover exactly the providers in the built registry.');

for (const provider of requiredProviders) {
  assert(cases.some((entry) => entry.provider === provider && entry.expected.ok),
    `Workerd qualification needs at least one passing case for ${provider}.`);
  assert(cases.some((entry) => entry.provider === provider
    && entry.expected.ok === false && entry.expected.reason === 'invalid-signature'),
  `Workerd qualification needs at least one tamper case for ${provider}.`);
}

const workerSource = `
  import { verifyRequest } from './src/index.ts';
  import { diagnose } from './src/diagnostics/index.ts';

  const cases = ${JSON.stringify(cases)};

  export default {
    async fetch(request) {
      const url = new URL(request.url);

      if (url.pathname === '/diagnostics') {
        return Response.json(diagnose({
          ok: false, provider: 'clerk', reason: 'invalid-signature', message: 'WORKER_PRIVATE_CANARY',
        }, { verbose: true }));
      }

      if (url.pathname === '/runtime') {
        return Response.json({
          userAgent: globalThis.navigator?.userAgent ?? 'unavailable',
          hasProcess: typeof process !== 'undefined',
          hasBuffer: typeof Buffer !== 'undefined',
        });
      }

      if (!url.pathname.startsWith('/case/')) return new Response('not found', { status: 404 });

      const index = Number(url.pathname.slice('/case/'.length));
      const testCase = cases[index];

      if (testCase === undefined) return new Response('not found', { status: 404 });

      const result = await verifyRequest(request, {
        provider: testCase.provider,
        secrets: testCase.options.secrets,
        ...(testCase.options.toleranceSeconds === undefined
          ? {} : { toleranceSeconds: testCase.options.toleranceSeconds }),
        now: () => testCase.options.now,
      });

      return Response.json(result.ok
        ? {
          ok: true,
          provider: result.provider,
          bytes: Array.from(result.rawBody),
          identity: result.identity,
        }
        : { ok: false, provider: result.provider, reason: result.reason });
    },
  };
`;

const bundled = await build({
  stdin: { contents: workerSource, resolveDir: root, sourcefile: 'all-providers-worker.js' },
  bundle: true,
  write: false,
  platform: 'neutral',
  format: 'esm',
  target: 'es2022',
  conditions: WORKER_CONDITIONS,
});

const bundleText = bundled.outputFiles[0].text;

const nodeImports = [...bundleText.matchAll(/(?:\bfrom\s+|\bimport\s*(?:\(\s*)?|\brequire\s*\(\s*)["'](node:[a-z0-9_./-]+)["']/gi)]
  .map((match) => match[1]);

assert.equal(nodeImports.length, 0,
  `Bundled Worker must not import Node builtins: ${[...new Set(nodeImports)].join(', ')}`);

assert.deepEqual(COMPATIBILITY_FLAGS, [], 'Workerd qualification must not enable Node compatibility flags.');

const tempDir = await mkdtemp(join(tmpdir(), 'hooklatch-workers-providers-'));
const bundlePath = join(tempDir, 'worker.mjs');

let runtime;
let failure = null;

try {
  await writeFile(bundlePath, bundleText);
  const relativeBundle = relative(tempDir, bundlePath);

  assert(!relativeBundle.startsWith('..') && !relativeBundle.includes('..'),
    'Bundled Worker must stay within the temporary module root.');

  runtime = new Miniflare({
    modules: true,
    modulesRoot: tempDir,
    scriptPath: bundlePath,
    compatibilityDate: COMPATIBILITY_DATE,
    compatibilityFlags: COMPATIBILITY_FLAGS,
  });

  const runtimeResponse = await runtime.dispatchFetch('https://example.test/runtime');
  const runtimeFacts = await runtimeResponse.json();

  assert.equal(runtimeFacts.userAgent, 'Cloudflare-Workers', 'Expected a real workerd runtime.');
  assert.equal(runtimeFacts.hasProcess, false, 'process must be unavailable in the Worker.');
  assert.equal(runtimeFacts.hasBuffer, false, 'Buffer must be unavailable in the Worker.');

  const diagnostic = await (await runtime.dispatchFetch('https://example.test/diagnostics')).json();
  assert.equal(diagnostic.code, 'invalid-signature');
  assert.equal(diagnostic.kind, 'verification');
  assert.equal(diagnostic.provider, 'clerk');
  assert(diagnostic.detail.expectedHeaders.includes('svix-signature'));
  assert(!JSON.stringify(diagnostic).includes('WORKER_PRIVATE_CANARY'));
  console.log('PASS: pure diagnostics run in real workerd without leaking input messages.');

  for (const [index, testCase] of cases.entries()) {
    const headers = new Headers();

    for (const [name, value] of Object.entries(testCase.headers)) {
      for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item);
    }

    const body = new Uint8Array(Buffer.from(testCase.bodyBase64, 'base64'));

    const response = await runtime.dispatchFetch(`https://example.test/case/${index}`, {
      method: 'POST',
      headers,
      body,
    });

    assert.equal(response.status, 200, `${testCase.id}: probe returned HTTP ${response.status}.`);
    const result = await response.json();

    assert.equal(result.ok, testCase.expected.ok, `${testCase.id}: unexpected ok value.`);
    assert.equal(result.provider, testCase.provider, `${testCase.id}: wrong provider.`);

    if (!testCase.expected.ok) {
      assert.equal(result.reason, testCase.expected.reason, `${testCase.id}: wrong failure reason.`);
      console.log(`PASS: ${testCase.id} -> ${result.reason}`);
    } else {
      assert.deepEqual(result.bytes, [...body], `${testCase.id}: returned bytes differ.`);

      if (testCase.expected.identity !== undefined) {
        assert.deepEqual(result.identity, testCase.expected.identity,
          `${testCase.id}: identity differs.`);
      }

      console.log(`PASS: ${testCase.id} -> ${result.provider}`);
    }
  }
} catch (error) {
  failure = error;
  console.error('');
  console.error(`RESULT: FAIL — ${error instanceof Error ? error.stack : String(error)}`);
} finally {
  if (runtime !== undefined) {
    try {
      await runtime.dispose();
    } catch (error) {
      failure ??= error;
      console.error(`failed to dispose miniflare: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  await rm(tempDir, { recursive: true, force: true });
  assert.equal(existsSync(tempDir), false, 'Temporary Worker module root was not removed.');
}

if (failure !== null) process.exit(1);

console.log('');

console.log(`PASS: ${cases.length} workerd provider cases across ${requiredProviders.length} providers.`);
