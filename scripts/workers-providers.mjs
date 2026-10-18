import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';

/**
 * Real-workerd qualification for every supported provider.
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
const REQUIRED_PROVIDERS = ['stripe', 'github', 'shopify', 'standard-webhooks', 'clerk', 'svix'];
const ORIGINAL_PROVIDERS = ['stripe', 'github', 'shopify', 'standard-webhooks'];
const NEW_PROVIDERS = ['clerk', 'svix'];
const WORKER_CONDITIONS = ['workerd', 'worker', 'browser'];
const COMPATIBILITY_DATE = '2026-08-06';
const COMPATIBILITY_FLAGS = [];
const UNSIGNED_OR_NULL = 'unsigned-or-null';

const cases = [];

async function fixtureFile(provider) {
  return JSON.parse(await readFile(resolve(root, 'tests/fixtures', `${provider}.json`), 'utf8'));
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

  if (resolved.deliveryId === UNSIGNED_OR_NULL) {
    resolved.deliveryId = provider === 'github'
      ? headerValue(fixture.request.headers, 'x-github-delivery')
      : headerValue(fixture.request.headers, 'x-shopify-webhook-id');
  }

  if (resolved.eventId === UNSIGNED_OR_NULL) {
    resolved.eventId = headerValue(fixture.request.headers, 'x-shopify-event-id');
  }

  return resolved;
}

function pushCase(entry) {
  cases.push(entry);
}

for (const provider of ORIGINAL_PROVIDERS) {
  const file = await fixtureFile(provider);
  const fixture = file.cases.find((entry) => entry.expected.ok && entry.request.bodyBase64);
  assert(fixture, `Missing positive runtime fixture for ${provider}.`);

  pushCase({
    id: `${provider}: positive fixture`,
    provider,
    headers: fixture.request.headers,
    bodyBase64: fixture.request.bodyBase64,
    options: {
      secrets: fixture.options.secrets,
      toleranceSeconds: fixture.options.toleranceSeconds ?? 300,
      now: fixture.options.now,
    },
    expected: { ok: true, identity: resolveFixtureIdentity(provider, fixture) },
  });

  pushCase({
    id: `${provider}: tampered body bytes`,
    provider,
    headers: fixture.request.headers,
    bodyBase64: tamperedBody(fixture.request.bodyBase64),
    options: {
      secrets: fixture.options.secrets,
      toleranceSeconds: fixture.options.toleranceSeconds ?? 300,
      now: fixture.options.now,
    },
    expected: { ok: false, reason: 'invalid-signature' },
  });
}

const standardWebhooks = await fixtureFile('standard-webhooks');

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

for (const provider of NEW_PROVIDERS) {
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

assert.deepEqual(coveredProviders, [...REQUIRED_PROVIDERS].sort(),
  'Workerd qualification must cover exactly the supported provider set.');

for (const provider of REQUIRED_PROVIDERS) {
  assert(cases.some((entry) => entry.provider === provider && entry.expected.ok),
    `Workerd qualification needs at least one passing case for ${provider}.`);
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
        toleranceSeconds: testCase.options.toleranceSeconds,
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

console.log(`PASS: ${cases.length} workerd provider cases across ${REQUIRED_PROVIDERS.length} providers.`);
