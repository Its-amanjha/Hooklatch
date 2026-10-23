#!/usr/bin/env node
/**
 * Phase 10 CJS/ESM consumer matrix (Codebuff DeepSeek owner).
 *
 * Runs the REAL packaged candidates produced by scripts/phase10/cjs-prototype.mjs
 * through both provided Node 22 and Node 24 executables:
 *
 *   - `import` and `require` for all six public subpaths
 *   - core without peers and adapters with actual Express/Hono peers
 *   - independent TypeScript .mts/.cts compilation against candidate exports and
 *     declarations (core with types:[] and Web libs)
 *   - cross-subpath and cross-format HooklatchError identity (measured, not name-only)
 *   - optional-peer isolation and export encapsulation
 *   - node:crypto-signed GitHub, Vercel, fal, timestamped Grafana and legacy Polar
 *     cases through verify / verifyRequest / createVerifier
 *   - exact 21-provider inventory per format
 *
 * Exit: 0 qualified, 1 failure, 2 usage, 3 prerequisite BLOCKED.
 * PASS is printed only after scratch cleanup and tracked+dist integrity.
 */
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import {
  DEFAULT_RUNTIMES, ENTRY_POINTS, FORBIDDEN_SUBPATHS, PEER_PACKAGES, PEER_TYPE_PACKAGES,
  PROVIDERS, REPO_ROOT, PrerequisiteError, buildCjsEmit, buildEsmDist, classifyCompile,
  compareRunInputs, createCandidate, createWorkspace, disposeWorkspace, inspectCandidate,
  installConsumer, locateNpmCli, moduleGraph, packCandidate, pinnedToolPath, processHealth,
  resetProcessHealth, runChild, runNpm, runSync, snapshotRunInputs, snapshotTree, toolVersion,
} from './cjs-prototype.mjs';

/* ------------------------------------------------------------------ *
 * Generated consumer probes (written only into checked temp roots)
 * ------------------------------------------------------------------ */

const PROBE_IMPORT = `import process from 'node:process';

const [specifier, expectedJson] = process.argv.slice(2);
const expected = JSON.parse(expectedJson);
const forbidden = JSON.parse(process.env.PHASE10_FORBIDDEN ?? '[]');
const result = { ok: false, specifier, format: 'import', missing: [], forbidden: [], error: null };

try {
  const namespace = await import(specifier);

  result.exports = Object.keys(namespace).sort();
  result.missing = expected.filter((name) => !result.exports.includes(name));

  for (const blocked of forbidden) {
    try {
      await import(blocked);
      result.forbidden.push({ specifier: blocked, loaded: true, code: null });
    } catch (error) {
      result.forbidden.push({ specifier: blocked, loaded: false, code: error?.code ?? null });
    }
  }

  result.ok = result.missing.length === 0
    && result.forbidden.every((entry) => entry.loaded === false && entry.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED');
} catch (error) {
  result.error = { code: error?.code ?? null, name: error?.name ?? null, message: String(error?.message ?? error) };
}

console.log(JSON.stringify(result));
process.exit(result.ok ? 0 : 1);
`;

const PROBE_REQUIRE = `'use strict';
const process = require('node:process');

const [specifier, expectedJson] = process.argv.slice(2);
const expected = JSON.parse(expectedJson);
const forbidden = JSON.parse(process.env.PHASE10_FORBIDDEN ?? '[]');
const result = { ok: false, specifier, format: 'require', missing: [], forbidden: [], error: null };

try {
  const namespace = require(specifier);

  result.exports = Object.keys(namespace).sort();
  result.missing = expected.filter((name) => !result.exports.includes(name));

  for (const blocked of forbidden) {
    try {
      require(blocked);
      result.forbidden.push({ specifier: blocked, loaded: true, code: null });
    } catch (error) {
      result.forbidden.push({ specifier: blocked, loaded: false, code: error?.code ?? null });
    }
  }

  result.ok = result.missing.length === 0
    && result.forbidden.every((entry) => entry.loaded === false && entry.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED');
} catch (error) {
  result.error = { code: error?.code ?? null, name: error?.name ?? null, message: String(error?.message ?? error) };
}

console.log(JSON.stringify(result));
process.exit(result.ok ? 0 : 1);
`;

const DEEP_PROBE = `import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { createRequire } from 'node:module';
import process from 'node:process';

const KNOWN_PROVIDERS = CLOCK_PROVIDERS;
const BASE64_SECRET_PROVIDERS = new Set(['standard-webhooks', 'clerk', 'svix', 'dodo-payments', 'gitlab', 'replicate']);
const FORMAT = process.argv[2];
const NOW = 1800000000;

if (FORMAT !== 'import' && FORMAT !== 'require') {
  console.log(JSON.stringify({ ok: false, error: 'usage: deep.mjs <import|require>' }));
  process.exit(2);
}

const requireFromHere = createRequire(import.meta.url);
const load = (specifier) => FORMAT === 'import' ? import(specifier) : requireFromHere(specifier);
const checks = [];

const record = async (id, run) => {
  try {
    const detail = await run();
    checks.push({ id, ok: true, detail: detail === undefined ? null : detail });
  } catch (error) {
    checks.push({ id, ok: false, error: error instanceof Error ? error.message : String(error) });
  }
};

const hooklatch = await load('hooklatch');
const diagnostics = await load('hooklatch/diagnostics');
const BODY = new Uint8Array(Buffer.from(JSON.stringify({ event: 'phase10.synthetic', text: 'héllo 日本語 🚀' }), 'utf8'));

const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
const hmacHex = (hash, secret, bytes) => createHmac(hash, secret).update(bytes).digest('hex');

const inventoryOptions = (provider) => {
  if (provider === 'fal') return { provider, publicKeys: [new Uint8Array(32)], expectedUserId: 'phase10-synthetic-user' };
  if (provider === 'grafana') return { provider, secrets: ['phase10-grafana-synthetic-secret'], providerOptions: { mode: 'body' } };
  if (provider === 'polar') return { provider, secrets: [Buffer.alloc(32, 7).toString('base64')] };

  const secret = BASE64_SECRET_PROVIDERS.has(provider)
    ? Buffer.alloc(32, 9).toString('base64')
    : 'phase10-synthetic-literal-secret';

  return { provider, secrets: [secret] };
};

const assertTriplet = async (id, options, entries, identity) => {
  const viaVerify = await hooklatch.verify({ rawBody: BODY, headers: entries }, options);

  assert.equal(viaVerify.ok, true, id + ': verify failed: ' + JSON.stringify(viaVerify));
  assert.deepEqual([...viaVerify.rawBody], [...BODY], id + ': verify rawBody bytes differ');
  assert.deepEqual(viaVerify.identity, identity, id + ': verify identity mismatch');

  const request = new Request('https://synthetic.invalid/webhook', {
    method: 'POST', body: BODY, headers: Object.fromEntries(entries),
  });
  const viaRequest = await hooklatch.verifyRequest(request, options);

  assert.equal(viaRequest.ok, true, id + ': verifyRequest failed: ' + JSON.stringify(viaRequest));
  assert.deepEqual([...viaRequest.rawBody], [...BODY], id + ': verifyRequest rawBody bytes differ');

  const verifier = hooklatch.createVerifier(options);

  assert.equal(typeof verifier, 'function', id + ': createVerifier is not synchronous');
  assert.equal(verifier instanceof Promise, false, id + ': createVerifier returned a Promise');
  assert.equal(verifier.then, undefined, id + ': createVerifier returned a thenable');

  // Snapshot proof: mutate the caller-owned credential arrays after creation.
  if (Array.isArray(options.secrets)) options.secrets.push('phase10-mutated-extra-secret');
  if (Array.isArray(options.publicKeys)) options.publicKeys.push(new Uint8Array(32));

  const viaVerifier = await verifier({ rawBody: BODY, headers: entries });

  assert.equal(viaVerifier.ok, true, id + ': createVerifier snapshot broken');
  assert.deepEqual([...viaVerifier.rawBody], [...BODY], id + ': createVerifier rawBody bytes differ');

  return { identity: viaVerifier.identity };
};

await record('inventory.21-providers', async () => {
  for (const provider of KNOWN_PROVIDERS) {
    assert.equal(typeof hooklatch.createVerifier(inventoryOptions(provider)), 'function', provider + ': createVerifier');

    const diagnostic = diagnostics.diagnose({
      ok: false, provider, reason: 'invalid-signature', message: 'Synthetic verification failure.',
    }, { verbose: true });

    assert.equal(diagnostic.code, 'invalid-signature', provider + ': diagnostic code');
    assert.equal(diagnostic.kind, 'verification', provider + ': diagnostic kind');
    assert.equal(diagnostic.provider, provider, provider + ': diagnostic provider');
  }

  assert.throws(() => hooklatch.createVerifier({ provider: 'webflow', secrets: ['phase10-synthetic-literal-secret'] }),
    (error) => error?.code === 'unknown-provider' && error?.name === 'HooklatchError');
  assert.throws(() => diagnostics.diagnose({ ok: false, provider: 'webflow', reason: 'invalid-signature', message: 'x' }),
    (error) => error?.code === 'invalid-input');

  return { providers: KNOWN_PROVIDERS.length, order: KNOWN_PROVIDERS };
});

await record('github.node-crypto', async () => {
  const secret = 'phase10-github-synthetic-secret';
  const entries = [
    ['x-hub-signature-256', 'sha256=' + hmacHex('sha256', secret, BODY)],
    ['x-github-delivery', 'delivery-phase10-github'],
  ];
  const options = { provider: 'github', secrets: [secret] };
  const detail = await assertTriplet('github', options, entries, {
    deliveryId: 'delivery-phase10-github', eventId: null, timestamp: null, authenticatedFields: [],
  });

  const tampered = await hooklatch.verify({ rawBody: BODY.slice(0, BODY.length - 1), headers: entries }, options);

  assert.equal(tampered.ok, false, 'github: tampered body accepted');
  assert.equal(tampered.reason, 'invalid-signature', 'github: tampered body reason');
  assert.equal(diagnostics.diagnose(tampered).code, 'invalid-signature', 'github: diagnose(failure)');
  assert.equal(diagnostics.diagnose(tampered).provider, 'github', 'github: diagnose provider');

  return detail;
});

await record('vercel.node-crypto', async () => {
  const secret = 'phase10-vercel-synthetic-secret';
  const signature = createHmac('sha1', secret).update(BODY).digest('hex');
  const entries = [['x-vercel-signature', signature]];
  const options = { provider: 'vercel', secrets: [secret] };
  const detail = await assertTriplet('vercel', options, entries, {
    deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [],
  });

  assert.equal(signature.length, 40, 'vercel: expected a 20-byte SHA-1 signature');

  const tampered = await hooklatch.verify({ rawBody: new Uint8Array([...BODY, 0x21]), headers: entries }, options);

  assert.equal(tampered.ok, false, 'vercel: tampered body accepted');
  assert.equal(tampered.reason, 'invalid-signature', 'vercel: tampered body reason');

  return detail;
});

await record('fal.ed25519', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawPublic = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));

  assert.equal(rawPublic.byteLength, 32, 'fal: expected a raw 32-byte Ed25519 public key');

  const requestId = 'req-phase10-fal';
  const userId = 'user-phase10-fal';
  const timestamp = String(NOW);
  const content = new Uint8Array(Buffer.from(requestId + '\\n' + userId + '\\n' + timestamp + '\\n' + sha256Hex(BODY), 'utf8'));
  const entries = [
    ['x-fal-webhook-signature', sign(null, content, privateKey).toString('hex')],
    ['x-fal-webhook-request-id', requestId],
    ['x-fal-webhook-user-id', userId],
    ['x-fal-webhook-timestamp', timestamp],
  ];
  const options = { provider: 'fal', publicKeys: [rawPublic], expectedUserId: userId, now: () => NOW + 10 };
  const detail = await assertTriplet('fal', options, entries, {
    deliveryId: null, eventId: null, timestamp: NOW, authenticatedFields: ['timestamp'],
  });

  // Account before freshness: correct MAC but the wrong userId must be reported
  // as an invalid signature even when the timestamp is long expired.
  const wrongUser = { provider: 'fal', publicKeys: [rawPublic], expectedUserId: 'user-phase10-other', now: () => NOW + 100000 };
  const accountFailure = await hooklatch.verify({ rawBody: BODY, headers: entries }, wrongUser);

  assert.equal(accountFailure.ok, false, 'fal: wrong account accepted');
  assert.equal(accountFailure.reason, 'invalid-signature', 'fal: account must be checked before freshness');

  const stale = await hooklatch.verify({ rawBody: BODY, headers: entries },
    { provider: 'fal', publicKeys: [rawPublic], expectedUserId: userId, now: () => NOW + 100000 });
  const future = await hooklatch.verify({ rawBody: BODY, headers: entries },
    { provider: 'fal', publicKeys: [rawPublic], expectedUserId: userId, now: () => NOW - 100000 });

  assert.equal(stale.reason, 'timestamp-expired', 'fal: stale timestamp reason');
  assert.equal(future.reason, 'timestamp-future', 'fal: future timestamp reason');

  return detail;
});

await record('grafana.timestamped', async () => {
  const secret = 'phase10-grafana-synthetic-secret';
  const timestamp = String(NOW);
  const content = new Uint8Array(Buffer.concat([Buffer.from(timestamp + ':', 'utf8'), BODY]));
  const entries = [
    ['x-grafana-alerting-signature', hmacHex('sha256', secret, content)],
    ['x-grafana-timestamp', timestamp],
  ];
  const options = {
    provider: 'grafana', secrets: [secret],
    providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' }, now: () => NOW,
  };
  const detail = await assertTriplet('grafana', options, entries, {
    deliveryId: null, eventId: null, timestamp: NOW, authenticatedFields: ['timestamp'],
  });

  // Receiver configuration is snapshotted even if the caller mutates it later.
  const mutable = { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' };
  const verifier = hooklatch.createVerifier({ provider: 'grafana', secrets: [secret], providerOptions: mutable, now: () => NOW });

  mutable.mode = 'body';
  mutable.timestampHeader = 'x-phase10-mutated';

  assert.equal((await verifier({ rawBody: BODY, headers: entries })).ok, true, 'grafana: provider options were not snapshotted');

  // Authentication precedes freshness: a stale request with a bad MAC is not
  // reported as a timestamp failure.
  const wrongMac = [
    ['x-grafana-alerting-signature', hmacHex('sha256', 'phase10-wrong-secret', content)],
    ['x-grafana-timestamp', timestamp],
  ];
  const staleWrong = await hooklatch.verify({ rawBody: BODY, headers: wrongMac }, { ...options, now: () => NOW + 100000 });
  const staleRight = await hooklatch.verify({ rawBody: BODY, headers: entries }, { ...options, now: () => NOW + 100000 });

  assert.equal(staleWrong.reason, 'invalid-signature', 'grafana: MAC must be checked before freshness');
  assert.equal(staleRight.reason, 'timestamp-expired', 'grafana: stale timestamp reason');

  return detail;
});

await record('polar.legacy', async () => {
  // A literal secret with a whsec_ prefix is invalid under the current
  // Standard Webhooks decoder and valid only in legacy literal mode.
  const secret = 'whsec_phase10-polar-legacy-literal';
  const eventId = 'msg_phase10_polar';
  const timestamp = String(NOW);
  const content = new Uint8Array(Buffer.concat([Buffer.from(eventId + '.' + timestamp + '.', 'utf8'), BODY]));
  const entries = [
    ['webhook-id', eventId],
    ['webhook-timestamp', timestamp],
    ['webhook-signature', 'v1,' + createHmac('sha256', secret).update(content).digest('base64')],
  ];
  const options = { provider: 'polar', secrets: [secret], providerOptions: { secretMode: 'legacy' }, now: () => NOW };
  const detail = await assertTriplet('polar', options, entries, {
    deliveryId: null, eventId, timestamp: NOW, authenticatedFields: ['eventId', 'timestamp'],
  });

  let currentMode = null;
  try {
    hooklatch.createVerifier({ provider: 'polar', secrets: [secret], providerOptions: { secretMode: 'current' } });
  } catch (error) {
    currentMode = error;
  }

  assert.equal(currentMode?.code, 'invalid-secret', 'polar: current mode must reject the legacy literal secret');

  const wrongMac = [
    ['webhook-id', eventId],
    ['webhook-timestamp', timestamp],
    ['webhook-signature', 'v1,' + createHmac('sha256', 'phase10-wrong-secret').update(content).digest('base64')],
  ];
  const staleWrong = await hooklatch.verify({ rawBody: BODY, headers: wrongMac }, { ...options, now: () => NOW + 100000 });
  const staleRight = await hooklatch.verify({ rawBody: BODY, headers: entries }, { ...options, now: () => NOW + 100000 });

  assert.equal(staleWrong.reason, 'invalid-signature', 'polar: MAC must be checked before freshness');
  assert.equal(staleRight.reason, 'timestamp-expired', 'polar: stale timestamp reason');

  return detail;
});

console.log(JSON.stringify({
  ok: checks.every((check) => check.ok),
  format: FORMAT,
  node: process.version,
  requireModuleFeature: process.features.require_module === true,
  checks,
}));
process.exit(checks.every((check) => check.ok) ? 0 : 1);
`;

const IDENTITY_PROBE = `import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import process from 'node:process';

const requireFromHere = createRequire(import.meta.url);
const esmRoot = await import('hooklatch');
const esmDiagnostics = await import('hooklatch/diagnostics');
const cjsRoot = requireFromHere('hooklatch');
const cjsDiagnostics = requireFromHere('hooklatch/diagnostics');

const identity = {
  node: process.version,
  crossFormatClassIdentity: esmRoot.HooklatchError === cjsRoot.HooklatchError,
  crossFormatInstanceof: new cjsRoot.HooklatchError('invalid-input', 'synthetic') instanceof esmRoot.HooklatchError,
  crossFormatVerifyIdentity: esmRoot.verify === cjsRoot.verify,
  crossFormatCreateVerifierIdentity: esmRoot.createVerifier === cjsRoot.createVerifier,
  crossSubpathClassIdentity: [esmRoot.HooklatchError === esmRoot.HooklatchError, cjsRoot.HooklatchError === cjsRoot.HooklatchError],
  sameFormatDiagnoseAccepted: null,
  crossFormatDiagnoseAccepted: null,
  crossFormatDiagnoseErrorCode: null,
};

// Same format across subpaths: a root error must be accepted by diagnostics.
const esmError = new esmRoot.HooklatchError('invalid-input', 'synthetic');
const sameFormat = esmDiagnostics.diagnose(esmError);

identity.sameFormatDiagnoseAccepted = sameFormat.kind === 'setup';

// Cross format: the ESM error is handed to the CJS diagnostics copy. This is a
// behavioural probe, not a name comparison.
try {
  cjsDiagnostics.diagnose(esmError);
  identity.crossFormatDiagnoseAccepted = true;
} catch (error) {
  identity.crossFormatDiagnoseAccepted = false;
  identity.crossFormatDiagnoseErrorCode = error?.code ?? null;
}

assert.equal(identity.sameFormatDiagnoseAccepted, true, 'diagnose must accept a same-format HooklatchError');
console.log(JSON.stringify({ ok: true, identity }));
`;

const PEERS_PROBE = `import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import http from 'node:http';
import { createRequire } from 'node:module';
import process from 'node:process';

const FORMAT = process.argv[2];
if (FORMAT !== 'import' && FORMAT !== 'require') {
  console.log(JSON.stringify({ ok: false, error: 'usage: peers.mjs <import|require>' }));
  process.exit(2);
}

const requireFromHere = createRequire(import.meta.url);
const load = (specifier) => FORMAT === 'import' ? import(specifier) : Promise.resolve(requireFromHere(specifier));
const requirePeer = (specifier) => FORMAT === 'import' ? import(specifier) : Promise.resolve(requireFromHere(specifier));

const hooklatch = await load('hooklatch');
const expressAdapter = await load('hooklatch/express');
const honoAdapter = await load('hooklatch/hono');
const expressModule = await requirePeer('express');
const express = expressModule.default ?? expressModule;
const honoModule = await requirePeer('hono');
const Hono = honoModule.Hono;

const secret = 'phase10-peer-synthetic-secret';
const BODY = Buffer.from(JSON.stringify({ event: 'phase10.peer' }), 'utf8');
const signature = createHmac('sha256', secret).update(BODY).digest('hex');
const entries = {
  'x-hub-signature-256': 'sha256=' + signature,
  'x-github-delivery': 'delivery-phase10-peer',
};
const options = { provider: 'github', secrets: [secret] };
const checks = [];

// Real Express HTTP server with the real middleware and a real socket request.
{
  const app = express();

  app.post('/webhook', expressAdapter.createWebhookMiddleware(options), (request, response) => {
    response.json({ deliveryId: request.webhook.identity.deliveryId });
  });

  const server = app.listen(0, '127.0.0.1');
  const port = await new Promise((resolve, reject) => {
    server.once('listening', () => resolve(server.address().port));
    server.once('error', reject);
  });

  // node:http with agent:false instead of global fetch: it leaves no undici
  // keep-alive handle that could outlive the assertions in a newer runtime.
  const post = (requestHeaders) => new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1', port, path: '/webhook', method: 'POST', agent: false,
      headers: { ...requestHeaders, 'content-length': String(BODY.length) },
    }, (response) => {
      let text = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { text += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, text }));
    });
    request.on('error', reject);
    request.end(BODY);
  });

  try {
    const accepted = await post(entries);
    const payload = JSON.parse(accepted.text);

    assert.equal(accepted.status, 200, 'express: valid request status');
    assert.equal(payload.deliveryId, 'delivery-phase10-peer', 'express: identity not delivered');

    const rejected = await post({ ...entries, 'x-hub-signature-256': 'sha256=' + '0'.repeat(64) });

    assert.equal(rejected.status, 400, 'express: invalid signature status');
    checks.push({ id: 'express.real-server', ok: true });
  } finally {
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, 5000);
      server.close(() => { clearTimeout(timer); resolve(); });
    });
  }
}

// Real Hono app with the real middleware, driven through its request interface.
{
  const app = new Hono();

  app.use('/webhook', honoAdapter.createWebhookMiddleware(options));
  app.post('/webhook', (context) => context.json({ deliveryId: context.get('webhook').identity.deliveryId }));

  const accepted = await app.request('/webhook', { method: 'POST', body: BODY, headers: entries });
  const payload = await accepted.json();

  assert.equal(accepted.status, 200, 'hono: valid request status');
  assert.equal(payload.deliveryId, 'delivery-phase10-peer', 'hono: identity not delivered');

  const rejected = await app.request('/webhook', {
    method: 'POST', body: BODY, headers: { ...entries, 'x-hub-signature-256': 'sha256=' + '0'.repeat(64) },
  });

  assert.equal(rejected.status, 400, 'hono: invalid signature status');
  checks.push({ id: 'hono.real-app', ok: true });
}

console.log(JSON.stringify({ ok: checks.every((check) => check.ok), format: FORMAT, node: process.version, checks, hooklatchExports: Object.keys(hooklatch).sort() }));
process.exitCode = checks.every((check) => check.ok) ? 0 : 1;
`;

/* ------------------------------------------------------------------ *
 * Consumer files (compilation probes and tsconfigs)
 * ------------------------------------------------------------------ */

const CORE_PROBE = `import { verify, verifyRequest, createVerifier, HooklatchError } from 'hooklatch';
import type { VerificationResult, VerifyOptions } from 'hooklatch';
import { diagnose } from 'hooklatch/diagnostics';

const options: VerifyOptions = { provider: 'github', secrets: ['phase10-synthetic-literal-secret'] };

export const typed: VerifyOptions = options;
export const verifier = createVerifier(options);
export const verified: Promise<VerificationResult> = verify({ rawBody: new Uint8Array(), headers: {} }, options);
export const fromRequest: Promise<VerificationResult> = verifyRequest(new Request('https://synthetic.invalid/webhook'), options);
export const diagnostic = diagnose({ ok: false, provider: 'github', reason: 'invalid-signature', message: 'synthetic' });
export const failure = new HooklatchError('invalid-input', 'synthetic');
export const reason: string = diagnostic.code;
`;

const PEERS_PROBE_SOURCE = `import { createWebhookMiddleware as createExpressMiddleware } from 'hooklatch/express';
import { createWebhookHandler as createNextHandler } from 'hooklatch/nextjs';
import { createWebhookHandler as createWorkerHandler } from 'hooklatch/cloudflare';
import { createWebhookMiddleware as createHonoMiddleware } from 'hooklatch/hono';
import type { NextWebhookHandlerOptions } from 'hooklatch/nextjs';
import type { WorkerWebhookHandlerOptions } from 'hooklatch/cloudflare';
import type { VerifyOptions } from 'hooklatch';

const options: VerifyOptions = { provider: 'github', secrets: ['phase10-synthetic-literal-secret'] };

export const expressMiddleware = createExpressMiddleware(options);
export const honoMiddleware = createHonoMiddleware(options);
export const nextOptions: NextWebhookHandlerOptions = {
  provider: 'github', secrets: ['phase10-synthetic-literal-secret'], handler: () => new Response('ok'),
};
export const nextHandler = createNextHandler(nextOptions);
export const workerOptions: WorkerWebhookHandlerOptions = {
  options: () => options, handler: () => new Response('ok'),
};
export const workerHandler = createWorkerHandler(workerOptions);
`;

function compileConfig(include, { skipLibCheck = true } = {}) {
  return {
    compilerOptions: {
      target: 'ES2022',
      module: 'NodeNext',
      moduleResolution: 'NodeNext',
      lib: ['ES2022', 'DOM', 'DOM.Iterable'],
      types: [],
      strict: true,
      noUncheckedIndexedAccess: true,
      exactOptionalPropertyTypes: true,
      verbatimModuleSyntax: false,
      noEmit: true,
      skipLibCheck,
    },
    include,
  };
}

function writeConsumerFiles(root, { peers }) {
  const compileDir = path.join(root, 'compile');

  mkdirSync(compileDir, { recursive: true });
  writeFileSync(path.join(root, 'probe-import.mjs'), PROBE_IMPORT);
  writeFileSync(path.join(root, 'probe-require.cjs'), PROBE_REQUIRE);
  writeFileSync(path.join(root, 'deep.mjs'), DEEP_PROBE.replace('CLOCK_PROVIDERS', JSON.stringify(PROVIDERS)));
  writeFileSync(path.join(root, 'identity.mjs'), IDENTITY_PROBE);
  writeFileSync(path.join(compileDir, 'probe.mts'), peers ? PEERS_PROBE_SOURCE : CORE_PROBE);
  writeFileSync(path.join(compileDir, 'probe.cts'), peers ? PEERS_PROBE_SOURCE : CORE_PROBE);
  writeFileSync(path.join(compileDir, 'tsconfig.json'), `${JSON.stringify(compileConfig(['probe.mts', 'probe.cts']), null, 2)}\n`);

  if (peers) writeFileSync(path.join(root, 'peers.mjs'), PEERS_PROBE);
}

/* ------------------------------------------------------------------ *
 * Matrix
 * ------------------------------------------------------------------ */

const EXPECTED_IDENTITY = {
  'per-module-cjs': {
    crossFormatClassIdentity: false,
    crossFormatInstanceof: false,
    crossFormatVerifyIdentity: false,
    crossFormatDiagnoseAccepted: false,
    crossFormatDiagnoseErrorCode: 'invalid-input',
  },
  'require-bridge': {
    crossFormatClassIdentity: true,
    crossFormatInstanceof: true,
    crossFormatVerifyIdentity: true,
    crossFormatDiagnoseAccepted: true,
    crossFormatDiagnoseErrorCode: null,
  },
};

async function runtimeInfo(executable) {
  if (!existsSync(executable)) throw new PrerequisiteError(`Runtime executable missing: ${executable}`);

  const probe = await runChild(executable, ['-e', 'console.log(JSON.stringify({ version: process.versions.node, requireModule: process.features.require_module === true }))'], {
    cwd: REPO_ROOT, timeoutMs: 30000,
  });

  if (!probe.ok) throw new PrerequisiteError(`Runtime ${executable} cannot execute: ${probe.stderr.slice(0, 200)}`);

  const parsed = JSON.parse(probe.stdout.trim());

  return { executable, version: parsed.version, major: Number(parsed.version.split('.')[0]), requireModule: parsed.requireModule };
}

function prerequisites() {
  if (!existsSync(path.join(REPO_ROOT, 'src', 'index.ts'))) throw new PrerequisiteError('src/index.ts is absent.');

  const toolchain = {
    typescript: toolVersion('typescript'),
    esbuild: toolVersion('esbuild'),
    npmCli: locateNpmCli(),
  };

  const npmVersion = runSync(process.execPath, [toolchain.npmCli, '--version']);

  if (npmVersion.status !== 0) throw new PrerequisiteError('npm CLI is not runnable.');
  toolchain.npm = npmVersion.stdout.trim();

  for (const dependency of [...PEER_PACKAGES, ...PEER_TYPE_PACKAGES]) pinnedToolPath(dependency);

  return toolchain;
}

async function compileProbe({ executable, root, label, configName = 'tsconfig.json' }) {
  const tsc = path.join(pinnedToolPath('typescript'), 'bin', 'tsc');
  const config = path.join(root, 'compile', configName);
  const evidence = await runChild(executable, [tsc, '-p', config], { cwd: root, timeoutMs: 180000 });
  const classification = classifyCompile(evidence);

  return {
    label,
    runtime: executable,
    exitCode: evidence.exitCode,
    classification: classification.kind,
    diagnostics: classification.diagnostics,
    ok: classification.kind === 'clean',
  };
}

async function runMatrix({ toolchain, runtimes, report }) {
  const before = snapshotRunInputs();
  const workspace = createWorkspace();
  let baseline = before;
  const entries = [];
  const compiles = [];

  // Attach the progress arrays immediately so partial evidence survives a
  // mid-run infrastructure failure instead of vanishing with the report.
  report.entries = entries;
  report.compiles = compiles;

  const record = (entry) => {
    entries.push({ ...entry, ok: entry.ok === true });
  };

  try {
    const esmBuild = await buildEsmDist();
    const afterBuild = snapshotRunInputs();

    baseline = { tracked: before.tracked, dist: afterBuild.dist, head: before.head };

    const cjsBuild = await buildCjsEmit(workspace);

    const candidates = [
      createCandidate(workspace, 'per-module-cjs', cjsBuild),
      createCandidate(workspace, 'require-bridge'),
    ];

    const inspections = candidates.map((candidate) => inspectCandidate(candidate));

    for (const inspection of inspections) {
      if (!inspection.exportKeysExact) throw new Error(`${inspection.kind}: exports are not exactly the six public subpaths.`);

      if (inspection.missingTargets.length > 0) throw new Error(`${inspection.kind}: missing export targets ${JSON.stringify(inspection.missingTargets)}.`);

      if (inspection.declarations.unresolved.length > 0 || inspection.declarations.stale.length > 0) {
        throw new Error(`${inspection.kind}: broken declaration graph.`);
      }

      if (inspection.requires.unresolved.length > 0 || inspection.requires.esmSyntax.length > 0) {
        throw new Error(`${inspection.kind}: broken CJS runtime graph.`);
      }

      if (!inspection.peerIsolation) throw new Error(`${inspection.kind}: runtime dependencies are not empty.`);
    }

    const graph = moduleGraph();
    const coverage = [];

    for (const input of graph.inputs) {
      const relative = input.slice('src/'.length).replace(/\.ts$/, '');
      coverage.push({
        input,
        esm: existsSync(path.join(candidates[0].directory, 'dist', `${relative}.js`)),
        cjs: existsSync(path.join(candidates[0].directory, 'dist-cjs', `${relative}.cjs`)),
        cts: existsSync(path.join(candidates[0].directory, 'dist-cjs', `${relative}.d.cts`)),
      });
    }

    const uncovered = coverage.filter((entry) => !entry.esm || !entry.cjs || !entry.cts);

    if (uncovered.length > 0) throw new Error(`Module graph coverage failed: ${JSON.stringify(uncovered.slice(0, 5))}`);

    const packaged = [];

    for (const candidate of candidates) {
      const tarball = await packCandidate(candidate, workspace, toolchain.npmCli);

      packaged.push({ candidate, tarball });
    }

    if (new Set(packaged.map((entry) => entry.tarball.tarball)).size !== packaged.length) {
      throw new Error('Candidate tarballs collided on the same path.');
    }

    const consumers = new Map();

    for (const { candidate } of packaged) {
      for (const peers of [false, true]) {
        const name = `${candidate.kind}-${peers ? 'peers' : 'core'}`;

        const consumer = await installConsumer(workspace, {
          name, tarball: packaged.find((entry) => entry.candidate === candidate).tarball.tarball, peers, npmCli: toolchain.npmCli,
        });

        writeConsumerFiles(consumer.root, { peers });
        consumers.set(name, { ...consumer, candidate, peers });
      }
    }

    // One record per distinct consumer root: installs are runtime-independent.
    report.installs = [...consumers.values()].map((consumer) => ({
      name: `${consumer.candidate.kind}-${consumer.peers ? 'peers' : 'core'}`,
      exitCode: consumer.installExitCode,
      peersLinked: consumer.peers ? consumer.links.length : 0,
    }));

    // Optional-peer isolation: the core consumers must load all six subpaths
    // with no Express/Hono installation at all.
    report.peerIsolation = packaged.map(({ candidate }) => {
      const core = consumers.get(`${candidate.kind}-core`);
      const installedPeers = [...PEER_PACKAGES].filter((peer) => existsSync(path.join(core.root, 'node_modules', peer)));

      if (installedPeers.length > 0) {
        throw new Error(`${candidate.kind}: the core consumer unexpectedly contains peers: ${installedPeers.join(', ')}`);
      }

      return { candidate: candidate.kind, coreConsumerWithoutPeers: true, installedPeers: [] };
    });

    // Independent TypeScript compilation against the installed candidate.
    for (const runtime of runtimes) {
      for (const { candidate } of packaged) {
        for (const peers of [false, true]) {
          const name = `${candidate.kind}-${peers ? 'peers' : 'core'}`;
          const consumer = consumers.get(name);

          compiles.push(await compileProbe({ executable: runtime.executable, root: consumer.root, label: `${name}@${runtime.version}` }));
        }
      }
    }

    // Shallow matrix: every subpath, both formats, both runtimes.
    for (const runtime of runtimes) {
      for (const { candidate } of packaged) {
        const consumer = consumers.get(`${candidate.kind}-core`);
        const forbidden = JSON.stringify(FORBIDDEN_SUBPATHS);

        for (const entry of ENTRY_POINTS) {
          for (const format of ['import', 'require']) {
            const probeFile = format === 'import' ? 'probe-import.mjs' : 'probe-require.cjs';

            const evidence = await runChild(runtime.executable,
              [path.join(consumer.root, probeFile), `hooklatch${entry.subpath === '.' ? '' : entry.subpath.slice(1)}`, JSON.stringify(entry.exports)],
              { cwd: consumer.root, timeoutMs: 60000, env: { ...process.env, PHASE10_FORBIDDEN: forbidden } });

            let parsed = null;

            try {
              parsed = JSON.parse(evidence.stdout.trim());
            } catch {
              parsed = null;
            }

            record({
              area: 'subpath', candidate: candidate.kind, runtime: runtime.version, format, subpath: entry.subpath,
              ok: evidence.ok && parsed?.ok === true,
              detail: parsed === null
                ? { exitCode: evidence.exitCode, signal: evidence.signal, timedOut: evidence.timedOut, stderr: evidence.stderr.slice(0, 400) }
                : { ...parsed, exitCode: evidence.exitCode, signal: evidence.signal, timedOut: evidence.timedOut },
            });
          }
        }
      }
    }

    // Deep cases: inventory, provider protocols and ordering per format.
    for (const runtime of runtimes) {
      for (const { candidate } of packaged) {
        const consumer = consumers.get(`${candidate.kind}-core`);

        for (const format of ['import', 'require']) {
          const evidence = await runChild(runtime.executable, [path.join(consumer.root, 'deep.mjs'), format], {
            cwd: consumer.root, timeoutMs: 120000,
          });

          let parsed = null;

          try {
            parsed = JSON.parse(evidence.stdout.trim());
          } catch {
            parsed = null;
          }

          record({
            area: 'protocols', candidate: candidate.kind, runtime: runtime.version, format,
            ok: evidence.ok && parsed?.ok === true,
            detail: parsed === null
              ? { exitCode: evidence.exitCode, signal: evidence.signal, timedOut: evidence.timedOut, stderr: evidence.stderr.slice(0, 400) }
              : { ...parsed, exitCode: evidence.exitCode, signal: evidence.signal, timedOut: evidence.timedOut },
          });
        }
      }
    }

    // Identity probes, then compare against each candidate's design expectation.
    for (const runtime of runtimes) {
      for (const { candidate } of packaged) {
        const consumer = consumers.get(`${candidate.kind}-core`);

        const evidence = await runChild(runtime.executable, [path.join(consumer.root, 'identity.mjs')], {
          cwd: consumer.root, timeoutMs: 60000,
        });

        let parsed = null;

        try {
          parsed = JSON.parse(evidence.stdout.trim());
        } catch {
          parsed = null;
        }

        const expected = EXPECTED_IDENTITY[candidate.kind];
        const identity = parsed?.identity ?? null;

        const matches = identity !== null
          && identity.crossFormatClassIdentity === expected.crossFormatClassIdentity
          && identity.crossFormatInstanceof === expected.crossFormatInstanceof
          && identity.crossFormatVerifyIdentity === expected.crossFormatVerifyIdentity
          && identity.crossFormatDiagnoseAccepted === expected.crossFormatDiagnoseAccepted
          && identity.crossFormatDiagnoseErrorCode === expected.crossFormatDiagnoseErrorCode;

        record({
          area: 'identity', candidate: candidate.kind, runtime: runtime.version, format: 'cross-format',
          ok: evidence.ok && matches,
          detail: { expected, measured: identity },
        });
      }
    }

    // Real peer adapters.
    for (const runtime of runtimes) {
      for (const { candidate } of packaged) {
        const consumer = consumers.get(`${candidate.kind}-peers`);

        for (const format of ['import', 'require']) {
          const evidence = await runChild(runtime.executable, [path.join(consumer.root, 'peers.mjs'), format], {
            cwd: consumer.root, timeoutMs: 120000,
          });

          let parsed = null;

          try {
            parsed = JSON.parse(evidence.stdout.trim());
          } catch {
            parsed = null;
          }

          record({
            area: 'peers', candidate: candidate.kind, runtime: runtime.version, format,
            ok: evidence.ok && parsed?.ok === true,
            detail: parsed === null
              ? { exitCode: evidence.exitCode, signal: evidence.signal, timedOut: evidence.timedOut, stderr: evidence.stderr.slice(0, 400) }
              : { ...parsed, exitCode: evidence.exitCode, signal: evidence.signal, timedOut: evidence.timedOut, durationMs: evidence.durationMs },
          });
        }
      }
    }

    report.candidates = inspections;
    report.tarballs = packaged.map(({ candidate, tarball }) => ({ kind: candidate.kind, ...tarball }));
    report.moduleGraph = { version: graph.version, count: graph.count, coverage: coverage.length, uncovered: uncovered.length };
    report.esmBuild = { steps: esmBuild.length };
    report.cjsBuild = { modules: cjsBuild.renamed.scripts, declarations: cjsBuild.renamed.declarations };
    report.compilerSettings = compileConfig([]).compilerOptions;
    report.limitations = [
      'CJS remains a prototype: no package.json, exports, engines, dependencies or build configuration is changed by this task.',
      'The per-module CJS emit requires a temp type:commonjs source copy and .js->.cjs/.d.cts specifier rewriting; the repository build is untouched.',
      'The CJS emit covers the six exported subpaths; the CLI bin remains ESM-only in this prototype.',
      'Only Node 22.23.4 and 24.15.0 were executed. No Node 18/20 support and no generic Node >=22 require(esm) support is inferred.',
      'require(esm) is unflagged from Node 22.12.0; Node 22.0-22.11 needs --experimental-require-module, so the bridge candidate narrows engines to >=22.12.0.',
      'TypeScript 6.0.3 accepted the ESM declaration graph for .cts consumers in this pin; older compilers may require a .d.cts graph under the require condition.',
      'The matrix ran on win32 only; no cross-platform module-resolution claim is made.',
      'All provider cases are synthetic, locally signed with node:crypto. No live provider, account, registry or network call was made.',
      'The consumer projects use the repository default skipLibCheck:true; only the wrong-declaration-graph control disables it to observe TS2307.',
    ];
  } finally {
    const after = snapshotRunInputs();
    const problems = compareRunInputs(baseline, after);

    try {
      disposeWorkspace(workspace);
      report.cleanup = { scratchRemoved: true };
    } catch (error) {
      report.cleanup = { scratchRemoved: false, error: error.message };
      problems.push(`cleanup: ${error.message}`);
    }

    report.integrity = { problems, trackedDigestAfter: after.tracked.digest, distDigestAfter: after.dist.digest };
  }
}

/* ------------------------------------------------------------------ *
 * Controls
 * ------------------------------------------------------------------ */

async function controls({ toolchain, runtime, workspace }) {
  const results = {};

  {
    const esmBuild = await buildEsmDist();
    const cjsBuild = await buildCjsEmit(workspace);
    const candidate = createCandidate(workspace, 'per-module-cjs', cjsBuild);
    const tarball = await packCandidate(candidate, workspace, toolchain.npmCli);
    const consumer = await installConsumer(workspace, { name: 'controls-core', tarball: tarball.tarball, peers: false, npmCli: toolchain.npmCli });

    writeConsumerFiles(consumer.root, { peers: false });

    // Baseline: the real probe compiles cleanly.
    const clean = await compileProbe({ executable: runtime.executable, root: consumer.root, label: 'control-clean' });

    // A genuine type error must be classified as a compiler diagnostic.
    writeFileSync(path.join(consumer.root, 'compile', 'broken.cts'), "const broken: number = 'phase10';\nexport { broken };\n");
    writeFileSync(path.join(consumer.root, 'compile', 'tsconfig.json'),
      `${JSON.stringify(compileConfig(['probe.mts', 'probe.cts', 'broken.cts']), null, 2)}\n`);
    const diagnosed = await compileProbe({ executable: runtime.executable, root: consumer.root, label: 'control-diagnostic' });

    // A broken declaration graph must ALSO surface as a diagnostic, proving the
    // .d.cts graph is really consumed rather than the ESM declarations.
    writeFileSync(path.join(consumer.root, 'compile', 'tsconfig.json'),
      `${JSON.stringify(compileConfig(['probe.mts', 'probe.cts']), null, 2)}\n`);
    // An internal declaration reference is broken on purpose. The consumer
    // project uses the repository default skipLibCheck:true (which suppresses
    // errors INSIDE declaration files), so this control compiles probe.cts with
    // skipLibCheck:false to observe the TS2307. That proves the require-condition
    // .d.cts graph is the graph actually consumed, not the ESM declarations.
    writeFileSync(path.join(consumer.root, 'compile', 'tsconfig.wrong-graph.json'),
      `${JSON.stringify(compileConfig(['probe.cts'], { skipLibCheck: false }), null, 2)}\n`);
    const declarationFile = path.join(consumer.root, 'node_modules', 'hooklatch', 'dist-cjs', 'index.d.cts');
    const original = readFileSync(declarationFile, 'utf8');

    writeFileSync(declarationFile, original.replace('/core.cjs', '/core.js'));

    const wrongGraph = await compileProbe({
      executable: runtime.executable, root: consumer.root, label: 'control-wrong-graph', configName: 'tsconfig.wrong-graph.json',
    });

    writeFileSync(declarationFile, original);

    // Exit 2 with no diagnostic is infrastructure, not a type failure.
    const exitTwo = await runChild(runtime.executable, ['-e', 'process.exit(2)'], { cwd: consumer.root, timeoutMs: 30000 });
    const exitTwoClass = classifyCompile(exitTwo);

    // A timeout is its own class and must withhold cleanup. The control uses a
    // throwaway workspace so the outer workspace stays usable.
    resetProcessHealth();
    const timeoutWorkspace = createWorkspace('hooklatch-phase10-cjs-timeout-control-');

    const timeout = await runChild(runtime.executable, ['-e', 'setInterval(() => {}, 1000);'], {
      cwd: timeoutWorkspace.root, timeoutMs: 250,
    });

    const timeoutClass = classifyCompile(timeout);
    const timedOutUncertain = processHealth.uncertain;
    let withheld = false;

    try {
      disposeWorkspace(timeoutWorkspace);
    } catch (error) {
      withheld = /preserved/i.test(error.message);
    }

    const preservedExists = existsSync(timeoutWorkspace.root);

    resetProcessHealth();

    if (preservedExists) rmSync(timeoutWorkspace.root, { recursive: true, force: true });

    results.compileEvidence = {
      clean: { classification: clean.classification, diagnostics: clean.diagnostics },
      wrongUsage: { classification: diagnosed.classification, diagnostics: diagnosed.diagnostics },
      wrongDeclarationGraph: { classification: wrongGraph.classification, diagnostics: wrongGraph.diagnostics },
    };

    results.distDigestAfterBuild = snapshotTree(path.join(REPO_ROOT, 'dist'));
    results.compilerDiagnostic = {
      baselineClean: clean.ok,
      wrongUsageDiagnosed: diagnosed.classification === 'diagnostic' && diagnosed.ok === false,
      wrongDeclarationGraphDiagnosed: wrongGraph.classification === 'diagnostic' && wrongGraph.ok === false,
      exitTwoIsInfrastructure: exitTwoClass.kind === 'exit-2',
      timeoutIsInfrastructure: timeoutClass.kind === 'timeout',
      timeoutMarksUncertain: timedOutUncertain === true,
      timeoutWithheldCleanup: withheld && preservedExists,
    };
    results.compilerDiagnostic.discriminates = Object.entries(results.compilerDiagnostic)
      .filter(([key]) => key !== 'discriminates')
      .every(([, value]) => value === true);

    // Export-shape probe discrimination: an installed copy with disconnected
    // exports must fail the same shape check that passes on the real candidate.
    const disconnected = path.join(workspace.root, 'controls', 'disconnected');
    const disconnectedPackage = path.join(disconnected, 'node_modules', 'hooklatch');

    mkdirSync(disconnected, { recursive: true });
    writeFileSync(path.join(disconnected, 'package.json'), `${JSON.stringify({ name: 'phase10-control-disconnected', private: true })}\n`);
    writeFileSync(path.join(disconnected, 'probe-require.cjs'), PROBE_REQUIRE);

    const install = await runNpm(toolchain.npmCli,
      ['install', tarball.tarball, '--no-save', '--ignore-scripts', '--offline', '--no-audit', '--no-fund', '--legacy-peer-deps'],
      disconnected, workspace);

    assert.equal(install.exitCode, 0, 'control install failed');
    assert(existsSync(disconnectedPackage), 'control package was not installed');

    const baselineProbe = await runChild(runtime.executable, [path.join(consumer.root, 'probe-require.cjs'), 'hooklatch', JSON.stringify(ENTRY_POINTS[0].exports)], {
      cwd: consumer.root, env: { ...process.env, PHASE10_FORBIDDEN: '[]' }, timeoutMs: 60000,
    });

    writeFileSync(path.join(disconnectedPackage, 'dist-cjs', 'index.cjs'), "'use strict';\nmodule.exports = {};\n");

    const disconnectedProbe = await runChild(runtime.executable, [path.join(disconnected, 'probe-require.cjs'), 'hooklatch', JSON.stringify(ENTRY_POINTS[0].exports)], {
      cwd: disconnected, env: { ...process.env, PHASE10_FORBIDDEN: '[]' }, timeoutMs: 60000,
    });

    results.disconnectedExports = {
      baselinePasses: baselineProbe.ok,
      detected: !disconnectedProbe.ok,
    };
    results.disconnectedExports.discriminates = results.disconnectedExports.baselinePasses && results.disconnectedExports.detected;

    results.controlHealthReset = processHealth.uncertain === false;
    results.esmBuildSteps = esmBuild.length;
    results.controlsPassed = results.compilerDiagnostic.discriminates
      && results.disconnectedExports.discriminates
      && results.controlHealthReset;
  }

  resetProcessHealth();

  return results;
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

function usage() {
  console.log('Usage: node scripts/phase10/cjs-consumers.mjs [--json] [--self-test] [--out <file>] [--help]');
  console.log('Exit 0 the actual Node22/24 consumer matrix qualified, 1 failure, 2 usage, 3 prerequisite blocked.');
  console.log('Discovers the two runtimes from the Phase10 manifest defaults (PHASE10_NODE22/PHASE10_NODE24 override).');
  console.log('PASS is printed only after scratch cleanup and tracked+dist integrity checks.');
}

function parseArgs(args) {
  const options = { json: false, selfTest: false, help: false, out: null };
  const seen = new Set();

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];

    if (seen.has(arg)) return { error: `duplicate argument: ${arg}` };
    seen.add(arg);

    if (arg === '--json') options.json = true;
    else if (arg === '--self-test') options.selfTest = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--out') {
      const value = args[index + 1];

      if (!value || value.startsWith('--')) return { error: '--out requires a file path' };
      options.out = value;
      index += 1;
    } else return { error: `unknown argument: ${arg}` };
  }

  return { options };
}

function summarise(report) {
  const entries = report.entries ?? [];

  return {
    status: report.status,
    runtime: report.runtimes,
    candidates: report.candidates?.map((candidate) => ({
      kind: candidate.kind,
      declarationFiles: candidate.declarations.files,
      cjsModules: candidate.requires.files,
      packageBytes: candidate.packageBytes,
    })),
    compiles: report.compiles?.map((compile) => ({ label: compile.label, clean: compile.ok, classification: compile.classification })),
    totals: {
      total: entries.length,
      passed: entries.filter((entry) => entry.ok).length,
      failed: entries.filter((entry) => !entry.ok).length,
    },
    failures: entries.filter((entry) => !entry.ok).map((entry) => ({
      area: entry.area, candidate: entry.candidate, runtime: entry.runtime, format: entry.format,
      subpath: entry.subpath ?? null, detail: entry.detail ?? entry.error ?? null,
    })),
    identity: entries.filter((entry) => entry.area === 'identity').map((entry) => ({
      candidate: entry.candidate, runtime: entry.runtime, ok: entry.ok, measured: entry.detail?.measured ?? null,
    })),
    cleanup: report.cleanup,
    integrity: report.integrity,
  };
}

async function main() {
  const parsed = parseArgs(process.argv.slice(2));

  if (parsed.error) {
    console.error(parsed.error);
    usage();

    return 2;
  }

  if (parsed.options.help) {
    usage();

    return 0;
  }

  let report;
  let exitCode = 0;

  try {
    const toolchain = prerequisites();
    const runtimes = [await runtimeInfo(DEFAULT_RUNTIMES.node22), await runtimeInfo(DEFAULT_RUNTIMES.node24)];

    for (const runtime of runtimes) {
      assert(runtime.major === 22 || runtime.major === 24, `Unexpected runtime major: ${runtime.version}`);
    }

    if (new Set(runtimes.map((runtime) => runtime.major)).size !== 2) {
      throw new PrerequisiteError('The two runtime executables are not distinct Node majors.');
    }

    report = {
      status: 'RUNNING',
      phase: '10',
      owner: 'deepseek-codebuff',
      generatedAt: new Date().toISOString(),
      toolchain: { node: process.version, npm: toolchain.npm, typescript: toolchain.typescript, esbuild: toolchain.esbuild },
      runtimes: runtimes.map((runtime) => ({
        executable: runtime.executable, version: runtime.version, major: runtime.major, requireModule: runtime.requireModule,
      })),
      installs: [],
      cleanup: null,
      integrity: null,
    };

    if (parsed.options.selfTest) {
      const beforeControls = snapshotRunInputs();
      const workspace = createWorkspace('hooklatch-phase10-cjs-controls-');
      let results;

      try {
        results = await controls({ toolchain, runtime: runtimes[1], workspace });
      } finally {
        // Cleanup failure is a run failure: it propagates as FAILED, never a
        // silent success or a preserved scratch directory without a report.
        disposeWorkspace(workspace);
        report.cleanup = { scratchRemoved: true };
      }

      const afterControls = snapshotRunInputs();

      const problems = compareRunInputs({
        tracked: beforeControls.tracked, dist: results.distDigestAfterBuild, head: beforeControls.head,
      }, afterControls);

      report.integrity = { problems, trackedDigestAfter: afterControls.tracked.digest, distDigestAfter: afterControls.dist.digest };
      report.status = results.controlsPassed && problems.length === 0 ? 'CONTROLS_PASSED' : 'FAILED';
      report.controls = { ...results, workspaceRootInsideTemp: workspace.root };
      exitCode = report.status === 'CONTROLS_PASSED' ? 0 : 1;
    } else {
      await runMatrix({ toolchain, runtimes, report });

      const entries = report.entries ?? [];
      const compiles = report.compiles ?? [];

      const allPassed = entries.length > 0 && entries.every((entry) => entry.ok)
        && compiles.length > 0 && compiles.every((compile) => compile.ok)
        && report.integrity.problems.length === 0
        && report.cleanup.scratchRemoved === true;

      report.status = allPassed ? 'PASS' : 'FAILED';
      report.totals = {
        entries: entries.length,
        passed: entries.filter((entry) => entry.ok).length,
        failed: entries.filter((entry) => !entry.ok).length,
        compiles: compiles.length,
        compilesClean: compiles.filter((compile) => compile.ok).length,
        installs: report.installs.length,
      };
      report.findings = {
        dualPackageHazard: entries
          .filter((entry) => entry.area === 'identity' && entry.detail?.measured !== null)
          .map((entry) => ({
            candidate: entry.candidate, runtime: entry.runtime,
            classIdentity: entry.detail.measured.crossFormatClassIdentity,
            instanceofIdentity: entry.detail.measured.crossFormatInstanceof,
            crossFormatDiagnoseAccepted: entry.detail.measured.crossFormatDiagnoseAccepted,
          })),
        requireEsm: {
          runtimeSupport: report.runtimes.map((runtime) => ({ version: runtime.version, requireModule: runtime.requireModule })),
          documentedFloor: 'Unflagged require(esm) starts at Node 22.12.0 (and 20.19.0); 22.0-22.11 require --experimental-require-module.',
        },
        declarationGraph: {
          perModuleCjs: report.candidates.find((candidate) => candidate.kind === 'per-module-cjs')?.declarations,
          requireBridge: report.candidates.find((candidate) => candidate.kind === 'require-bridge')?.declarations,
        },
      };

      exitCode = allPassed ? 0 : 1;
    }
  } catch (error) {
    if (error instanceof PrerequisiteError) {
      report = { status: 'BLOCKED', reason: error.message, phase: '10', owner: 'deepseek-codebuff' };
      exitCode = 3;
    } else {
      report = {
        status: 'FAILED',
        phase: '10',
        owner: 'deepseek-codebuff',
        error: error instanceof Error ? (error.stack ?? error.message) : String(error),
      };
      exitCode = 1;
    }
  }

  if (parsed.options.out) {
    const destination = path.resolve(REPO_ROOT, parsed.options.out);

    mkdirSync(path.dirname(destination), { recursive: true });
    writeFileSync(destination, `${JSON.stringify(report, null, 2)}\n`);
  }

  if (parsed.options.json) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(JSON.stringify(summarise(report), null, 2));

    if (report.status === 'PASS') {
      console.log(`PASS: ${report.totals.entries} matrix entries and ${report.totals.compilesClean}/${report.totals.compiles} compiles passed on Node ${report.runtimes.map((runtime) => runtime.version).join(' and ')}; scratch removed and tracked/dist bytes unchanged.`);
    } else console.log(`${report.status}: consumer matrix did not qualify.`);
  }

  return exitCode;
}

try {
  process.exitCode = await main();
} catch (error) {
  console.log(JSON.stringify({
    status: 'FAILED', error: error instanceof Error ? (error.stack ?? error.message) : String(error),
  }));
  process.exitCode = 1;
}
