#!/usr/bin/env node
/**
 * Phase 11 Node 22.0 minimum-runtime consumer (big-pickle owner).
 *
 * Executed by scripts/phase11/runtime-floor.mjs inside a checked OS-temp
 * consumer root where the candidate tarball has been installed. This file is
 * the code that must run on the minimum supported runtime, so it imports only
 * Node builtins and the installed `hooklatch` package. It does not depend on
 * the repository, the harness, dev dependencies, polyfills, compatibility
 * flags or compile-time transformations.
 *
 * Usage:
 *   <node> phase11-floor-consumer.mjs --cli <installed dist/cli/index.js>
 *                                     --expect-exec-argv <json array>
 *
 * Prints exactly one `PHASE11_FLOOR_REPORT <json>` line. Exit 0 only when every
 * check passed. A failed check is reported honestly, never skipped or retried.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const nodeRequire = createRequire(import.meta.url);
const REPORT_PREFIX = 'PHASE11_FLOOR_REPORT ';
const NOW = 1800000000;
const TOLERANCE = 300;

/** Frozen public entry inventory: exact names, no additions or removals. */
const ENTRIES = Object.freeze([
  ['hooklatch', ['HooklatchError', 'createVerifier', 'verify', 'verifyRequest']],
  ['hooklatch/diagnostics', ['diagnose']],
  ['hooklatch/express', ['createWebhookMiddleware']],
  ['hooklatch/nextjs', ['createWebhookHandler']],
  ['hooklatch/cloudflare', ['createWebhookHandler']],
  ['hooklatch/hono', ['createWebhookMiddleware']],
]);

const GITHUB_SECRET = 'github-synthetic-secret';
const VERCEL_SECRET = 'vercel-synthetic-secret';
const GRAFANA_SECRET = 'grafana-synthetic-secret';
const POLAR_KEY = Buffer.from('phase11-polar-current-synthetic-key');
const POLAR_CURRENT_SECRET = `whsec_${POLAR_KEY.toString('base64')}`;
const GITHUB_DELIVERY = 'delivery-synthetic-1';
const GRAFANA_SIGNATURE_HEADER = 'x-synthetic-grafana-signature';
const GRAFANA_TIMESTAMP_HEADER = 'x-synthetic-grafana-time';

const SUCCESS_KEYS = ['identity', 'ok', 'provider', 'rawBody'];
const FAILURE_KEYS = ['message', 'ok', 'provider', 'reason'];

const GITHUB_IDENTITY = Object.freeze({
  deliveryId: GITHUB_DELIVERY,
  eventId: null,
  timestamp: null,
  authenticatedFields: [],
});

const encoder = new TextEncoder();

function objectTag(value) {
  return Object.prototype.toString.call(value);
}

function assertString(value, label) {
  assert.equal(objectTag(value), '[object String]', `${label}: expected a string value`);
}

function assertFunction(value, label) {
  assert.equal(value instanceof Function, true, `${label}: expected a function value`);
}

function utf8(text) {
  return encoder.encode(text);
}

function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function hmac(algorithm, key, content) {
  return createHmac(algorithm, key).update(content).digest();
}

function normalizePath(filePath) {
  return filePath.split(path.sep).join('/');
}

function bytesEqual(actual, expected) {
  return Buffer.from(actual).equals(Buffer.from(expected));
}

function buildRequest(rawBody, headerPairs) {
  return new Request('https://hooklatch.invalid/webhook', {
    method: 'POST',
    headers: headerPairs,
    body: rawBody,
  });
}

function listTree(root) {
  const entries = [];
  const pending = [root];

  while (pending.length > 0) {
    const current = pending.pop();
    const children = readdirSync(current, { withFileTypes: true });

    for (const child of children) {
      const childPath = path.join(current, child.name);

      entries.push(normalizePath(path.relative(root, childPath)));

      if (child.isDirectory()) pending.push(childPath);
    }
  }

  return entries.sort();
}

function parseArguments(argv) {
  const parsed = { cli: null, expectExecArgv: null };

  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];

    if (value === undefined) throw new Error(`Missing value for ${String(flag)}.`);

    if (flag === '--cli') parsed.cli = value;
    else if (flag === '--expect-exec-argv') parsed.expectExecArgv = JSON.parse(value);
    else throw new Error(`Unknown flag ${String(flag)}.`);
  }

  if (parsed.cli === null) throw new Error('--cli is required.');

  if (!Array.isArray(parsed.expectExecArgv)) throw new Error('--expect-exec-argv is required.');

  return parsed;
}

/* ------------------------------------------------------------------ *
 * Signing recipes (synthetic material; independent of package internals)
 * ------------------------------------------------------------------ */

function createFalCredentials() {
  const pair = generateKeyPairSync('ed25519');
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const raw = Buffer.from(jwk.x, 'base64url');

  assert.equal(raw.length, 32, 'fal public key must be exactly 32 raw bytes');

  return { privateKey: pair.privateKey, publicKeys: [new Uint8Array(raw)] };
}

function falHeaders({ requestId, userId, timestamp, privateKey, rawBody }) {
  const signed = utf8(`${requestId}\n${userId}\n${timestamp}\n${sha256Hex(rawBody)}`);
  const signature = sign(null, signed, privateKey);

  assert.equal(signature.length, 64, 'fal detached signature must be 64 bytes');

  return [
    ['x-fal-webhook-signature', signature.toString('hex')],
    ['x-fal-webhook-request-id', requestId],
    ['x-fal-webhook-user-id', userId],
    ['x-fal-webhook-timestamp', timestamp],
  ];
}

function githubHeaders(secret, rawBody, deliveryId = GITHUB_DELIVERY) {
  return [
    ['x-hub-signature-256', `sha256=${toHex(hmac('sha256', utf8(secret), rawBody))}`],
    ['x-github-delivery', deliveryId],
  ];
}

function vercelHeaders(secret, rawBody) {
  return [['x-vercel-signature', toHex(hmac('sha1', utf8(secret), rawBody))]];
}

function grafanaHeaders(secret, rawBody, timestampText) {
  const signed = Buffer.concat([Buffer.from(`${timestampText}:`, 'utf8'), Buffer.from(rawBody)]);

  return [
    [GRAFANA_SIGNATURE_HEADER, toHex(hmac('sha256', utf8(secret), signed))],
    [GRAFANA_TIMESTAMP_HEADER, timestampText],
  ];
}

function polarHeaders(key, rawBody, id, timestampText) {
  const signed = Buffer.concat([Buffer.from(`${id}.${timestampText}.`, 'utf8'), Buffer.from(rawBody)]);

  return [
    ['webhook-id', id],
    ['webhook-timestamp', timestampText],
    ['webhook-signature', `v1,${toBase64(hmac('sha256', key, signed))}`],
  ];
}

/* ------------------------------------------------------------------ *
 * Result assertions
 * ------------------------------------------------------------------ */

function assertVerificationResult(result, expected, label) {
  assert.notEqual(result, null, `${label}: result must not be null`);
  assert.equal(Array.isArray(result), false, `${label}: result must be a plain data object`);
  assert.equal(result.ok, expected.ok, `${label}: ok flag`);

  const wanted = expected.ok ? SUCCESS_KEYS : FAILURE_KEYS;

  assert.deepEqual(Object.keys(result).sort(), wanted, `${label}: exact result keys`);
  assert.equal(result.provider, expected.provider, `${label}: provider`);

  if (expected.ok) {
    assert.ok(result.rawBody instanceof Uint8Array, `${label}: rawBody must be a Uint8Array`);
    assert.ok(bytesEqual(result.rawBody, expected.rawBody), `${label}: exact rawBody bytes`);
    assert.deepEqual(result.identity, expected.identity, `${label}: exact identity`);
  } else {
    assert.equal(result.reason, expected.reason, `${label}: failure reason`);
    assertString(result.message, `${label}: failure message`);
    assert.ok(result.message.length > 0, `${label}: message must not be empty`);
    assert.equal(Object.hasOwn(result, 'rawBody'), false, `${label}: no rawBody on failure`);
  }
}

/* ------------------------------------------------------------------ *
 * Main collection
 * ------------------------------------------------------------------ */

async function collect({ cli, expectExecArgv }) {
  const checks = [];
  const namespaces = { import: new Map(), require: new Map() };

  async function check(id, run) {
    try {
      const detail = await run();

      checks.push({ id, ok: true, detail: detail === undefined ? null : detail });
    } catch (error) {
      checks.push({
        id,
        ok: false,
        error: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
      });
    }
  }

  assert.equal(existsSync(cli), true, `installed CLI entry must exist at ${cli}`);

  for (const [specifier] of ENTRIES) {
    namespaces.import.set(specifier, await import(specifier));
    namespaces.require.set(specifier, nodeRequire(specifier));
  }

  const coreImport = namespaces.import.get('hooklatch');
  const coreRequire = namespaces.require.get('hooklatch');
  const diagnosticsImport = namespaces.import.get('hooklatch/diagnostics');
  const resolution = { import: {}, require: {} };

  for (const [specifier] of ENTRIES) {
    resolution.import[specifier] = normalizePath(fileURLToPath(import.meta.resolve(specifier)));
    resolution.require[specifier] = normalizePath(nodeRequire.resolve(specifier));
  }

  async function expectResult(core, format, options, material, expected, label) {
    const direct = await core.verify({ rawBody: material.rawBody, headers: material.headers }, options);

    assertVerificationResult(direct, expected, `${label} [${format}/verify]`);

    const bound = core.createVerifier(options);
    const viaVerifier = await bound({ rawBody: material.rawBody, headers: material.headers });

    assertVerificationResult(viaVerifier, expected, `${label} [${format}/createVerifier]`);

    const viaRequest = await core.verifyRequest(buildRequest(material.rawBody, material.headers), options);

    assertVerificationResult(viaRequest, expected, `${label} [${format}/verifyRequest]`);

    return format;
  }

  async function expectBothFormats(options, material, expected, label) {
    const importEvidence = await expectResult(
      coreImport, 'import', options, material, expected, label,
    );

    const requireEvidence = await expectResult(
      coreRequire, 'require', options, material, expected, label,
    );

    return { formats: [importEvidence, requireEvidence], apis: ['verify', 'createVerifier', 'verifyRequest'] };
  }

  /* ---------------------------- environment ---------------------------- */

  await check('env-runtime-identity', () => {
    assert.equal(process.release.name, 'node');
    assert.equal(process.version, `v${process.versions.node}`);

    return { runtime: process.version, node: process.versions.node, v8: process.versions.v8, modules: process.versions.modules };
  });

  await check('env-exec-argv-exact', () => {
    assert.deepEqual(process.execArgv, expectExecArgv);

    return { execArgv: process.execArgv };
  });

  await check('env-no-compat-overrides', () => {
    assert.equal(process.env.NODE_OPTIONS, undefined, 'NODE_OPTIONS must not be set for the target runtime');

    return { nodeOptions: null };
  });

  await check('env-require-module-feature', () => {
    const feature = process.features.require_module;

    if (feature !== undefined) assert.equal(feature, false, 'require(esm) must be unavailable');

    return { requireModuleFeature: feature === undefined ? null : feature };
  });

  await check('env-resolution-commonjs', () => {
    const requireMain = resolution.require.hooklatch;

    assert.ok(requireMain.endsWith('/dist/cjs/index.cjs'), `unexpected require entry ${requireMain}`);

    for (const [specifier, file] of Object.entries(resolution.require)) {
      assert.ok(file.endsWith('.cjs'), `${specifier} must resolve to a .cjs file, got ${file}`);
      assert.ok(file.includes('/dist/cjs/'), `${specifier} must resolve inside dist/cjs, got ${file}`);
      assert.equal(existsSync(file), true, `${specifier} require target must exist`);
    }

    return { requireMain };
  });

  await check('env-resolution-esm-facades', () => {
    const importMain = resolution.import.hooklatch;

    assert.ok(importMain.endsWith('/dist/node/index.js'), `unexpected import entry ${importMain}`);

    for (const [specifier, file] of Object.entries(resolution.import)) {
      assert.ok(file.endsWith('.js'), `${specifier} must resolve to a .js facade, got ${file}`);
      assert.ok(file.includes('/dist/node/'), `${specifier} must resolve inside dist/node, got ${file}`);
      assert.equal(existsSync(file), true, `${specifier} import target must exist`);
    }

    return { importMain };
  });

  await check('env-no-peer-packages', () => {
    const installRoot = path.join(process.cwd(), 'node_modules');

    for (const peer of ['express', 'hono']) {
      assert.equal(existsSync(path.join(installRoot, peer)), false, `${peer} must not be installed`);
    }

    const loadedPeers = Object.keys(nodeRequire.cache).filter(
      (file) => /[\\/]node_modules[\\/](express|hono)[\\/]/.test(file),
    );

    assert.deepEqual(loadedPeers, [], 'core/diagnostics must not load optional peers');

    return { loadedPeers };
  });

  /* ------------------- six subpaths and shared identity ------------------- */

  await check('subpaths-import-inventory', () => {
    for (const [specifier, names] of ENTRIES) {
      assert.deepEqual(Object.keys(namespaces.import.get(specifier)).sort(), [...names].sort(), specifier);
    }

    return { entries: ENTRIES.length };
  });

  await check('subpaths-require-inventory', () => {
    for (const [specifier, names] of ENTRIES) {
      assert.deepEqual(Object.keys(namespaces.require.get(specifier)).sort(), [...names].sort(), specifier);
    }

    return { entries: ENTRIES.length };
  });

  await check('identity-cross-format', () => {
    const names = [];

    for (const [specifier, expected] of ENTRIES) {
      for (const name of expected) {
        assert.equal(
          namespaces.import.get(specifier)[name],
          namespaces.require.get(specifier)[name],
          `${specifier} ${name} must be the same reference in import and require`,
        );
        names.push(`${specifier}#${name}`);
      }
    }

    return { names };
  });

  await check('identity-error-instance-both-directions', async () => {
    let requireError = null;

    try {
      await coreRequire.verify({ rawBody: new Uint8Array(0), headers: [] }, { provider: 'stripe' });
    } catch (error) {
      requireError = error;
    }

    assert.ok(requireError instanceof coreImport.HooklatchError, 'require error must satisfy the import class');
    assert.equal(requireError.code, 'missing-secrets');

    let importError = null;

    try {
      await coreImport.verify({ rawBody: new Uint8Array(0), headers: [] }, { provider: 'stripe' });
    } catch (error) {
      importError = error;
    }

    assert.ok(importError instanceof coreRequire.HooklatchError, 'import error must satisfy the require class');
    assert.equal(importError.code, 'missing-secrets');

    return { code: requireError.code };
  });

  await check('identity-diagnostics-error', () => {
    let thrown = null;

    try {
      diagnosticsImport.diagnose(
        { ok: false, provider: 'github', reason: 'invalid-signature', message: 'synthetic' },
        { provider: 'stripe' },
      );
    } catch (error) {
      thrown = error;
    }

    assert.ok(thrown instanceof coreImport.HooklatchError, 'diagnostics mismatch must throw the shared error class');
    assert.equal(thrown.code, 'invalid-input');

    return { code: thrown.code };
  });

  await check('diagnostics-verification-detail', () => {
    const failure = {
      ok: false,
      provider: 'github',
      reason: 'invalid-signature',
      message: 'Webhook signature is invalid.',
    };

    const diagnostic = diagnosticsImport.diagnose(failure, { provider: 'github', verbose: true });

    assert.equal(diagnostic.code, 'invalid-signature');
    assert.equal(diagnostic.kind, 'verification');
    assert.equal(diagnostic.provider, 'github');
    assertString(diagnostic.summary, 'diagnostic summary');
    assert.ok(diagnostic.possibleCauses.length > 0, 'diagnostic causes must not be empty');
    assert.ok(diagnostic.suggestions.length > 0, 'diagnostic suggestions must not be empty');
    assert.deepEqual(diagnostic.detail.expectedHeaders, ['X-Hub-Signature-256']);
    assertString(diagnostic.detail.grammar, 'diagnostic grammar');

    return { code: diagnostic.code, headers: diagnostic.detail.expectedHeaders };
  });

  await check('diagnostics-setup-guidance', async () => {
    let error = null;

    try {
      await coreImport.verify({ rawBody: new Uint8Array(0), headers: [] }, { provider: 'github' });
    } catch (caught) {
      error = caught;
    }

    assert.ok(error instanceof coreImport.HooklatchError, 'missing secrets must throw the shared error class');

    const diagnostic = diagnosticsImport.diagnose(error, { provider: 'github' });

    assert.equal(diagnostic.code, 'missing-secrets');
    assert.equal(diagnostic.kind, 'setup');

    return { code: diagnostic.code, kind: diagnostic.kind };
  });

  /* ------------------------- real bound adapters ------------------------- */

  const githubBody = utf8('{"phase11":"github","octets":[0,1,2]}');

  const githubOptions = {
    provider: 'github',
    secrets: [GITHUB_SECRET],
    toleranceSeconds: TOLERANCE,
    now: () => NOW,
  };

  await check('adapter-express-bound', async () => {
    const body = utf8('{"phase11":"express-bound"}');
    const middleware = namespaces.require.get('hooklatch/express').createWebhookMiddleware(githubOptions);

    assertFunction(middleware, 'express middleware');
    assert.equal(middleware.length, 3, 'express middleware must accept (req, res, next)');

    const captured = { status: null, sent: null, next: 0 };
    const request = { headers: Object.fromEntries(githubHeaders(GITHUB_SECRET, body)), body };

    const response = {
      status(code) {
        captured.status = code;

        return this;
      },
      send(text) {
        captured.sent = text;

        return this;
      },
    };

    await middleware(request, response, () => {
      captured.next += 1;
    });

    assert.equal(captured.next, 1, 'middleware must call next()');
    assert.equal(captured.status, null, 'middleware must not reject a valid request');
    assert.equal(request.webhook.ok, true);
    assert.ok(bytesEqual(request.webhook.rawBody, body));

    return { next: captured.next };
  });

  await check('adapter-hono-bound', async () => {
    const body = utf8('{"phase11":"hono-bound"}');
    const middleware = namespaces.import.get('hooklatch/hono').createWebhookMiddleware(githubOptions);

    assertFunction(middleware, 'hono middleware');

    const captured = { key: null, value: null, next: 0 };

    const context = {
      req: { raw: buildRequest(body, githubHeaders(GITHUB_SECRET, body)) },
      set(key, value) {
        captured.key = key;
        captured.value = value;
      },
      text(text, status) {
        return new Response(text, { status });
      },
    };

    await middleware(context, async () => {
      captured.next += 1;
    });

    assert.equal(captured.next, 1);
    assert.equal(captured.key, 'webhook');
    assert.equal(captured.value.ok, true);
    assert.ok(bytesEqual(captured.value.rawBody, body));

    return { next: captured.next };
  });

  await check('adapter-nextjs-bound', async () => {
    const body = utf8('{"phase11":"nextjs-bound"}');

    const handler = namespaces.require.get('hooklatch/nextjs').createWebhookHandler({
      ...githubOptions,
      handler: (_request, success) => Response.json({ ok: success.ok, length: success.rawBody.byteLength }),
    });

    assertFunction(handler, 'nextjs handler');

    const response = await handler(buildRequest(body, githubHeaders(GITHUB_SECRET, body)));

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true, length: body.byteLength });

    return { status: response.status };
  });

  await check('adapter-cloudflare-bound', async () => {
    const body = utf8('{"phase11":"cloudflare-bound"}');

    const handler = namespaces.import.get('hooklatch/cloudflare').createWebhookHandler({
      options: () => githubOptions,
      handler: (_request, _env, _ctx, success) => Response.json({ ok: success.ok, length: success.rawBody.byteLength }),
    });

    assertFunction(handler, 'cloudflare handler');

    const response = await handler(buildRequest(body, githubHeaders(GITHUB_SECRET, body)), {}, {});

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true, length: body.byteLength });

    return { status: response.status };
  });

  /* ----------------------------- providers ----------------------------- */

  await check('provider-github-valid', () => expectBothFormats(
    githubOptions,
    { rawBody: githubBody, headers: githubHeaders(GITHUB_SECRET, githubBody) },
    { ok: true, provider: 'github', rawBody: githubBody, identity: GITHUB_IDENTITY },
    'github valid',
  ));

  await check('provider-github-tamper', () => {
    const tampered = new Uint8Array(githubBody);
    const headers = githubHeaders(GITHUB_SECRET, githubBody);

    tampered[tampered.length - 1] ^= 0x01;

    return expectBothFormats(
      githubOptions,
      { rawBody: tampered, headers },
      { ok: false, provider: 'github', reason: 'invalid-signature' },
      'github tampered',
    );
  });

  const vercelBody = utf8('{"phase11":"vercel"}');

  const vercelOptions = {
    provider: 'vercel',
    secrets: [VERCEL_SECRET],
    toleranceSeconds: TOLERANCE,
    now: () => NOW,
  };

  await check('provider-vercel-valid', () => expectBothFormats(
    vercelOptions,
    { rawBody: vercelBody, headers: vercelHeaders(VERCEL_SECRET, vercelBody) },
    {
      ok: true,
      provider: 'vercel',
      rawBody: vercelBody,
      identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
    'vercel valid (SHA-1)',
  ));

  await check('provider-vercel-tamper', () => {
    const tampered = new Uint8Array(vercelBody);

    tampered[0] ^= 0x20;

    return expectBothFormats(
      vercelOptions,
      { rawBody: tampered, headers: vercelHeaders(VERCEL_SECRET, vercelBody) },
      { ok: false, provider: 'vercel', reason: 'invalid-signature' },
      'vercel tampered',
    );
  });

  const fal = createFalCredentials();
  const falBody = utf8('{"phase11":"fal","user":"synthetic"}');
  const falUser = 'user_synthetic_1';
  const falRequest = 'request_synthetic_1';

  function falMaterial(timestampText, userId = falUser, body = falBody) {
    return {
      rawBody: body,
      headers: falHeaders({
        requestId: falRequest,
        userId,
        timestamp: timestampText,
        privateKey: fal.privateKey,
        rawBody: body,
      }),
    };
  }

  function falOptions(expectedUserId = falUser, toleranceSeconds = TOLERANCE, now = () => NOW) {
    return { provider: 'fal', publicKeys: fal.publicKeys, expectedUserId, toleranceSeconds, now };
  }

  function falIdentity(timestamp) {
    return { deliveryId: null, eventId: null, timestamp, authenticatedFields: ['timestamp'] };
  }

  await check('provider-fal-valid', () => expectBothFormats(
    falOptions(),
    falMaterial(String(NOW)),
    { ok: true, provider: 'fal', rawBody: falBody, identity: falIdentity(NOW) },
    'fal valid (Ed25519)',
  ));

  await check('provider-fal-tamper', () => {
    const tampered = new Uint8Array(falBody);

    tampered[1] ^= 0x04;

    return expectBothFormats(
      falOptions(),
      { rawBody: tampered, headers: falMaterial(String(NOW)).headers },
      { ok: false, provider: 'fal', reason: 'invalid-signature' },
      'fal tampered body',
    );
  });

  await check('provider-fal-wrong-account', () => expectBothFormats(
    falOptions('user_synthetic_2'),
    falMaterial(String(NOW)),
    { ok: false, provider: 'fal', reason: 'invalid-signature' },
    'fal valid signature for a different account',
  ));

  await check('provider-fal-boundary-expired', () => expectBothFormats(
    falOptions(),
    falMaterial(String(NOW - TOLERANCE - 1)),
    { ok: false, provider: 'fal', reason: 'timestamp-expired' },
    'fal one second past the tolerance',
  ));

  await check('provider-fal-boundary-expired-edge', () => expectBothFormats(
    falOptions(),
    falMaterial(String(NOW - TOLERANCE)),
    { ok: true, provider: 'fal', rawBody: falBody, identity: falIdentity(NOW - TOLERANCE) },
    'fal exactly at the past tolerance edge',
  ));

  await check('provider-fal-boundary-future', () => expectBothFormats(
    falOptions(),
    falMaterial(String(NOW + TOLERANCE + 1)),
    { ok: false, provider: 'fal', reason: 'timestamp-future' },
    'fal one second past the future tolerance',
  ));

  await check('provider-fal-boundary-future-edge', () => expectBothFormats(
    falOptions(),
    falMaterial(String(NOW + TOLERANCE)),
    { ok: true, provider: 'fal', rawBody: falBody, identity: falIdentity(NOW + TOLERANCE) },
    'fal exactly at the future tolerance edge',
  ));

  await check('provider-fal-zero-tolerance', async () => {
    const zero = 0;

    const accepted = await expectBothFormats(
      falOptions(falUser, zero),
      falMaterial(String(NOW)),
      { ok: true, provider: 'fal', rawBody: falBody, identity: falIdentity(NOW) },
      'fal explicit zero tolerance at the signed second',
    );

    const past = await expectBothFormats(
      falOptions(falUser, zero),
      falMaterial(String(NOW - 1)),
      { ok: false, provider: 'fal', reason: 'timestamp-expired' },
      'fal explicit zero tolerance, one second old',
    );

    const future = await expectBothFormats(
      falOptions(falUser, zero),
      falMaterial(String(NOW + 1)),
      { ok: false, provider: 'fal', reason: 'timestamp-future' },
      'fal explicit zero tolerance, one second ahead',
    );

    return { accepted, past, future };
  });

  const grafanaBody = utf8('{"phase11":"grafana","status":"firing"}');

  function grafanaOptions(toleranceSeconds = TOLERANCE, now = () => NOW) {
    return {
      provider: 'grafana',
      secrets: [GRAFANA_SECRET],
      toleranceSeconds,
      now,
      providerOptions: {
        mode: 'timestamped',
        signatureHeader: GRAFANA_SIGNATURE_HEADER,
        timestampHeader: GRAFANA_TIMESTAMP_HEADER,
      },
    };
  }

  await check('provider-grafana-timestamped-valid', () => expectBothFormats(
    grafanaOptions(),
    { rawBody: grafanaBody, headers: grafanaHeaders(GRAFANA_SECRET, grafanaBody, String(NOW)) },
    {
      ok: true,
      provider: 'grafana',
      rawBody: grafanaBody,
      identity: { deliveryId: null, eventId: null, timestamp: NOW, authenticatedFields: ['timestamp'] },
    },
    'grafana timestamped custom headers',
  ));

  await check('provider-grafana-timestamped-tamper', () => {
    const tampered = new Uint8Array(grafanaBody);

    tampered[tampered.length - 2] ^= 0x08;

    return expectBothFormats(
      grafanaOptions(),
      { rawBody: tampered, headers: grafanaHeaders(GRAFANA_SECRET, grafanaBody, String(NOW)) },
      { ok: false, provider: 'grafana', reason: 'invalid-signature' },
      'grafana timestamped tampered',
    );
  });

  await check('provider-grafana-timestamped-expired', () => expectBothFormats(
    grafanaOptions(),
    { rawBody: grafanaBody, headers: grafanaHeaders(GRAFANA_SECRET, grafanaBody, String(NOW - TOLERANCE - 1)) },
    { ok: false, provider: 'grafana', reason: 'timestamp-expired' },
    'grafana timestamped outside the past window',
  ));

  await check('provider-grafana-required-header', () => expectBothFormats(
    grafanaOptions(),
    {
      rawBody: grafanaBody,
      headers: [
        ['x-grafana-alerting-signature', toHex(hmac('sha256', utf8(GRAFANA_SECRET), grafanaBody))],
        [GRAFANA_TIMESTAMP_HEADER, String(NOW)],
      ],
    },
    { ok: false, provider: 'grafana', reason: 'missing-signature' },
    'grafana configured signature header is required',
  ));

  const polarBody = utf8('{"phase11":"polar"}');
  const polarId = 'msg_synthetic_1';
  const polarTimestamp = String(NOW);
  const polarIdentity = { deliveryId: null, eventId: polarId, timestamp: NOW, authenticatedFields: ['eventId', 'timestamp'] };

  const polarCurrentOptions = {
    provider: 'polar',
    secrets: [POLAR_CURRENT_SECRET],
    toleranceSeconds: TOLERANCE,
    now: () => NOW,
  };

  const polarLegacyOptions = {
    provider: 'polar',
    secrets: [POLAR_CURRENT_SECRET],
    toleranceSeconds: TOLERANCE,
    now: () => NOW,
    providerOptions: { secretMode: 'legacy' },
  };

  await check('provider-polar-current-valid', () => expectBothFormats(
    polarCurrentOptions,
    { rawBody: polarBody, headers: polarHeaders(POLAR_KEY, polarBody, polarId, polarTimestamp) },
    { ok: true, provider: 'polar', rawBody: polarBody, identity: polarIdentity },
    'polar current (standard webhooks)',
  ));

  await check('provider-polar-legacy-valid', () => expectBothFormats(
    polarLegacyOptions,
    {
      rawBody: polarBody,
      headers: polarHeaders(Buffer.from(POLAR_CURRENT_SECRET, 'utf8'), polarBody, polarId, polarTimestamp),
    },
    { ok: true, provider: 'polar', rawBody: polarBody, identity: polarIdentity },
    'polar legacy literal secret',
  ));

  await check('provider-polar-mode-separation', async () => {
    const legacySigned = polarHeaders(
      Buffer.from(POLAR_CURRENT_SECRET, 'utf8'), polarBody, polarId, polarTimestamp,
    );

    const currentSigned = polarHeaders(POLAR_KEY, polarBody, polarId, polarTimestamp);

    const rejectedCurrent = await expectBothFormats(
      polarCurrentOptions,
      { rawBody: polarBody, headers: legacySigned },
      { ok: false, provider: 'polar', reason: 'invalid-signature' },
      'polar current mode rejects a legacy-key signature',
    );

    const rejectedLegacy = await expectBothFormats(
      polarLegacyOptions,
      { rawBody: polarBody, headers: currentSigned },
      { ok: false, provider: 'polar', reason: 'invalid-signature' },
      'polar legacy mode rejects a current-key signature',
    );

    return { rejectedCurrent, rejectedLegacy };
  });

  /* --------------------------- exact offset view --------------------------- */

  const VIEW_PAYLOAD = new Uint8Array([0, 255, 195, 40, 123, 10, 128, 254]);

  function offsetView(fill) {
    const backing = Buffer.alloc(VIEW_PAYLOAD.length + 9, fill);

    backing.set(VIEW_PAYLOAD, 4);

    return { backing, view: new Uint8Array(backing.buffer, backing.byteOffset + 4, VIEW_PAYLOAD.length) };
  }

  await check('binary-offset-view-exact', async () => {
    const { view } = offsetView(0xa5);

    assert.notEqual(view.byteOffset, 0, 'the view must start at a non-zero byte offset');
    assert.equal(view.byteLength, VIEW_PAYLOAD.length);

    const material = { rawBody: view, headers: githubHeaders(GITHUB_SECRET, view) };

    const evidence = await expectBothFormats(
      githubOptions,
      material,
      { ok: true, provider: 'github', rawBody: VIEW_PAYLOAD, identity: GITHUB_IDENTITY },
      'exact binary offset view',
    );

    return { byteOffset: view.byteOffset, byteLength: view.byteLength, evidence };
  });

  await check('binary-offset-view-outside-tamper', async () => {
    const { backing, view } = offsetView(0x5a);
    const headers = githubHeaders(GITHUB_SECRET, view);

    backing[0] ^= 0xff;
    backing[backing.length - 1] ^= 0xff;

    const evidence = await expectBothFormats(
      githubOptions,
      { rawBody: view, headers },
      { ok: true, provider: 'github', rawBody: VIEW_PAYLOAD, identity: GITHUB_IDENTITY },
      'bytes outside the view do not participate',
    );

    return { evidence };
  });

  await check('binary-offset-view-inside-tamper', async () => {
    const { view } = offsetView(0x5a);
    const headers = githubHeaders(GITHUB_SECRET, view);

    view[0] ^= 0x01;

    const evidence = await expectBothFormats(
      githubOptions,
      { rawBody: view, headers },
      { ok: false, provider: 'github', reason: 'invalid-signature' },
      'a byte inside the view participates',
    );

    return { evidence };
  });

  /* -------------------------------- CLI -------------------------------- */

  const scratch = path.join(process.cwd(), 'cli-scratch');

  if (!existsSync(scratch)) mkdirSync(scratch, { recursive: true });

  function runCli(args) {
    return spawnSync(process.execPath, [cli, ...args], {
      cwd: scratch, encoding: 'utf8', timeout: 60000, windowsHide: true,
    });
  }

  await check('cli-help', () => {
    const result = runCli(['--help']);

    assert.equal(result.error, undefined, 'CLI --help must not fail to spawn');
    assert.equal(result.signal, null, 'CLI --help must not be signalled');
    assert.equal(result.status, 0, `CLI --help exit code, stderr: ${result.stderr}`);
    assert.match(result.stdout, /^Usage: hooklatch init webhook/);
    assert.ok(result.stdout.includes('--dry-run'), 'help must document --dry-run');
    assert.equal(result.stdout.includes('Created '), false, 'help must not print a creation line');

    return { status: result.status, runtime: process.version };
  });

  await check('cli-dry-run-github', () => {
    if (!existsSync(scratch)) mkdirSync(scratch, { recursive: true });

    const result = runCli([
      'init', 'webhook', '--provider', 'github', '--framework', 'express', '--dry-run', '--out', 'generated',
    ]);

    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, `CLI dry run exit code, stderr: ${result.stderr}`);
    assert.ok(result.stdout.includes('github.express.ts'), 'dry run prints the target relative path');
    assert.ok(result.stdout.includes('createWebhookMiddleware'), 'dry run prints the adapter import');
    assert.ok(result.stdout.includes('GITHUB_WEBHOOK_SECRET'), 'dry run prints the default secret env');
    assert.equal(existsSync(path.join(scratch, 'generated')), false, 'dry run must not create the output directory');

    return { status: result.status, runtime: process.version };
  });

  await check('cli-dry-run-fal', () => {
    if (!existsSync(scratch)) mkdirSync(scratch, { recursive: true });

    const result = runCli([
      'init', 'webhook', '--provider', 'fal', '--framework', 'cloudflare', '--dry-run', '--out', 'falg',
    ]);

    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, `CLI fal dry run exit code, stderr: ${result.stderr}`);
    assert.ok(result.stdout.includes('fal.cloudflare.ts'), 'dry run prints the fal target path');
    assert.ok(result.stdout.includes('FAL_WEBHOOK_PUBLIC_KEYS'), 'dry run prints the fal public key env');
    assert.ok(result.stdout.includes('FAL_WEBHOOK_USER_ID'), 'dry run prints the fal user env');
    assert.equal(existsSync(path.join(scratch, 'falg')), false);

    return { status: result.status, runtime: process.version };
  });

  await check('cli-no-writes', () => {
    if (!existsSync(scratch)) mkdirSync(scratch, { recursive: true });

    const before = listTree(scratch);

    const result = runCli([
      'init', 'webhook', '--provider', 'github', '--framework', 'nextjs', '--dry-run', '--out', 'route-dir',
    ]);

    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, `CLI dry run exit code, stderr: ${result.stderr}`);
    assert.deepEqual(listTree(scratch), before, 'dry runs must leave the working tree unchanged');
    assert.deepEqual(before, [], 'the scratch working tree must stay empty');

    rmSync(scratch, { recursive: true, force: true });
    assert.equal(existsSync(scratch), false, 'scratch must be removed');

    return { entries: before };
  });

  const failed = checks.filter((entry) => !entry.ok);

  return {
    kind: 'phase11-floor-consumer',
    runtime: process.version,
    platform: process.platform,
    arch: process.arch,
    execArgv: process.execArgv,
    versions: { node: process.versions.node, v8: process.versions.v8, modules: process.versions.modules },
    requireModuleFeature: process.features.require_module === undefined ? null : process.features.require_module,
    resolution,
    checks,
    summary: { total: checks.length, passed: checks.length - failed.length, failed: failed.length },
  };
}

function writeFailure(error) {
  const failure = {
    kind: 'phase11-floor-consumer',
    runtime: process.version,
    fatal: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
    checks: [],
    summary: { total: 0, passed: 0, failed: 0 },
  };

  process.stdout.write(`${REPORT_PREFIX}${JSON.stringify(failure)}\n`);
  process.exitCode = 1;
}

function main() {
  try {
    const { cli, expectExecArgv } = parseArguments(process.argv.slice(2));

    return collect({ cli, expectExecArgv }).then(
      (report) => {
        process.stdout.write(`${REPORT_PREFIX}${JSON.stringify(report)}\n`);
        process.exitCode = report.summary.failed === 0 ? 0 : 1;
      },
      (error) => {
        writeFailure(error);
      },
    );
  } catch (error) {
    writeFailure(error);

    return Promise.resolve();
  }
}

await main();
