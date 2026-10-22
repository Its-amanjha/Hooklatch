import { createHmac } from 'node:crypto';
import * as http from 'node:http';
import express from 'express';
import { Hono } from 'hono';

import { createWebhookMiddleware } from '../../src/adapters/express.js';
import { createWebhookHandler as createNextHandler } from '../../src/adapters/nextjs.js';
import { createWebhookHandler as createWorkerHandler } from '../../src/adapters/cloudflare.js';
import { createWebhookMiddleware as createHonoMiddleware } from '../../src/adapters/hono.js';
import { isTcpAddress } from './signing.js';

/**
 * Phase 7 Stage B repair — adapter configuration propagation and
 * setup-before-body-read regressions.
 *
 * Repair pass (2026-10-22): Grafana signatures are bare 64-hex (not
 * sha256= prefixed); Polar uses independent Base64/UTF-8 key derivation;
 * timestamped cases use a fixed `now` matching the synthetic timestamp.
 *
 * GREEN cases use the shipped GitHub provider. Grafana/Polar cases are written
 * against the frozen contract types and are RED at this base: 'grafana'/'polar'
 * are not yet in the Provider union and VerifyOptions has no providerOptions
 * field. Those RED failures are the expected contract-branch state, not defects
 * in this file. No cast of unregistered provider IDs is used.
 *
 * No production code, shared helper, config, or other test file is changed.
 */

const GITHUB_SECRET = 'phase7-adapter-config-canary-secret-7b3d2c';

type MutableSecrets = { secrets: string[] };

function hmacHex(bytes: Uint8Array, secret: string): string {
  return createHmac('sha256', secret).update(bytes).digest('hex');
}

function githubSig(bytes: Uint8Array, secret: string): string {
  return `sha256=${hmacHex(bytes, secret)}`;
}

function toBytes(text: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(new TextEncoder().encode(text));
}

function sendRaw(app: express.Express, body: Uint8Array, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, () => {
      const addr = server.address();

      if (!isTcpAddress(addr)) { server.close(); reject(new Error('Expected TCP server address'));

 return; }

      const port = addr.port;

      const req = http.request(
        { hostname: '127.0.0.1', port, path: '/', method: 'POST', headers: { 'content-type': 'application/octet-stream', ...headers } },
        (res) => {
          let data = '';
          res.on('data', (c: Buffer) => { data += c; });
          res.on('end', () => { server.close(); resolve({ status: res.statusCode ?? 0, body: data }); });
        },
      );

      req.on('error', (e) => { server.close(); reject(e); });
      req.write(Buffer.from(body));
      req.end();
    });
  });
}

// ---------------------------------------------------------------------------
// 1. Express: repeated normalization preserves configuration per request
// ---------------------------------------------------------------------------

test('express re-normalizes options on every request', async () => {
  const options = { provider: 'github' as const, secrets: [GITHUB_SECRET] };
  const app = express();
  app.use(createWebhookMiddleware(options));
  app.use((_req, res) => res.status(200).send('ok'));

  const first = await sendRaw(app, toBytes('hi'), { 'x-hub-signature-256': githubSig(toBytes('hi'), GITHUB_SECRET) });
  expect(first.status).toBe(200);

  // Mutate the shared options between requests.
  // SAFETY: the cast targets the known secrets array property on the options object.
  (options as MutableSecrets).secrets = ['changed-secret'];

  const second = await sendRaw(app, toBytes('hi'), { 'x-hub-signature-256': githubSig(toBytes('hi'), 'changed-secret') });
  expect(second.status).toBe(200);

  // Restore.
  // SAFETY: the cast targets the known secrets array property on the options object.
  (options as MutableSecrets).secrets = [GITHUB_SECRET];
});

test('express invalid config returns 500 before body read and does not call handler', async () => {
  const handlerCalled = { value: false };
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: [] }));
  app.use((_req, res) => { handlerCalled.value = true; res.status(200).send('ok'); });
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).send('Internal Server Error');
  });

  const r = await sendRaw(app, toBytes('hello'), { 'x-hub-signature-256': githubSig(toBytes('hello'), GITHUB_SECRET) });
  expect(r.status).toBe(500);
  expect(r.body).toBe('Internal Server Error');
  expect(handlerCalled.value).toBe(false);
});

test('express does not derive options from request headers', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: [GITHUB_SECRET] }));
  app.use((_req, res) => res.status(200).send('ok'));

  const r = await sendRaw(app, toBytes('hi'), {
    'x-hub-signature-256': githubSig(toBytes('hi'), 'wrong-secret'),
    'secrets': GITHUB_SECRET,
    'provider': 'github',
  });

  expect(r.status).toBe(400);
  expect(r.body).toBe('Bad Request');
});

test('express returns generic error bodies on setup failure', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: [] }));
  app.use((_req, res) => res.status(200).send('ok'));
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).send('Internal Server Error');
  });
  const r = await sendRaw(app, toBytes('hi'), { 'x-hub-signature-256': githubSig(toBytes('hi'), GITHUB_SECRET) });
  expect(r.status).toBe(500);
  expect(r.body).toBe('Internal Server Error');
});

// ---------------------------------------------------------------------------
// 2. Hono: per-request config
// ---------------------------------------------------------------------------

test('hono re-evaluates options on every request', async () => {
  const options = { provider: 'github' as const, secrets: [GITHUB_SECRET] };
  const app = new Hono();
  app.post('/webhook', createHonoMiddleware(options), (c) => c.text('ok', 200));

  const first = await app.request('/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSig(toBytes('hi'), GITHUB_SECRET) },
  });

  expect(first.status).toBe(200);

  // Mutate the shared options between requests.
  // SAFETY: the cast targets the known secrets array property on the options object.
  (options as MutableSecrets).secrets = ['changed-secret'];

  const second = await app.request('/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSig(toBytes('hi'), 'changed-secret') },
  });

  expect(second.status).toBe(200);

  // Restore.
  // SAFETY: the cast targets the known secrets array property on the options object.
  (options as MutableSecrets).secrets = [GITHUB_SECRET];
});

test('hono invalid config returns 500 and does not consume body', async () => {
  const app = new Hono();
  let called = false;
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [] }), (c) => {
    called = true;

    return c.text('ok', 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream' },
  });

  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(called).toBe(false);
});

test('hono does not derive options from request headers', async () => {
  const app = new Hono();
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [GITHUB_SECRET] }), (c) => c.text('ok', 200));

  const res = await app.request('/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSig(toBytes('hi'), 'wrong-secret'), 'secrets': GITHUB_SECRET },
  });

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
});

// ---------------------------------------------------------------------------
// 3. Next.js: construction-time snapshot
// ---------------------------------------------------------------------------

test('nextjs snapshots verifyOptions at construction', async () => {
  const options = { provider: 'github' as const, secrets: [GITHUB_SECRET], handler: async (_req: Request, success: { rawBody: Uint8Array }) => new Response(String(success.rawBody.byteLength), { status: 200 }) };

  const handler = createNextHandler(options);

  // Mutate the original options after construction.
  // SAFETY: the cast targets the known secrets array property on the options object.
  (options as MutableSecrets).secrets = ['changed-secret'];

  // The handler uses the snapshotted secret, so the original signature still verifies.
  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSig(toBytes('hi'), GITHUB_SECRET) },
  }));

  expect(res.status).toBe(200);
  expect(await res.text()).toBe('2');
});

test('nextjs invalid config returns 500 and does not consume body', async () => {
  const handler = createNextHandler({
    provider: 'github',
    secrets: [],
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream' },
  });

  const res = await handler(req);
  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(req.bodyUsed).toBe(false);
});

test('nextjs does not derive options from request headers', async () => {
  const handler = createNextHandler({
    provider: 'github',
    secrets: [GITHUB_SECRET],
    handler: async () => new Response('ok', { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSig(toBytes('hi'), 'wrong-secret'), 'secrets': GITHUB_SECRET },
  }));

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
});

// ---------------------------------------------------------------------------
// 4. Cloudflare: env resolver timing
// ---------------------------------------------------------------------------

test('cloudflare resolves env options per request', async () => {
  let currentSecret = GITHUB_SECRET;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [currentSecret] }),
    handler: async (_req, _env, _ctx, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });

  const first = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: toBytes('hi'),
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSig(toBytes('hi'), GITHUB_SECRET) },
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(first.status).toBe(200);

  // Change the env-derived secret between requests.
  currentSecret = 'changed-secret';

  const second = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: toBytes('hi'),
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSig(toBytes('hi'), 'changed-secret') },
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(second.status).toBe(200);
});

test('cloudflare env resolver throwing yields 500 without reading body', async () => {
  const handler = createWorkerHandler({
    options: () => { throw new Error('env resolution failed'); },
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream' },
  });

  const res = await handler(req, {}, { waitUntil: () => undefined });
  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(req.bodyUsed).toBe(false);
});

test('cloudflare invalid config returns 500 and does not consume body', async () => {
  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [] }),
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream' },
  });

  const res = await handler(req, {}, { waitUntil: () => undefined });
  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(req.bodyUsed).toBe(false);
});

test('cloudflare does not derive options from request headers', async () => {
  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [GITHUB_SECRET] }),
    handler: async () => new Response('ok', { status: 200 }),
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: toBytes('hi'),
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSig(toBytes('hi'), 'wrong-secret'), 'secrets': GITHUB_SECRET },
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
});

// ---------------------------------------------------------------------------
// 5. Grafana/Polar configuration forwarding (RED at this base)
// ---------------------------------------------------------------------------

// RED: 'grafana' and 'polar' are not in the Provider union at this base, and
// VerifyOptions has no providerOptions field. These tests will not compile and
// will fail at runtime with "Unsupported webhook provider." They are the
// contract-branch tests; they become green once Codex integrates the two
// providers. Do not cast unregistered provider IDs.

test('grafana body mode authenticates with default signature header', async () => {
  const handler = createNextHandler({
    provider: 'grafana',
    secrets: [GITHUB_SECRET],
    providerOptions: { mode: 'body' },
    handler: async (_req, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream', 'x-grafana-alerting-signature': 'd51444e75f143d82404d1fee9d2c5bb0ac250cde1671d5e32c391eabce56b17c' },
  }));

  expect(res.status).toBe(200);
  expect(await res.text()).toBe('2');
});

test('grafana body mode rejects a wrong signature header name', async () => {
  const handler = createNextHandler({
    provider: 'grafana',
    secrets: [GITHUB_SECRET],
    providerOptions: { mode: 'body', signatureHeader: 'x-custom-sig' },
    handler: async () => new Response('ok', { status: 200 }),
  });

  // Default header is present but the adapter is configured for x-custom-sig.
  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream', 'x-grafana-alerting-signature': 'd51444e75f143d82404d1fee9d2c5bb0ac250cde1671d5e32c391eabce56b17c' },
  }));

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
});

test('grafana timestamped mode authenticates with configured headers', async () => {
  const body = toBytes('hi');
  const timestamp = 1700000100;
  const signed = `${timestamp}:hi`;
  const sig = createHmac('sha256', GITHUB_SECRET).update(signed).digest('hex');

  const handler = createNextHandler({
    provider: 'grafana',
    secrets: [GITHUB_SECRET],
    providerOptions: { mode: 'timestamped', signatureHeader: 'x-grafana-alerting-signature', timestampHeader: 'x-grafana-timestamp' },
    handler: async (_req, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body,
    headers: { 'content-type': 'application/octet-stream', 'x-grafana-alerting-signature': sig, 'x-grafana-timestamp': String(timestamp) },
  }));

  expect(res.status).toBe(200);
  expect(await res.text()).toBe('2');
});

test('polar current mode authenticates a standard webhooks request', async () => {
  const secret = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
  const key = Buffer.from(secret.slice('whsec_'.length), 'base64');
  const id = 'msg_test';
  const ts = 1700000100;
  const body = 'hi';
  const sig = createHmac('sha256', key).update(`${id}.${ts}.${body}`).digest('base64');

  const handler = createNextHandler({
    provider: 'polar',
    secrets: [secret],
    providerOptions: { secretMode: 'current' },
    handler: async (_req, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes(body),
    headers: { 'content-type': 'application/octet-stream', 'webhook-id': id, 'webhook-timestamp': String(ts), 'webhook-signature': `v1,${sig}` },
  }));

  expect(res.status).toBe(200);
  expect(await res.text()).toBe('2');
});

test('polar legacy mode authenticates a standard webhooks request', async () => {
  const secret = 'polar-legacy-secret-xyz';
  const id = 'msg_test';
  const ts = 1700000100;
  const body = 'hi';
  const sig = createHmac('sha256', secret).update(`${id}.${ts}.${body}`).digest('base64');

  const handler = createNextHandler({
    provider: 'polar',
    secrets: [secret],
    providerOptions: { secretMode: 'legacy' },
    handler: async (_req, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes(body),
    headers: { 'content-type': 'application/octet-stream', 'webhook-id': id, 'webhook-timestamp': String(ts), 'webhook-signature': `v1,${sig}` },
  }));

  expect(res.status).toBe(200);
  expect(await res.text()).toBe('2');
});

test('polar cross-era: current-signed message rejected under legacy mode', async () => {
  const secret = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
  const key = Buffer.from(secret.slice('whsec_'.length), 'base64');
  const id = 'msg_test';
  const ts = 1700000100;
  const body = 'hi';
  const sig = createHmac('sha256', key).update(`${id}.${ts}.${body}`).digest('base64');

  const handler = createNextHandler({
    provider: 'polar',
    secrets: [secret],
    providerOptions: { secretMode: 'legacy' },
    handler: async () => new Response('ok', { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes(body),
    headers: { 'content-type': 'application/octet-stream', 'webhook-id': id, 'webhook-timestamp': String(ts), 'webhook-signature': `v1,${sig}` },
  }));

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
});

test('grafana invalid config returns 500 before body read', async () => {
  const handler = createNextHandler({
    provider: 'grafana',
    secrets: [GITHUB_SECRET],
    providerOptions: { mode: 'body', timestampHeader: 'x-ts' },
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream' },
  });

  const res = await handler(req);
  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(req.bodyUsed).toBe(false);
});

test('grafana handler receives verified bytes and exact signed identity', async () => {
  const body = toBytes('hi');

  const handler = createNextHandler({
    provider: 'grafana',
    secrets: [GITHUB_SECRET],
    providerOptions: { mode: 'body' },
    handler: async (_req, success) => new Response(JSON.stringify({ bytes: success.rawBody.byteLength, identity: success.identity }), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body,
    headers: { 'content-type': 'application/octet-stream', 'x-grafana-alerting-signature': hmacHex(body, GITHUB_SECRET) },
  }));

  expect(res.status).toBe(200);
  // SAFETY: the response body is produced by this test's own handler as
  // JSON.stringify of a fixed shape; the cast matches that known shape.
  const parsed = JSON.parse(await res.text()) as { bytes: number; identity: { deliveryId: null; eventId: null; timestamp: null; authenticatedFields: readonly string[] } };
  expect(parsed.bytes).toBe(2);
  expect(parsed.identity.deliveryId).toBeNull();
  expect(parsed.identity.eventId).toBeNull();
  expect(parsed.identity.timestamp).toBeNull();
  expect(parsed.identity.authenticatedFields).toEqual([]);
});

// Grafana own-undefined and throwing-getter traps (setup invalid -> 500, no leak).
test('grafana own-undefined providerOptions is invalid', async () => {
  const handler = createNextHandler({
    provider: 'grafana',
    secrets: [GITHUB_SECRET],
    providerOptions: { mode: 'body', signatureHeader: undefined },
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream' },
  });

  const res = await handler(req);
  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(req.bodyUsed).toBe(false);
});

test('grafana throwing getter in providerOptions yields generic 500', async () => {
  const options = {
    provider: 'grafana',
    secrets: [GITHUB_SECRET],
    get providerOptions() { throw new Error('secret getter boom'); },
    handler: async () => new Response('ok', { status: 200 }),
  };

  const handler = createNextHandler(options);

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: toBytes('hi'),
    headers: { 'content-type': 'application/octet-stream' },
  });

  const res = await handler(req);
  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(req.bodyUsed).toBe(false);
});

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------