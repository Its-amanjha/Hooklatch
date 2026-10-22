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
 * Phase 8 Stage A — Linear adapter-isolation regressions.
 *
 * Linear is NOT registered at this base (18 providers; target 19). Tests use
 * `provider: 'linear'` directly, which is a type error and fails at runtime
 * with "Unsupported webhook provider." Those RED failures are the honest
 * contract-branch state, not defects in this file. No cast of the unregistered
 * id is used.
 *
 * Uses real framework requests and independent node:crypto MACs. No module
 * mocks, no fake IncomingMessage, no production or shared-helper edits.
 */

const LINEAR_SECRET = 'phase8-linear-canary-secret-7b3d2c';
const LINEAR_BODY = 'phase8-linear-canary-payload-9f2e1a';
const LINEAR_DELIVERY_ID = 'phase8-linear-canary-delivery-id-1e7b3c';

const ALIEN_STRIPE_HEADER = 't=1700000000,v1=phase8-alien-stripe-mac-0000000000000000000000000000000000000000000000000000000000000000';

const ALIEN_SW_HEADERS = {
  'webhook-id': 'msg_phase8alienstandardwebhooks',
  'webhook-timestamp': '1700000000',
  'webhook-signature': 'v1,phase8alienswsignaturebase64==',
};

const ALIEN_TOKEN = 'phase8-alien-authorization-bearer-token-xyz';

const CANARY_TOKENS = [LINEAR_BODY, LINEAR_SECRET, LINEAR_DELIVERY_ID, ALIEN_TOKEN];

function assertNoCanary(body: string): void {
  for (const token of CANARY_TOKENS) {
    expect(body).not.toContain(token);
  }
}

function linearSig(body: Uint8Array, secret: string): string {
  return createHmac('sha256', secret).update(body).digest('hex');
}

function bodyBytes(text: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(new TextEncoder().encode(text));
}

const LINEAR_BODY_BYTES = bodyBytes(LINEAR_BODY);
const LINEAR_SIG_HEADER = linearSig(LINEAR_BODY_BYTES, LINEAR_SECRET);

const ALIEN_HEADERS = {
  'stripe-signature': ALIEN_STRIPE_HEADER,
  'x-shopify-hmac-sha256': 'phase8-alien-shopify-hmac-base64=',
  'authorization': `Bearer ${ALIEN_TOKEN}`,
  ...ALIEN_SW_HEADERS,
};

function linearHeaders(extra: Record<string, string> = {}) {
  return {
    'content-type': 'application/octet-stream',
    'linear-signature': LINEAR_SIG_HEADER,
    ...extra,
  };
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
// 1. Missing linear header is not rescued by alien headers
// ---------------------------------------------------------------------------

test('express: missing linear header stays missing-signature despite alien headers', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'linear', secrets: [LINEAR_SECRET] }));
  app.use((_req, res) => res.status(200).send('ok'));
  const r = await sendRaw(app, LINEAR_BODY_BYTES, { ...ALIEN_HEADERS });
  expect(r.status).toBe(400);
  expect(r.body).toBe('Bad Request');
  assertNoCanary(r.body);
});

test('hono: missing linear header stays missing-signature despite alien headers', async () => {
  const app = new Hono();
  let called = false;
  app.post('/webhook', createHonoMiddleware({ provider: 'linear', secrets: [LINEAR_SECRET] }), (c) => {
    called = true;

    return c.text('ok', 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: LINEAR_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', ...ALIEN_HEADERS },
  });

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
  expect(called).toBe(false);
});

test('nextjs: missing linear header stays missing-signature despite alien headers', async () => {
  let called = false;

  const handler = createNextHandler({
    provider: 'linear',
    secrets: [LINEAR_SECRET],
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: LINEAR_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', ...ALIEN_HEADERS },
  }));

  expect(res.status).toBe(400);
  const text = await res.text();
  expect(text).toBe('Bad Request');
  expect(called).toBe(false);
  assertNoCanary(text);
});

test('cloudflare: missing linear header stays missing-signature despite alien headers', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'linear', secrets: [LINEAR_SECRET] }),
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: LINEAR_BODY_BYTES,
      headers: { 'content-type': 'application/octet-stream', ...ALIEN_HEADERS },
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(400);
  const text = await res.text();
  expect(text).toBe('Bad Request');
  expect(called).toBe(false);
  assertNoCanary(text);
});

// ---------------------------------------------------------------------------
// 2. Malformed linear header is not rescued by alien headers
// ---------------------------------------------------------------------------

test('express: malformed linear header stays malformed despite alien headers', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'linear', secrets: [LINEAR_SECRET] }));
  app.use((_req, res) => res.status(200).send('ok'));

  const r = await sendRaw(app, LINEAR_BODY_BYTES, {
    'linear-signature': 'not-a-valid-signature',
    ...ALIEN_HEADERS,
  });

  expect(r.status).toBe(400);
  expect(r.body).toBe('Bad Request');
  assertNoCanary(r.body);
});

test('hono: malformed linear header stays malformed despite alien headers', async () => {
  const app = new Hono();
  let called = false;
  app.post('/webhook', createHonoMiddleware({ provider: 'linear', secrets: [LINEAR_SECRET] }), (c) => {
    called = true;

    return c.text('ok', 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: LINEAR_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'linear-signature': 'not-a-valid-signature', ...ALIEN_HEADERS },
  });

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
  expect(called).toBe(false);
});

test('nextjs: malformed linear header stays malformed despite alien headers', async () => {
  let called = false;

  const handler = createNextHandler({
    provider: 'linear',
    secrets: [LINEAR_SECRET],
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: LINEAR_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'linear-signature': 'not-a-valid-signature', ...ALIEN_HEADERS },
  }));

  expect(res.status).toBe(400);
  const text = await res.text();
  expect(text).toBe('Bad Request');
  expect(called).toBe(false);
  assertNoCanary(text);
});

test('cloudflare: malformed linear header stays malformed despite alien headers', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'linear', secrets: [LINEAR_SECRET] }),
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: LINEAR_BODY_BYTES,
      headers: { 'content-type': 'application/octet-stream', 'linear-signature': 'not-a-valid-signature', ...ALIEN_HEADERS },
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(400);
  const text = await res.text();
  expect(text).toBe('Bad Request');
  expect(called).toBe(false);
  assertNoCanary(text);
});

// ---------------------------------------------------------------------------
// 3. Invalid (wrong MAC) linear header is not rescued by alien headers
// ---------------------------------------------------------------------------

const WRONG_MAC_HEADER = '0'.repeat(64);

test('express: invalid linear MAC stays invalid despite alien headers', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'linear', secrets: [LINEAR_SECRET] }));
  app.use((_req, res) => res.status(200).send('ok'));

  const r = await sendRaw(app, LINEAR_BODY_BYTES, {
    'linear-signature': WRONG_MAC_HEADER,
    ...ALIEN_HEADERS,
  });

  expect(r.status).toBe(400);
  expect(r.body).toBe('Bad Request');
  assertNoCanary(r.body);
});

test('hono: invalid linear MAC stays invalid despite alien headers', async () => {
  const app = new Hono();
  let called = false;
  app.post('/webhook', createHonoMiddleware({ provider: 'linear', secrets: [LINEAR_SECRET] }), (c) => {
    called = true;

    return c.text('ok', 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: LINEAR_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'linear-signature': WRONG_MAC_HEADER, ...ALIEN_HEADERS },
  });

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
  expect(called).toBe(false);
});

test('nextjs: invalid linear MAC stays invalid despite alien headers', async () => {
  let called = false;

  const handler = createNextHandler({
    provider: 'linear',
    secrets: [LINEAR_SECRET],
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: LINEAR_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'linear-signature': WRONG_MAC_HEADER, ...ALIEN_HEADERS },
  }));

  expect(res.status).toBe(400);
  const text = await res.text();
  expect(text).toBe('Bad Request');
  expect(called).toBe(false);
  assertNoCanary(text);
});

test('cloudflare: invalid linear MAC stays invalid despite alien headers', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'linear', secrets: [LINEAR_SECRET] }),
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: LINEAR_BODY_BYTES,
      headers: { 'content-type': 'application/octet-stream', 'linear-signature': WRONG_MAC_HEADER, ...ALIEN_HEADERS },
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(400);
  const text = await res.text();
  expect(text).toBe('Bad Request');
  expect(called).toBe(false);
  assertNoCanary(text);
});

// ---------------------------------------------------------------------------
// 4. Valid linear verifies even with alien headers present
// ---------------------------------------------------------------------------

test('express: valid linear verifies even with alien headers present', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'linear', secrets: [LINEAR_SECRET] }));
  app.use((req, res) => res.status(200).send(String(req.webhook?.rawBody.byteLength)));
  const r = await sendRaw(app, LINEAR_BODY_BYTES, linearHeaders(ALIEN_HEADERS));
  expect(r.status).toBe(200);
  expect(r.body).toBe(String(LINEAR_BODY_BYTES.byteLength));
});

test('hono: valid linear verifies even with alien headers present', async () => {
  const app = new Hono();
  app.post('/webhook', createHonoMiddleware({ provider: 'linear', secrets: [LINEAR_SECRET] }), (c) => {
    const w = c.get('webhook');

    return c.text(`ok:${w.rawBody.byteLength}`, 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: LINEAR_BODY_BYTES,
    headers: linearHeaders(ALIEN_HEADERS),
  });

  expect(res.status).toBe(200);
  expect(await res.text()).toBe(`ok:${LINEAR_BODY_BYTES.byteLength}`);
});

test('nextjs: valid linear verifies even with alien headers present', async () => {
  const handler = createNextHandler({
    provider: 'linear',
    secrets: [LINEAR_SECRET],
    handler: async (_req, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: LINEAR_BODY_BYTES,
    headers: linearHeaders(ALIEN_HEADERS),
  }));

  expect(res.status).toBe(200);
  expect(await res.text()).toBe(String(LINEAR_BODY_BYTES.byteLength));
});

test('cloudflare: valid linear verifies even with alien headers present', async () => {
  const handler = createWorkerHandler({
    options: () => ({ provider: 'linear', secrets: [LINEAR_SECRET] }),
    handler: async (_req, _env, _ctx, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: LINEAR_BODY_BYTES,
      headers: linearHeaders(ALIEN_HEADERS),
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(200);
  expect(await res.text()).toBe(String(LINEAR_BODY_BYTES.byteLength));
});

// ---------------------------------------------------------------------------
// 5. Signed body timestamp vs unsigned header timestamp (no freshness check)
// ---------------------------------------------------------------------------

test('linear: valid body MAC succeeds regardless of old timestamp in headers', async () => {
  const handler = createNextHandler({
    provider: 'linear',
    secrets: [LINEAR_SECRET],
    handler: async (_req, success) => new Response(JSON.stringify(success.identity), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: LINEAR_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'linear-signature': LINEAR_SIG_HEADER, 'linear-timestamp': '1000', 'linear-delivery': 'old-delivery-id' },
  }));

  expect(res.status).toBe(200);
  // SAFETY: the response body is produced by this test's own handler as
  // JSON.stringify of a fixed shape; the cast matches that known shape.
  const identity = JSON.parse(await res.text()) as { deliveryId: null; eventId: null; timestamp: null; authenticatedFields: readonly string[] };
  expect(identity.deliveryId).toBeNull();
  expect(identity.eventId).toBeNull();
  expect(identity.timestamp).toBeNull();
  expect(identity.authenticatedFields).toEqual([]);
});

test('linear: valid body MAC succeeds regardless of future timestamp in headers', async () => {
  const handler = createNextHandler({
    provider: 'linear',
    secrets: [LINEAR_SECRET],
    handler: async (_req, success) => new Response(JSON.stringify(success.identity), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: LINEAR_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'linear-signature': LINEAR_SIG_HEADER, 'linear-timestamp': '9999999999', 'linear-delivery': 'future-delivery-id' },
  }));

  expect(res.status).toBe(200);
  // SAFETY: the response body is produced by this test's own handler as
  // JSON.stringify of a fixed shape; the cast matches that known shape.
  const identity = JSON.parse(await res.text()) as { deliveryId: null; eventId: null; timestamp: null; authenticatedFields: readonly string[] };
  expect(identity.deliveryId).toBeNull();
  expect(identity.eventId).toBeNull();
  expect(identity.timestamp).toBeNull();
  expect(identity.authenticatedFields).toEqual([]);
});

test('linear: changing unsigned delivery/event/time headers does not change a valid result', async () => {
  const handler = createNextHandler({
    provider: 'linear',
    secrets: [LINEAR_SECRET],
    handler: async (_req, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });

  for (const delivery of ['id-a', 'id-b', '']) {
    for (const event of ['evt-1', 'evt-2', '']) {
      for (const ts of ['0', '1000', '9999999999']) {
        const res = await handler(new Request('https://example.test/webhook', {
          method: 'POST',
          body: LINEAR_BODY_BYTES,
          headers: { 'content-type': 'application/octet-stream', 'linear-signature': LINEAR_SIG_HEADER, 'linear-delivery': delivery, 'linear-event': event, 'linear-timestamp': ts },
        }));

        expect(res.status).toBe(200);
        expect(await res.text()).toBe(String(LINEAR_BODY_BYTES.byteLength));
      }
    }
  }
});

test('linear: stale body (old data) with valid MAC is still authentication success', async () => {
  // Linear has no freshness check. A validly signed body succeeds regardless of
  // how old the data is. Freshness is the caller's responsibility after verify.
  const handler = createNextHandler({
    provider: 'linear',
    secrets: [LINEAR_SECRET],
    handler: async (_req, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: LINEAR_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'linear-signature': LINEAR_SIG_HEADER },
  }));

  expect(res.status).toBe(200);
  expect(await res.text()).toBe(String(LINEAR_BODY_BYTES.byteLength));
});

// ---------------------------------------------------------------------------
// 6. Generic error bodies omit canaries
// ---------------------------------------------------------------------------

test('linear error bodies contain no payload, secret, signature or id', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'linear', secrets: [LINEAR_SECRET] }));
  app.use((_req, res) => res.status(200).send('ok'));

  const r = await sendRaw(app, LINEAR_BODY_BYTES, {
    'linear-signature': 'not-a-valid-signature',
    'linear-delivery': LINEAR_DELIVERY_ID,
    ...ALIEN_HEADERS,
  });

  expect(r.status).toBe(400);
  expect(r.body).toBe('Bad Request');
  assertNoCanary(r.body);

  const wrongMac = await sendRaw(app, LINEAR_BODY_BYTES, {
    'linear-signature': '0'.repeat(64),
    'linear-delivery': LINEAR_DELIVERY_ID,
    ...ALIEN_HEADERS,
  });

  expect(wrongMac.status).toBe(400);
  expect(wrongMac.body).toBe('Bad Request');
  assertNoCanary(wrongMac.body);

  const missing = await sendRaw(app, LINEAR_BODY_BYTES, { ...ALIEN_HEADERS });
  expect(missing.status).toBe(400);
  expect(missing.body).toBe('Bad Request');
  assertNoCanary(missing.body);
});