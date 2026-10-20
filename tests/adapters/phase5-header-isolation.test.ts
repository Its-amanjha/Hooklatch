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
 * Phase 5 Stage A — header-confusion regressions on the shipped adapters.
 *
 * Uses shipped providers only (GitHub is the explicitly configured provider;
 * Stripe and Standard Webhooks supply independent, valid-looking alien headers).
 * No module mocks, no casts to unregistered provider ids, no new providers,
 * no production code or shared helper changes.
 */

const GITHUB_SECRET = 'phase5-header-isolation-canary-secret-7b3d2c';
const GITHUB_BODY = 'phase5-header-isolation-canary-payload-9f2e1a';
const GITHUB_DELIVERY_ID = 'phase5-header-isolation-canary-delivery-id-1e7b3c';

const ALIEN_STRIPE_SECRET = 'phase5-alien-stripe-secret-1a2b3c';
const ALIEN_SW_SECRET = 'whsec_phase5alienswsecret0123456789abcdef';
const ALIEN_SW_ID = 'msg_phase5alienstandardwebhooks';
const ALIEN_SW_TS = '1700000000';

const ALIEN_TOKEN = 'phase5-alien-authorization-bearer-token-xyz';

const CANARY_TOKENS = [GITHUB_BODY, GITHUB_SECRET, GITHUB_DELIVERY_ID, ALIEN_TOKEN];

function assertNoCanary(body: string): void {
  for (const token of CANARY_TOKENS) {
    expect(body).not.toContain(token);
  }
}

function githubSig(bytes: Uint8Array, secret: string): string {
  return `sha256=${createHmac('sha256', secret).update(bytes).digest('hex')}`;
}

function stripeSig(body: Uint8Array, secret: string, timestamp: string): string {
  const signed = `${timestamp}.${new TextDecoder().decode(body)}`;
  const hex = createHmac('sha256', secret).update(signed).digest('hex');

  return `t=${timestamp},v1=${hex}`;
}

function standardWebhooksSig(body: Uint8Array, secret: string, id: string, timestamp: string): string {
  const key = Buffer.from(secret.slice('whsec_'.length), 'base64');
  const content = `${id}.${timestamp}.${new TextDecoder().decode(body)}`;
  const b64 = createHmac('sha256', key).update(content).digest('base64');

  return `v1,${b64}`;
}

function bodyBytes(text: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(new TextEncoder().encode(text));
}

const GITHUB_BODY_BYTES = bodyBytes(GITHUB_BODY);
const GITHUB_SIG_HEADER = githubSig(GITHUB_BODY_BYTES, GITHUB_SECRET);

const ALIEN_STRIPE_HEADER = stripeSig(GITHUB_BODY_BYTES, ALIEN_STRIPE_SECRET, '1700000000');

const ALIEN_SW_HEADERS = {
  'webhook-id': ALIEN_SW_ID,
  'webhook-timestamp': ALIEN_SW_TS,
  'webhook-signature': standardWebhooksSig(GITHUB_BODY_BYTES, ALIEN_SW_SECRET, ALIEN_SW_ID, ALIEN_SW_TS),
};

// Alien headers that are present alongside a valid GitHub request.
const ALIEN_HEADERS = {
  'stripe-signature': ALIEN_STRIPE_HEADER,
  'x-shopify-hmac-sha256': 'phase5-alien-shopify-hmac-base64=',
  'authorization': `Bearer ${ALIEN_TOKEN}`,
  ...ALIEN_SW_HEADERS,
};

function githubHeaders(extra: Record<string, string> = {}) {
  return {
    'content-type': 'application/octet-stream',
    'x-hub-signature-256': GITHUB_SIG_HEADER,
    'x-github-delivery': GITHUB_DELIVERY_ID,
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

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
// 1. Missing GitHub header is not rescued by alien headers
// ---------------------------------------------------------------------------

test('express: missing github header stays missing-signature despite alien headers', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: [GITHUB_SECRET] }));
  app.use((_req, res) => res.status(200).send('ok'));
  const r = await sendRaw(app, GITHUB_BODY_BYTES, { ...ALIEN_HEADERS });
  expect(r.status).toBe(400);
  expect(r.body).toBe('Bad Request');
  assertNoCanary(r.body);
});

test('hono: missing github header stays missing-signature despite alien headers', async () => {
  const app = new Hono();
  let called = false;
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [GITHUB_SECRET] }), (c) => {
    called = true;

    return c.text('ok', 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: GITHUB_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', ...ALIEN_HEADERS },
  });

  const text = await res.text();
  expect(res.status).toBe(400);
  expect(text).toBe('Bad Request');
  expect(called).toBe(false);
  assertNoCanary(text);
});

test('nextjs: missing github header stays missing-signature despite alien headers', async () => {
  let called = false;

  const handler = createNextHandler({
    provider: 'github',
    secrets: [GITHUB_SECRET],
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: GITHUB_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', ...ALIEN_HEADERS },
  }));

  expect(res.status).toBe(400);
  const text = await res.text();
  expect(text).toBe('Bad Request');
  expect(called).toBe(false);
  assertNoCanary(text);
});

test('cloudflare: missing github header stays missing-signature despite alien headers', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [GITHUB_SECRET] }),
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: GITHUB_BODY_BYTES,
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
// 2. Malformed github header is not rescued by alien headers
// ---------------------------------------------------------------------------

test('express: malformed github header stays malformed despite alien headers', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: [GITHUB_SECRET] }));
  app.use((_req, res) => res.status(200).send('ok'));

  const r = await sendRaw(app, GITHUB_BODY_BYTES, {
    'x-hub-signature-256': 'not-a-valid-signature',
    ...ALIEN_HEADERS,
  });

  expect(r.status).toBe(400);
  expect(r.body).toBe('Bad Request');
  assertNoCanary(r.body);
});

test('hono: malformed github header stays malformed despite alien headers', async () => {
  const app = new Hono();
  let called = false;
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [GITHUB_SECRET] }), (c) => {
    called = true;

    return c.text('ok', 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: GITHUB_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': 'not-a-valid-signature', ...ALIEN_HEADERS },
  });

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
  expect(called).toBe(false);
});

test('nextjs: malformed github header stays malformed despite alien headers', async () => {
  let called = false;

  const handler = createNextHandler({
    provider: 'github',
    secrets: [GITHUB_SECRET],
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: GITHUB_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': 'not-a-valid-signature', ...ALIEN_HEADERS },
  }));

  expect(res.status).toBe(400);
  const text = await res.text();
  expect(text).toBe('Bad Request');
  expect(called).toBe(false);
  assertNoCanary(text);
});

test('cloudflare: malformed github header stays malformed despite alien headers', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [GITHUB_SECRET] }),
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: GITHUB_BODY_BYTES,
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': 'not-a-valid-signature', ...ALIEN_HEADERS },
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
// 3. Invalid (wrong MAC) github header is not rescued by alien headers
// ---------------------------------------------------------------------------

const WRONG_MAC_HEADER = `sha256=${'0'.repeat(64)}`;

test('express: invalid github MAC stays invalid despite alien headers', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: [GITHUB_SECRET] }));
  app.use((_req, res) => res.status(200).send('ok'));

  const r = await sendRaw(app, GITHUB_BODY_BYTES, {
    'x-hub-signature-256': WRONG_MAC_HEADER,
    ...ALIEN_HEADERS,
  });

  expect(r.status).toBe(400);
  expect(r.body).toBe('Bad Request');
  assertNoCanary(r.body);
});

test('hono: invalid github MAC stays invalid despite alien headers', async () => {
  const app = new Hono();
  let called = false;
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [GITHUB_SECRET] }), (c) => {
    called = true;

    return c.text('ok', 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: GITHUB_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': WRONG_MAC_HEADER, ...ALIEN_HEADERS },
  });

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
  expect(called).toBe(false);
});

test('nextjs: invalid github MAC stays invalid despite alien headers', async () => {
  let called = false;

  const handler = createNextHandler({
    provider: 'github',
    secrets: [GITHUB_SECRET],
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: GITHUB_BODY_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': WRONG_MAC_HEADER, ...ALIEN_HEADERS },
  }));

  expect(res.status).toBe(400);
  const text = await res.text();
  expect(text).toBe('Bad Request');
  expect(called).toBe(false);
  assertNoCanary(text);
});

test('cloudflare: invalid github MAC stays invalid despite alien headers', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [GITHUB_SECRET] }),
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: GITHUB_BODY_BYTES,
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': WRONG_MAC_HEADER, ...ALIEN_HEADERS },
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
// 4. Valid github header is unaffected by alien headers
// ---------------------------------------------------------------------------

test('express: valid github verifies even with alien headers present', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: [GITHUB_SECRET] }));
  app.use((req, res) => res.status(200).send(String(req.webhook?.rawBody.byteLength)));
  const r = await sendRaw(app, GITHUB_BODY_BYTES, githubHeaders(ALIEN_HEADERS));
  expect(r.status).toBe(200);
  expect(r.body).toBe(String(GITHUB_BODY_BYTES.byteLength));
});

test('hono: valid github verifies even with alien headers present', async () => {
  const app = new Hono();
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [GITHUB_SECRET] }), (c) => {
    const w = c.get('webhook');

    if (!w) throw new Error('expected a verified webhook');

    return c.text(`ok:${w.rawBody.byteLength}`, 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: GITHUB_BODY_BYTES,
    headers: githubHeaders(ALIEN_HEADERS),
  });

  expect(res.status).toBe(200);
  expect(await res.text()).toBe(`ok:${GITHUB_BODY_BYTES.byteLength}`);
});

test('nextjs: valid github verifies even with alien headers present', async () => {
  const handler = createNextHandler({
    provider: 'github',
    secrets: [GITHUB_SECRET],
    handler: async (_req, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: GITHUB_BODY_BYTES,
    headers: githubHeaders(ALIEN_HEADERS),
  }));

  expect(res.status).toBe(200);
  expect(await res.text()).toBe(String(GITHUB_BODY_BYTES.byteLength));
});

test('cloudflare: valid github verifies even with alien headers present', async () => {
  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [GITHUB_SECRET] }),
    handler: async (_req, _env, _ctx, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: GITHUB_BODY_BYTES,
      headers: githubHeaders(ALIEN_HEADERS),
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(200);
  expect(await res.text()).toBe(String(GITHUB_BODY_BYTES.byteLength));
});

// ---------------------------------------------------------------------------
// 5. Alien signature headers do not alter verified github identity
// ---------------------------------------------------------------------------

test('github signed identity fields stay null even with alien headers', async () => {
  const handler = createNextHandler({
    provider: 'github',
    secrets: [GITHUB_SECRET],
    handler: async (_req, success) => new Response(JSON.stringify(success.identity), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: GITHUB_BODY_BYTES,
    headers: githubHeaders(ALIEN_HEADERS),
  }));

  expect(res.status).toBe(200);
  // SAFETY: the response body is produced by this test's own handler as
  // JSON.stringify(success.identity); the shape is fixed by the core contract.
  const identity = JSON.parse(await res.text()) as { deliveryId: string | null; eventId: string | null; timestamp: number | null; authenticatedFields: readonly string[] };
  expect(identity.eventId).toBeNull();
  expect(identity.timestamp).toBeNull();
  expect(identity.authenticatedFields).toEqual([]);
});