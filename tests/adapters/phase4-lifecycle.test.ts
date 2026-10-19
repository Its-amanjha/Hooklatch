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
 * Phase 4 Stage A ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â adapter adverse lifecycle and failure-boundary regressions.
 *
 * Uses the implemented GitHub provider as the common signing recipe. All data is
 * synthetic. No production code, shared helper, config, fixture, or other test
 * file is changed by this suite.
 */

/** Distinctive canaries. Long enough that substring checks are meaningful. */
const CANARY_PAYLOAD = 'phase4-lifecycle-canary-payload-9f2e1a2b';
const CANARY_SECRET = 'phase4-lifecycle-canary-secret-7b3d2c4e';
const CANARY_SIGNATURE_HEX = 'phase4lifecyclecanarysignaturehex4a8c1f2e3b5d7a9c';
const CANARY_ID = 'phase4-lifecycle-canary-delivery-id-1e7b3c5d';

const CANARY_TOKENS = [CANARY_PAYLOAD, CANARY_SECRET, CANARY_SIGNATURE_HEX, CANARY_ID];

function assertNoCanary(body: string): void {
  for (const token of CANARY_TOKENS) {
    expect(body).not.toContain(token);
  }
}

function githubSig(bytes: Uint8Array, secret: string): string {
  return `sha256=${createHmac('sha256', secret).update(bytes).digest('hex')}`;
}

function toBytes(text: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(new TextEncoder().encode(text));
}

// ---------------------------------------------------------------------------
// 1. Invalid setup rejected before body pull or downstream handler
// ---------------------------------------------------------------------------

function makeExpressAppWithSecrets(secrets: string[]) {
  const handlerCalled = { value: false };
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets }));
  app.use((_req, res) => { handlerCalled.value = true; res.status(200).send('ok'); });
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).send('Internal Server Error');
  });

  return { app, handlerCalled };
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

test('express invalid setup returns 500 and never pulls body or calls handler', async () => {
  const { handlerCalled } = makeExpressAppWithSecrets([]);
  const capturedBody = Buffer.from('hi');
  const app2 = express();
  app2.use(express.raw({ type: '*/*' }));
  app2.use(createWebhookMiddleware({ provider: 'github', secrets: [] }));
  app2.use((_req, res) => { handlerCalled.value = true; res.status(200).send('ok'); });
  app2.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).send('Internal Server Error');
  });

  const server = http.createServer(app2);

  const result = await new Promise<{ status: number; body: string }>((resolve, reject) => {
    server.listen(0, () => {
      const addr = server.address();

      if (!isTcpAddress(addr)) { server.close(); reject(new Error('Expected TCP server address'));

 return; }

      const port = addr.port;

      const req = http.request(
        { hostname: '127.0.0.1', port, path: '/', method: 'POST', headers: { 'content-type': 'application/octet-stream', 'content-length': String(capturedBody.byteLength) } },
        (res) => {
          let data = '';
          res.on('data', (c: Buffer) => { data += c; });
          res.on('end', () => { server.close(); resolve({ status: res.statusCode ?? 0, body: data }); });
        },
      );

      req.on('error', (e) => { server.close(); reject(e); });
      req.write(capturedBody);
      req.end();
    });
  });

  expect(result.status).toBe(500);
  expect(result.body).toBe('Internal Server Error');
  expect(handlerCalled.value).toBe(false);
  assertNoCanary(result.body);
});

test('hono invalid setup returns 500 and never calls handler', async () => {
  let called = false;
  const app = new Hono();
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [] }), (c) => {
    called = true;

    return c.text('ok', 200);
  });
  const res = await app.request('/webhook', { method: 'POST', body: 'hi' });
  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(called).toBe(false);
});

test('nextjs invalid setup returns 500 and does not consume the request body', async () => {
  const handler = createNextHandler({
    provider: 'github',
    secrets: [],
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: CANARY_PAYLOAD,
    headers: { 'content-type': 'text/plain' },
  });

  const res = await handler(req);
  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  // Body was never pulled: readBody never ran.
  expect(req.bodyUsed).toBe(false);
});

test('cloudflare invalid setup returns 500 and does not consume the request body', async () => {
  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [] }),
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: CANARY_PAYLOAD,
    headers: { 'content-type': 'text/plain' },
  });

  const res = await handler(req, {}, { waitUntil: () => undefined });
  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(req.bodyUsed).toBe(false);
});

// ---------------------------------------------------------------------------
// 2. Body reader stream failure midway
// ---------------------------------------------------------------------------

test('nextjs returns 500 on a mid-stream read failure and does not call handler', async () => {
  let called = false;

  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new TextEncoder().encode('ab'));
      controller.error(new Error('stream broke midway'));
    },
  });

  const handler = createNextHandler({
    provider: 'github',
    secrets: [CANARY_SECRET],
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: stream,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSig(toBytes(CANARY_PAYLOAD), CANARY_SECRET) },
    // @ts-expect-error duplex is required by some runtimes for streaming bodies
    duplex: 'half',
  });

  const res = await handler(req);
  const text = await res.text();
  expect(res.status).toBe(500);
  expect(text).toBe('Internal Server Error');
  expect(called).toBe(false);
  assertNoCanary(text);
});

test('cloudflare returns 500 on a mid-stream read failure and does not call handler', async () => {
  let called = false;

  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new TextEncoder().encode('ab'));
      controller.error(new Error('stream broke midway'));
    },
  });

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [CANARY_SECRET] }),
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: stream,
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSig(toBytes(CANARY_PAYLOAD), CANARY_SECRET) },
      // @ts-expect-error duplex is required by some runtimes for streaming bodies
      duplex: 'half',
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(called).toBe(false);
});

test('hono returns 500 on a mid-stream read failure and does not call handler', async () => {
  let called = false;

  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new TextEncoder().encode('ab'));
      controller.error(new Error('stream broke midway'));
    },
  });

  const app = new Hono();
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [CANARY_SECRET] }), (c) => {
    called = true;

    return c.text('ok', 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: stream,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSig(toBytes(CANARY_PAYLOAD), CANARY_SECRET) },
    // @ts-expect-error duplex is required by some runtimes for streaming bodies
    duplex: 'half',
  });

  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(called).toBe(false);
});

test('readNodeStream throws a 500 HttpError on a mid-stream failure', async () => {
  // Direct, cast-free coverage of the helper Express uses to read a request
  // body. A throwing async iterable must surface as HttpError(500), which the
  // adapter's catch branch turns into 'Internal Server Error'. Exercising the
  // helper directly avoids constructing an impossible IncomingMessage.
  const { readNodeStream, HttpError } = await import('../../src/adapters/shared.js');

  async function* failing() {
    yield new Uint8Array([1, 2, 3]);
    throw new Error('stream broke midway');
  }

  await expect(readNodeStream(failing(), 100)).rejects.toBeInstanceOf(HttpError);

  await expect(readNodeStream(failing(), 100)).rejects.toMatchObject({ status: 500 });
});

// ---------------------------------------------------------------------------
// 3. Oversized streaming requests must not await a forever-pending cancel
// ---------------------------------------------------------------------------

test('nextjs returns 413 promptly even when reader.cancel never resolves', async () => {
  let settleCancel: () => void = () => {};
  const cancelPending = new Promise<void>((resolve) => { settleCancel = resolve; });

  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new Uint8Array(2)); // oversized vs maxBodyBytes: 1
      controller.close();
    },
    cancel() {
      return cancelPending;
    },
  });

  const handler = createNextHandler({
    provider: 'github',
    secrets: [CANARY_SECRET],
    maxBodyBytes: 1,
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: stream,
    headers: { 'content-type': 'application/octet-stream' },
    // @ts-expect-error duplex is required by some runtimes for streaming bodies
    duplex: 'half',
  });

  const outcome = await Promise.race([
    handler(req).then((r) => ({ kind: 'response' as const, status: r.status })),
    new Promise<{ kind: 'timeout' }>((resolve) => setTimeout(() => resolve({ kind: 'timeout' }), 200)),
  ]);

  expect(outcome).toEqual({ kind: 'response', status: 413 });
  settleCancel();
});

test('cloudflare returns 413 promptly even when reader.cancel never resolves', async () => {
  let settleCancel: () => void = () => {};
  const cancelPending = new Promise<void>((resolve) => { settleCancel = resolve; });

  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new Uint8Array(2));
      controller.close();
    },
    cancel() {
      return cancelPending;
    },
  });

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [CANARY_SECRET], maxBodyBytes: 1 }),
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: stream,
    headers: { 'content-type': 'application/octet-stream' },
    // @ts-expect-error duplex is required by some runtimes for streaming bodies
    duplex: 'half',
  });

  const outcome = await Promise.race([
    handler(req, {}, { waitUntil: () => undefined }).then((r) => ({ kind: 'response' as const, status: r.status })),
    new Promise<{ kind: 'timeout' }>((resolve) => setTimeout(() => resolve({ kind: 'timeout' }), 200)),
  ]);

  expect(outcome).toEqual({ kind: 'response', status: 413 });
  settleCancel();
});

// ---------------------------------------------------------------------------
// 4. Consumed / locked Web Request fails before handler, no second read
// ---------------------------------------------------------------------------

test('nextjs rejects a consumed request before reading or calling handler', async () => {
  const handler = createNextHandler({
    provider: 'github',
    secrets: [CANARY_SECRET],
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: CANARY_PAYLOAD,
    headers: { 'content-type': 'text/plain' },
  });

  await req.text(); // consume
  expect(req.bodyUsed).toBe(true);

  const res = await handler(req);
  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(req.bodyUsed).toBe(true);
});

test('cloudflare rejects a consumed request before reading or calling handler', async () => {
  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [CANARY_SECRET] }),
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: CANARY_PAYLOAD,
    headers: { 'content-type': 'text/plain' },
  });

  await req.text();
  expect(req.bodyUsed).toBe(true);

  const res = await handler(req, {}, { waitUntil: () => undefined });
  expect(res.status).toBe(500);
  expect(await res.text()).toBe('Internal Server Error');
  expect(req.bodyUsed).toBe(true);
});

test('nextjs rejects a locked request before reading or calling handler', async () => {
  const handler = createNextHandler({
    provider: 'github',
    secrets: [CANARY_SECRET],
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: CANARY_PAYLOAD,
    headers: { 'content-type': 'text/plain' },
  });

  const reader = req.body!.getReader();

  try {
    const res = await handler(req);
    expect(res.status).toBe(500);
    expect(await res.text()).toBe('Internal Server Error');
  } finally {
    reader.releaseLock();
  }
});

test('cloudflare rejects a locked request before reading or calling handler', async () => {
  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [CANARY_SECRET] }),
    handler: async () => new Response('ok', { status: 200 }),
  });

  const req = new Request('https://example.test/webhook', {
    method: 'POST',
    body: CANARY_PAYLOAD,
    headers: { 'content-type': 'text/plain' },
  });

  const reader = req.body!.getReader();

  try {
    const res = await handler(req, {}, { waitUntil: () => undefined });
    expect(res.status).toBe(500);
    expect(await res.text()).toBe('Internal Server Error');
  } finally {
    reader.releaseLock();
  }
});

// ---------------------------------------------------------------------------
// 5. Adapter HTTP error bodies omit distinct long canaries
// ---------------------------------------------------------------------------



test('adapter error bodies omit canary payload, secret, signature and id', async () => {
  // Express 400 path.
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: [CANARY_SECRET] }));
  app.use((_req, res) => res.status(200).send('ok'));

  const r = await sendRaw(app, toBytes(CANARY_PAYLOAD), {
    'x-hub-signature-256': `sha256=${CANARY_SIGNATURE_HEX}`,
    'x-github-delivery': CANARY_ID,
  });

  expect(r.status).toBe(400);
  assertNoCanary(r.body);
  expect(r.body).toBe('Bad Request');

  // Express 413 path: dedicated app with a 1-byte limit.
  const limitedApp = express();
  limitedApp.use(createWebhookMiddleware({ provider: 'github', secrets: [CANARY_SECRET], maxBodyBytes: 1 }));
  limitedApp.use((_req, res) => res.status(200).send('ok'));

  const overflow2 = await sendRaw(limitedApp, toBytes(CANARY_PAYLOAD), {
    'x-hub-signature-256': `sha256=${CANARY_SIGNATURE_HEX}`,
    'x-github-delivery': CANARY_ID,
  });

  expect(overflow2.status).toBe(413);
  assertNoCanary(overflow2.body);
  expect(overflow2.body).toBe('Payload Too Large');

  // Hono 400 path.
  const honoApp = new Hono();
  honoApp.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [CANARY_SECRET] }), (c) => c.text('ok', 200));

  const honoRes = await honoApp.request('/webhook', {
    method: 'POST',
    body: CANARY_PAYLOAD,
    headers: { 'content-type': 'text/plain', 'x-hub-signature-256': `sha256=${CANARY_SIGNATURE_HEX}`, 'x-github-delivery': CANARY_ID },
  });

  const honoText = await honoRes.text();
  expect(honoRes.status).toBe(400);
  assertNoCanary(honoText);
  expect(honoText).toBe('Bad Request');

  // Next.js 400 path.
  const nextHandler = createNextHandler({
    provider: 'github',
    secrets: [CANARY_SECRET],
    handler: async () => new Response('ok', { status: 200 }),
  });

  const nextRes = await nextHandler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: CANARY_PAYLOAD,
    headers: { 'content-type': 'text/plain', 'x-hub-signature-256': `sha256=${CANARY_SIGNATURE_HEX}`, 'x-github-delivery': CANARY_ID },
  }));

  const nextText = await nextRes.text();
  expect(nextRes.status).toBe(400);
  assertNoCanary(nextText);
  expect(nextText).toBe('Bad Request');

  // Cloudflare 400 path.
  const workerHandler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [CANARY_SECRET] }),
    handler: async () => new Response('ok', { status: 200 }),
  });

  const workerRes = await workerHandler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: CANARY_PAYLOAD,
      headers: { 'content-type': 'text/plain', 'x-hub-signature-256': `sha256=${CANARY_SIGNATURE_HEX}`, 'x-github-delivery': CANARY_ID },
    }),
    {},
    { waitUntil: () => undefined },
  );

  const workerText = await workerRes.text();
  expect(workerRes.status).toBe(400);
  assertNoCanary(workerText);
  expect(workerText).toBe('Bad Request');
});

// (end of file)
