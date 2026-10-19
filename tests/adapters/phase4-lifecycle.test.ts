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
 * Phase 4 Stage A: adapter adverse lifecycle and failure-boundary regressions.
 *
 * Uses the implemented GitHub provider as the common signing recipe. All data is
 * synthetic. No production code, shared helper, config, fixture, or other test
 * file is changed by this suite.
 */

/** Distinctive canaries. Long enough that substring checks are meaningful. */
const CANARY_PAYLOAD = 'phase4-lifecycle-canary-payload-9f2e1a2b';
const CANARY_SECRET = 'phase4-lifecycle-canary-secret-7b3d2c4e';
const CANARY_SIGNATURE_HEX = createHmac('sha256', CANARY_SECRET).update('different signed bytes').digest('hex');
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

async function sendRaw(app: express.Express, body: Uint8Array, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  const server = http.createServer(app);

  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });

    const address = server.address();

    if (!isTcpAddress(address)) throw new Error('Expected TCP server address');

    return await new Promise((resolve, reject) => {
      const req = http.request(
        { hostname: '127.0.0.1', port: address.port, path: '/', method: 'POST', headers: { 'content-type': 'application/octet-stream', ...headers } },
        (res) => {
          let data = '';
          res.on('data', (chunk: Buffer) => { data += chunk; });
          res.once('error', reject);
          res.once('aborted', () => reject(new Error('Response aborted')));
          res.once('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
        },
      );

      req.once('error', reject);
      req.setTimeout(5000, () => req.destroy(new Error('HTTP test request timed out')));
      req.end(Buffer.from(body));
    });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test('express invalid setup returns 500 before reading its incoming body or calling handler', async () => {
  const app = express();
  let handlerCalled = false;
  let bodyListenerAdded = false;
  let bodyReadAtFinish = false;

  app.use((req, res, next) => {
    req.on('newListener', (event) => {
      if (event === 'data' || event === 'readable') bodyListenerAdded = true;
    });
    res.once('finish', () => { bodyReadAtFinish = req.readableDidRead; });
    next();
  });
  app.use(createWebhookMiddleware({ provider: 'github', secrets: [] }));
  app.use((_req, res) => { handlerCalled = true; res.status(200).send('ok'); });

  const result = await sendRaw(app, toBytes(CANARY_PAYLOAD));

  expect(result.status).toBe(500);
  expect(result.body).toBe('Internal Server Error');
  expect(handlerCalled).toBe(false);
  expect(bodyListenerAdded).toBe(false);
  expect(bodyReadAtFinish).toBe(false);
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

  let pulls = 0;

  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls++;

      if (pulls === 1) {
        controller.enqueue(toBytes(CANARY_PAYLOAD));

        return;
      }

      controller.error(new Error(CANARY_ID));
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
  expect(pulls).toBe(2);
  assertNoCanary(text);
});

test('cloudflare returns 500 on a mid-stream read failure and does not call handler', async () => {
  let called = false;

  let pulls = 0;

  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls++;

      if (pulls === 1) {
        controller.enqueue(toBytes(CANARY_PAYLOAD));

        return;
      }

      controller.error(new Error(CANARY_ID));
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
  expect(pulls).toBe(2);
});

test('hono returns 500 on a mid-stream read failure and does not call handler', async () => {
  let called = false;

  let pulls = 0;

  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls++;

      if (pulls === 1) {
        controller.enqueue(toBytes(CANARY_PAYLOAD));

        return;
      }

      controller.error(new Error(CANARY_ID));
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
  expect(pulls).toBe(2);
});

test('readNodeStream throws a 500 HttpError on a mid-stream failure', async () => {
  // Direct, cast-free coverage of the helper Express uses to read a request
  // body. A throwing async iterable must surface as HttpError(500), which the
  // adapter's catch branch turns into 'Internal Server Error'. Exercising the
  // helper directly isolates reader failures from transport-level aborts.
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

async function assertOverflowDoesNotAwaitCancel(handle: (request: Request) => Promise<Response>): Promise<void> {
  let settleCancel: () => void = () => {};
  let markCancelEntered: () => void = () => {};
  const cancelPending = new Promise<void>((resolve) => { settleCancel = resolve; });
  const cancelEntered = new Promise<void>((resolve) => { markCancelEntered = resolve; });
  let cancelCalled = false;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(2));
      // Keep the source open: cancelling an already-drained closed stream
      // does not invoke this underlying cancel callback.
    },
    cancel() {
      cancelCalled = true;
      markCancelEntered();

      return cancelPending;
    },
  });

  const request = new Request('https://example.test/webhook', {
    method: 'POST',
    body: stream,
    // @ts-expect-error duplex is required by Node for streaming bodies
    duplex: 'half',
  });

  const response = handle(request);
  let checkpoint: ReturnType<typeof setImmediate> | undefined;

  try {
    // A macrotask checkpoint lets all response microtasks finish without
    // imposing a wall-clock performance budget on loaded CI machines.
    const outcome = await Promise.race([
      response.then((value) => ({ kind: 'response' as const, status: value.status })),
      new Promise<{ kind: 'pending' }>((resolve) => {
        checkpoint = setImmediate(() => resolve({ kind: 'pending' }));
      }),
    ]);

    expect(cancelCalled).toBe(true);
    await cancelEntered;
    expect(outcome).toEqual({ kind: 'response', status: 413 });
  } finally {
    if (checkpoint !== undefined) clearImmediate(checkpoint);
    settleCancel();
    await response;
  }
}

test('nextjs returns 413 before pending cancellation settles and never calls handler', async () => {
  let called = false;

  const handler = createNextHandler({
    provider: 'github',
    secrets: [CANARY_SECRET],
    maxBodyBytes: 1,
    handler: async () => {
      called = true;

      return new Response('ok');
    },
  });

  await assertOverflowDoesNotAwaitCancel(handler);
  expect(called).toBe(false);
});

test('cloudflare returns 413 before pending cancellation settles and never calls handler', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [CANARY_SECRET], maxBodyBytes: 1 }),
    handler: async () => {
      called = true;

      return new Response('ok');
    },
  });

  await assertOverflowDoesNotAwaitCancel((request) => handler(request, {}, { waitUntil: () => undefined }));
  expect(called).toBe(false);
});

// ---------------------------------------------------------------------------
// 4. Consumed / locked Web Request fails before handler, no second read
// ---------------------------------------------------------------------------

test('nextjs rejects a consumed request before reading or calling handler', async () => {
  let called = false;

  const handler = createNextHandler({
    provider: 'github',
    secrets: [CANARY_SECRET],
    handler: async () => {
      called = true;

      return new Response('ok', { status: 200 });
    },
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
  expect(called).toBe(false);
  expect(req.bodyUsed).toBe(true);
});

test('cloudflare rejects a consumed request before reading or calling handler', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [CANARY_SECRET] }),
    handler: async () => {
      called = true;

      return new Response('ok', { status: 200 });
    },
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
  expect(called).toBe(false);
  expect(req.bodyUsed).toBe(true);
});

test('nextjs rejects a locked request before reading or calling handler', async () => {
  let called = false;

  const handler = createNextHandler({
    provider: 'github',
    secrets: [CANARY_SECRET],
    handler: async () => {
      called = true;

      return new Response('ok', { status: 200 });
    },
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
    expect(called).toBe(false);
    expect(req.body!.locked).toBe(true);
  } finally {
    reader.releaseLock();
  }
});

test('cloudflare rejects a locked request before reading or calling handler', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [CANARY_SECRET] }),
    handler: async () => {
      called = true;

      return new Response('ok', { status: 200 });
    },
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
    expect(called).toBe(false);
    expect(req.body!.locked).toBe(true);
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
