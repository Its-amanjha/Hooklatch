import { createHmac } from 'node:crypto';
import * as http from 'node:http';
import express from 'express';
import { Hono } from 'hono';

import { verify } from '../../src/index.js';
import { createWebhookMiddleware } from '../../src/adapters/express.js';
import { createWebhookHandler as createNextHandler } from '../../src/adapters/nextjs.js';
import { createWebhookHandler as createWorkerHandler } from '../../src/adapters/cloudflare.js';
import { createWebhookMiddleware as createHonoMiddleware } from '../../src/adapters/hono.js';
import { isTcpAddress } from './signing.js';

/**
 * Phase 3 Stage A - adapter byte-boundary regressions.
 *
 * Uses the implemented GitHub provider as the common signing recipe. All bodies
 * are synthetic invalid-UTF8 bytes; signatures are computed with Node's
 * `node:crypto` (test-only) over the exact bytes. No mocks, no production
 * edits, no external network.
 */

const SECRET = 's';

/** Invalid-UTF8, NUL-containing bytes; deliberately not valid text. */
const RAW_BYTES = new Uint8Array([0x80, 0x81, 0xff, 0x00, 0x41, 0xfe, 0x7f, 0xc0, 0x80]);

/** Same length as RAW_BYTES with exactly one byte changed. */
const TAMPERED_BYTES = new Uint8Array([0x80, 0x81, 0xff, 0x00, 0x41, 0xfe, 0x7f, 0xc0, 0x81]);

function hmacHex(bytes: Uint8Array): string {
  return createHmac('sha256', SECRET).update(bytes).digest('hex');
}

function githubSigHeader(bytes: Uint8Array): string {
  return `sha256=${hmacHex(bytes)}`;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;

  for (let i = 0; i < a.byteLength; i += 1) if (a[i] !== b[i]) return false;

  return true;
}

// ---------------------------------------------------------------------------
// core: nonzero-offset public input (the public API permits a Uint8Array view)
// ---------------------------------------------------------------------------

test('core verify accepts a nonzero-offset Uint8Array view and preserves bytes', async () => {
  const full = new Uint8Array([0x11, 0x22, ...RAW_BYTES, 0x33]);
  const view = full.subarray(2, 2 + RAW_BYTES.byteLength);
  expect(view.byteOffset).toBeGreaterThan(0);

  const result = await verify({ rawBody: view, headers: { 'x-hub-signature-256': githubSigHeader(view) } }, { provider: 'github', secrets: [SECRET] });

  expect(result.ok).toBe(true);

  if (result.ok) {
    expect(result.rawBody.byteLength).toBe(view.byteLength);
    expect(bytesEqual(result.rawBody, view)).toBe(true);
    expect(result.rawBody.byteOffset).toBe(0); // snapshot is a fresh copy
  }
});

test('core verify rejects a tampered nonzero-offset view', async () => {
  const full = new Uint8Array([0x11, 0x22, ...RAW_BYTES, 0x33]);
  const view = full.subarray(2, 2 + RAW_BYTES.byteLength);
  const tamperedBacking = new Uint8Array(full);
  const tampered = tamperedBacking.subarray(2, 2 + RAW_BYTES.byteLength);
  expect(tampered.byteOffset).toBeGreaterThan(0);
  const firstByte = tampered[0];

  if (firstByte === undefined) throw new Error('expected a leading byte');
  tampered[0] = firstByte ^ 0xff;

  const result = await verify({ rawBody: tampered, headers: { 'x-hub-signature-256': githubSigHeader(view) } }, { provider: 'github', secrets: [SECRET] });

  expect(result.ok).toBe(false);

  if (!result.ok) expect(result.reason).toBe('invalid-signature');
});

// ---------------------------------------------------------------------------
// shared helpers for sending raw bytes
// ---------------------------------------------------------------------------

function makeExpressApp(maxBodyBytes?: number, secret = SECRET) {
  const handlerCalled = { value: false };
  const app = express();

  const options = maxBodyBytes === undefined
    ? { provider: 'github' as const, secrets: [secret] }
    : { provider: 'github' as const, secrets: [secret], maxBodyBytes };

  app.use(createWebhookMiddleware(options));
  app.use((req, res) => {
    handlerCalled.value = true;

    if (!req.webhook) throw new Error('expected a verified webhook');
    res.status(200).send(bytesHex(req.webhook.rawBody));
  });
  // Surface handler throws as a controlled 500 so propagation is observable.
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).send('handler-error');
  });

  return { app, handlerCalled };
}

interface HttpResult {
  status: number;
  body: string;
  chunks: number;
}

function bytesHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function sendRaw(app: express.Express, body: Uint8Array, headers: Record<string, string> = {}): Promise<HttpResult> {
  return sendChunked(app, [body], headers);
}

/** Send the next chunk only after the server observed every byte of the last.
 * This handshake guarantees distinct incoming data events without timers or
 * assumptions about how multiple synchronous client writes are coalesced.
 */
function sendChunked(app: express.Express, chunks: Uint8Array[], headers: Record<string, string> = {}): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    let request: http.ClientRequest | undefined;
    let settled = false;
    let chunkIndex = 0;
    let writtenBytes = 0;
    let receivedBytes = 0;
    let observedChunks = 0;

    function writeNext(): void {
      const chunk = chunks[chunkIndex];

      if (!request || settled) return;

      if (!chunk) {
        request.end();

        return;
      }

      chunkIndex += 1;
      writtenBytes += chunk.byteLength;
      request.write(Buffer.from(chunk));

      if (chunkIndex === chunks.length) request.end();
    }

    const server = http.createServer((incoming, response) => {
      incoming.on('data', (chunk: Buffer) => {
        observedChunks += 1;
        receivedBytes += chunk.byteLength;

        if (chunkIndex < chunks.length && receivedBytes >= writtenBytes) writeNext();
      });
      app(incoming, response);
    });

    function finish(outcome: { ok: true; value: HttpResult } | { ok: false; error: Error }): void {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      request?.destroy();
      server.closeAllConnections();
      server.close(() => {
        if (outcome.ok) resolve(outcome.value);
        else reject(outcome.error);
      });
    }

    const deadline = setTimeout(() => finish({ ok: false, error: new Error('Local HTTP test timed out') }), 3000);
    server.once('error', (error) => finish({ ok: false, error }));
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();

      if (!isTcpAddress(address)) {
        finish({ ok: false, error: new Error('Expected TCP server address') });

        return;
      }

      request = http.request({
        hostname: '127.0.0.1', port: address.port, path: '/', method: 'POST', agent: false,
        headers: { 'content-type': 'application/octet-stream', ...headers },
      }, (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk: string) => { body += chunk; });
        response.once('error', (error) => finish({ ok: false, error }));
        response.once('aborted', () => finish({ ok: false, error: new Error('Local HTTP response aborted') }));
        response.once('end', () => finish({
          ok: true, value: { status: response.statusCode ?? 0, body, chunks: observedChunks },
        }));
      });
      request.once('error', (error) => finish({ ok: false, error }));
      writeNext();
    });
  });
}

// ---------------------------------------------------------------------------
// 1. Byte fidelity - non-JSON / invalid-UTF8 raw bytes across all 4 adapters
// ---------------------------------------------------------------------------

test('express preserves invalid-UTF8 bytes end to end', async () => {
  const { app, handlerCalled } = makeExpressApp();
  const r = await sendRaw(app, RAW_BYTES, { 'x-hub-signature-256': githubSigHeader(RAW_BYTES) });
  expect(r.status).toBe(200);
  expect(r.body).toBe(bytesHex(RAW_BYTES));
  expect(handlerCalled.value).toBe(true);
});

test('hono preserves invalid-UTF8 bytes end to end', async () => {
  const app = new Hono();
  let seen: Uint8Array | undefined;
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [SECRET] }), (c) => {
    const w = c.get('webhook');

    if (!w) throw new Error('expected a verified webhook');
    seen = w.rawBody;

    return c.text(bytesHex(w.rawBody), 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: RAW_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
  });

  expect(res.status).toBe(200);
  expect(await res.text()).toBe(bytesHex(RAW_BYTES));
  expect(seen).toEqual(RAW_BYTES);
});

test('nextjs preserves invalid-UTF8 bytes end to end', async () => {
  const handler = createNextHandler({
    provider: 'github',
    secrets: [SECRET],
    handler: async (_req, success) => new Response(bytesHex(success.rawBody), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: RAW_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
  }));

  expect(res.status).toBe(200);
  expect(await res.text()).toBe(bytesHex(RAW_BYTES));
});

test('cloudflare preserves invalid-UTF8 bytes end to end', async () => {
  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [SECRET] }),
    handler: async (_req, _env, _ctx, success) => new Response(bytesHex(success.rawBody), { status: 200 }),
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: RAW_BYTES,
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(200);
  expect(await res.text()).toBe(bytesHex(RAW_BYTES));
});

// ---------------------------------------------------------------------------
// 2. Tampering rejects and never calls the user handler
// ---------------------------------------------------------------------------

test('express tampered body returns 400 and does not call handler', async () => {
  const { app, handlerCalled } = makeExpressApp();
  const r = await sendRaw(app, TAMPERED_BYTES, { 'x-hub-signature-256': githubSigHeader(RAW_BYTES) });
  expect(r.status).toBe(400);
  expect(r.body).toBe('Bad Request');
  expect(handlerCalled.value).toBe(false);
});

test('hono tampered body returns 400 and does not call handler', async () => {
  let called = false;
  const app = new Hono();
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [SECRET] }), (c) => {
    called = true;

    return c.text('ok', 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: TAMPERED_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
  });

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
  expect(called).toBe(false);
});

test('nextjs tampered body returns 400 and does not call handler', async () => {
  let called = false;

  const handler = createNextHandler({
    provider: 'github',
    secrets: [SECRET],
    handler: async () => {
      called = true;

      return new Response('ok', { status: 200 });
    },
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: TAMPERED_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
  }));

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
  expect(called).toBe(false);
});

test('cloudflare tampered body returns 400 and does not call handler', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [SECRET] }),
    handler: async () => {
      called = true;

      return new Response('ok', { status: 200 });
    },
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: TAMPERED_BYTES,
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(400);
  expect(await res.text()).toBe('Bad Request');
  expect(called).toBe(false);
});

// ---------------------------------------------------------------------------
// 3. Size enforcement uses actual bytes; handler not called on overflow
// ---------------------------------------------------------------------------

test('express returns 413 on overflow and does not call handler', async () => {
  const { app, handlerCalled } = makeExpressApp(1);
  const r = await sendRaw(app, RAW_BYTES, { 'x-hub-signature-256': githubSigHeader(RAW_BYTES) });
  expect(r.status).toBe(413);
  expect(r.body).toBe('Payload Too Large');
  expect(handlerCalled.value).toBe(false);
});

test('express enforces the limit on a chunked stream with no Content-Length', async () => {
  const { app, handlerCalled } = makeExpressApp(1);
  // No content-length at all: Node uses chunked transfer encoding and delivers
  // every byte. The limit must still be enforced on the actual bytes received.
  const r = await sendChunked(app, [RAW_BYTES.subarray(0, 4), RAW_BYTES.subarray(4)], { 'x-hub-signature-256': githubSigHeader(RAW_BYTES) });
  expect(r.status).toBe(413);
  expect(r.body).toBe('Payload Too Large');
  expect(handlerCalled.value).toBe(false);
});

test('express enforces the limit on a captured Buffer using byteLength, not a header', async () => {
  // With express.raw() the body is captured into req.body as a Buffer before the
  // adapter runs, so the adapter checks body.byteLength directly. A content-length
  // header is never consulted for the limit decision on this path.
  const handlerCalled = { value: false };
  const app = express();
  app.use(express.raw({ type: '*/*' }));
  app.use(createWebhookMiddleware({ provider: 'github', secrets: [SECRET], maxBodyBytes: 1 }));
  app.use((_req, res) => { handlerCalled.value = true; res.status(200).send('ok'); });
  const r = await sendRaw(app, RAW_BYTES, { 'x-hub-signature-256': githubSigHeader(RAW_BYTES) });
  expect(r.status).toBe(413);
  expect(r.body).toBe('Payload Too Large');
  expect(handlerCalled.value).toBe(false);
});

test('nextjs enforces the limit on actual bytes despite a misleading Content-Length', async () => {
  // A Web Request's body stream delivers every byte regardless of the
  // content-length header, so the adapter must measure actual bytes, not the
  // (possibly wrong) declared length.
  let called = false;

  const handler = createNextHandler({
    provider: 'github',
    secrets: [SECRET],
    maxBodyBytes: 1,
    handler: async () => {
      called = true;

      return new Response('ok', { status: 200 });
    },
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: RAW_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES), 'content-length': '1' },
  }));

  expect(res.status).toBe(413);
  expect(await res.text()).toBe('Payload Too Large');
  expect(called).toBe(false);
});

test('cloudflare enforces the limit on actual bytes despite a misleading Content-Length', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [SECRET], maxBodyBytes: 1 }),
    handler: async () => {
      called = true;

      return new Response('ok', { status: 200 });
    },
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: RAW_BYTES,
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES), 'content-length': '1' },
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(413);
  expect(await res.text()).toBe('Payload Too Large');
  expect(called).toBe(false);
});

test('hono returns 413 on overflow', async () => {
  let called = false;
  const app = new Hono();
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [SECRET], maxBodyBytes: 1 }), (c) => {
    called = true;

    return c.text('ok', 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: RAW_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
  });

  expect(res.status).toBe(413);
  expect(await res.text()).toBe('Payload Too Large');
  expect(called).toBe(false);
});

test('nextjs returns 413 on overflow', async () => {
  let called = false;

  const handler = createNextHandler({
    provider: 'github',
    secrets: [SECRET],
    maxBodyBytes: 1,
    handler: async () => {
      called = true;

      return new Response('ok', { status: 200 });
    },
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: RAW_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
  }));

  expect(res.status).toBe(413);
  expect(await res.text()).toBe('Payload Too Large');
  expect(called).toBe(false);
});

test('cloudflare returns 413 on overflow', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [SECRET], maxBodyBytes: 1 }),
    handler: async () => {
      called = true;

      return new Response('ok', { status: 200 });
    },
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: RAW_BYTES,
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(413);
  expect(await res.text()).toBe('Payload Too Large');
  expect(called).toBe(false);
});

// ---------------------------------------------------------------------------
// 4. Multichunk / streaming boundaries preserve bytes across splits
// ---------------------------------------------------------------------------

test('express preserves bytes written across multiple chunks', async () => {
  const { app, handlerCalled } = makeExpressApp();
  const first = RAW_BYTES.subarray(0, 4);
  const second = RAW_BYTES.subarray(4);
  const r = await sendChunked(app, [first, second], { 'x-hub-signature-256': githubSigHeader(RAW_BYTES) });
  expect(r.chunks).toBeGreaterThanOrEqual(2);
  expect(r.status).toBe(200);
  expect(r.body).toBe(bytesHex(RAW_BYTES));
  expect(handlerCalled.value).toBe(true);
});

test('nextjs preserves bytes streamed via a ReadableStream', async () => {
  const first = RAW_BYTES.subarray(0, 4);
  const second = RAW_BYTES.subarray(4);

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(first);
      controller.enqueue(second);
      controller.close();
    },
  });

  const handler = createNextHandler({
    provider: 'github',
    secrets: [SECRET],
    handler: async (_req, success) => new Response(bytesHex(success.rawBody), { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: stream,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
    // @ts-expect-error duplex is required by some runtimes for streaming bodies
    duplex: 'half',
  }));

  expect(res.status).toBe(200);
  expect(await res.text()).toBe(bytesHex(RAW_BYTES));
});

test('cloudflare preserves bytes streamed via a ReadableStream', async () => {
  const first = RAW_BYTES.subarray(0, 4);
  const second = RAW_BYTES.subarray(4);

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(first);
      controller.enqueue(second);
      controller.close();
    },
  });

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [SECRET] }),
    handler: async (_req, _env, _ctx, success) => new Response(bytesHex(success.rawBody), { status: 200 }),
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: stream,
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
      // @ts-expect-error duplex is required by some runtimes for streaming bodies
      duplex: 'half',
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(200);
  expect(await res.text()).toBe(bytesHex(RAW_BYTES));
});

// ---------------------------------------------------------------------------
// 5. User handler exceptions propagate per adapter contract (not signature errors)
// ---------------------------------------------------------------------------

test('express propagates a thrown handler error as 500', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: [SECRET] }));
  app.use(() => { throw new Error('boom'); });
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).send('handler-error');
  });
  const r = await sendRaw(app, RAW_BYTES, { 'x-hub-signature-256': githubSigHeader(RAW_BYTES) });
  expect(r.status).toBe(500);
  expect(r.body).toBe('handler-error');
});

test('hono propagates the original handler error to the application error handler', async () => {
  const app = new Hono();
  const handlerError = new Error('phase3-handler-error');
  let observedError: Error | undefined;
  app.onError((error, context) => {
    observedError = error;

    return context.text('application-handler-error', 500);
  });
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [SECRET] }), () => {
    throw handlerError;
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: RAW_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
  });

  expect(res.status).toBe(500);
  expect(await res.text()).toBe('application-handler-error');
  expect(observedError).toBe(handlerError);
});

test('nextjs propagates a thrown handler error', async () => {
  const handler = createNextHandler({
    provider: 'github',
    secrets: [SECRET],
    handler: async () => { throw new Error('boom'); },
  });

  await expect(handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: RAW_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
  }))).rejects.toThrow('boom');
});

test('cloudflare propagates a thrown handler error', async () => {
  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [SECRET] }),
    handler: async () => { throw new Error('boom'); },
  });

  await expect(handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: RAW_BYTES,
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': githubSigHeader(RAW_BYTES) },
    }),
    {},
    { waitUntil: () => undefined },
  )).rejects.toThrow('boom');
});

// ---------------------------------------------------------------------------
// 6. No payload / secret / signature leak in adapter HTTP error bodies
// ---------------------------------------------------------------------------

// A distinctive secret so the leak check is meaningful. The single-character
// test secret 's' cannot be used here: it occurs inside the generic response
// words ("Request", "Internal") and would make the assertion vacuous.
const LEAK_SECRET = 'phase3-leak-canary-secret-xyz';

function leakSigHeader(bytes: Uint8Array): string {
  return `sha256=${createHmac('sha256', LEAK_SECRET).update(bytes).digest('hex')}`;
}

const LEAK_SIG_HEX = createHmac('sha256', LEAK_SECRET).update(RAW_BYTES).digest('hex');
const LEAK_TOKENS = [LEAK_SECRET, `sha256=${LEAK_SIG_HEX}`, LEAK_SIG_HEX];

function assertNoLeak(body: string): void {
  for (const token of LEAK_TOKENS) {
    expect(body).not.toContain(token);
  }
}

test('express error bodies contain no payload, secret or signature', async () => {
  const { app } = makeExpressApp(undefined, LEAK_SECRET);
  const tampered = await sendRaw(app, TAMPERED_BYTES, { 'x-hub-signature-256': leakSigHeader(RAW_BYTES) });
  expect(tampered.status).toBe(400);
  assertNoLeak(tampered.body);
  expect(tampered.body).toBe('Bad Request');

  const overflow = await sendRaw(makeExpressApp(1, LEAK_SECRET).app, RAW_BYTES, { 'x-hub-signature-256': leakSigHeader(RAW_BYTES) });
  expect(overflow.status).toBe(413);
  assertNoLeak(overflow.body);
  expect(overflow.body).toBe('Payload Too Large');
});

test('hono error bodies contain no payload, secret or signature', async () => {
  const app = new Hono();
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [LEAK_SECRET] }), (c) => c.text('ok', 200));

  const res = await app.request('/webhook', {
    method: 'POST',
    body: TAMPERED_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': leakSigHeader(RAW_BYTES) },
  });

  const text = await res.text();
  expect(res.status).toBe(400);
  assertNoLeak(text);
  expect(text).toBe('Bad Request');
});

test('nextjs error bodies contain no payload, secret or signature', async () => {
  const handler = createNextHandler({
    provider: 'github',
    secrets: [LEAK_SECRET],
    handler: async () => new Response('ok', { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: TAMPERED_BYTES,
    headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': leakSigHeader(RAW_BYTES) },
  }));

  const text = await res.text();
  expect(res.status).toBe(400);
  assertNoLeak(text);
  expect(text).toBe('Bad Request');
});

test('cloudflare error bodies contain no payload, secret or signature', async () => {
  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [LEAK_SECRET] }),
    handler: async () => new Response('ok', { status: 200 }),
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: TAMPERED_BYTES,
      headers: { 'content-type': 'application/octet-stream', 'x-hub-signature-256': leakSigHeader(RAW_BYTES) },
    }),
    {},
    { waitUntil: () => undefined },
  );

  const text = await res.text();
  expect(res.status).toBe(400);
  assertNoLeak(text);
  expect(text).toBe('Bad Request');
});
