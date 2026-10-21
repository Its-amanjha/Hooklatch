
import { Hono } from 'hono';

import { createWebhookHandler as createNextHandler } from '../../src/adapters/nextjs.js';
import { createWebhookHandler as createWorkerHandler } from '../../src/adapters/cloudflare.js';
import { createWebhookMiddleware as createHonoMiddleware } from '../../src/adapters/hono.js';
import { readNodeStream } from '../../src/adapters/shared.js';
// (no signing helper needed; signatures are computed with node:crypto)

/**
 * Phase 6 Stage A â€” genuinely new stream-boundary regressions.
 *
 * Builds on (does not duplicate) the Phase 3 byte-contract and Phase 4
 * lifecycle suites. New ground here:
 *   - an overflowing producer whose underlying cancel REJECTS (Phase 4 only
 *     covered a cancel that never resolves);
 *   - distinguishing cancel *requested* from cancel *settled*;
 *   - partial valid byte chunks followed by an overflow (Phase 4 enqueued a
 *     single oversized chunk);
 *   - zero-length chunks before a real overflow;
 *   - readNodeStream partial-chunk and zero-length-chunk overflow (helper level).
 *
 * Uses the shipped GitHub provider as the common signing recipe and
 * node:crypto (test-only) for HMAC. No production code, shared helper,
 * config, or other test file is changed. No module mocks, no casts for
 * unsupported framework inputs, no new dependencies.
 */

const SECRET = 's';

// ---------------------------------------------------------------------------
// 1. Web Request: overflowing producer whose cancel REJECTS
// ---------------------------------------------------------------------------

async function assertOverflowWithRejectingCancel(handle: (request: Request) => Promise<Response>): Promise<void> {
  let settleReject: (err: Error) => void = () => {};
  let markCancelEntered: () => void = () => {};
  const cancelPending = new Promise<void>((_resolve, reject) => { settleReject = reject; });
  const cancelEntered = new Promise<void>((resolve) => { markCancelEntered = resolve; });
  let cancelCalled = false;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(2)); // oversized relative to maxBodyBytes: 1
      // Keep the source open so cancelling invokes the underlying cancel callback.
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
    headers: { 'content-type': 'application/octet-stream' },
    // @ts-expect-error duplex is required by Node for streaming bodies
    duplex: 'half',
  });

  const response = handle(request);
  let checkpoint: ReturnType<typeof setImmediate> | undefined;

  try {
    const outcome = await Promise.race([
      response.then((value) => ({ kind: 'response' as const, status: value.status })),
      new Promise<{ kind: 'pending' }>((resolve) => {
        checkpoint = setImmediate(() => resolve({ kind: 'pending' }));
      }),
    ]);

    expect(cancelCalled).toBe(true);
    await cancelEntered;
    // cancel was *requested* (called) but its settlement is still pending/rejected;
    // the adapter must have resolved the response before that settlement.
    expect(outcome).toEqual({ kind: 'response', status: 413 });

    // Release the pending cancel rejection so nothing dangles. The adapter
    // swallows it via reader.cancel().catch(() => undefined), so no unhandled
    // rejection should surface.
    settleReject(new Error('cancel rejected'));
    await response;
  } finally {
    if (checkpoint !== undefined) clearImmediate(checkpoint);
    settleReject(new Error('cancel rejected'));
    await response.catch(() => undefined);
  }
}

test('nextjs returns 413 when the overflowing producer cancel rejects', async () => {
  let called = false;

  const handler = createNextHandler({
    provider: 'github',
    secrets: [SECRET],
    maxBodyBytes: 1,
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  await assertOverflowWithRejectingCancel(handler);
  expect(called).toBe(false);
});

test('cloudflare returns 413 when the overflowing producer cancel rejects', async () => {
  let called = false;

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [SECRET], maxBodyBytes: 1 }),
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  await assertOverflowWithRejectingCancel((request) => handler(request, {}, { waitUntil: () => undefined }));
  expect(called).toBe(false);
});

// ---------------------------------------------------------------------------
// 2. Web Request: partial valid byte chunks followed by an overflow
// ---------------------------------------------------------------------------

test('nextjs returns 413 when a later chunk pushes a partial valid body over the limit', async () => {
  let called = false;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(1)); // under a limit of 2
      controller.enqueue(new Uint8Array(2)); // total 3 > 2
      controller.close();
    },
  });

  const handler = createNextHandler({
    provider: 'github',
    secrets: [SECRET],
    maxBodyBytes: 2,
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: stream,
    headers: { 'content-type': 'application/octet-stream' },
    // @ts-expect-error duplex is required by some runtimes for streaming bodies
    duplex: 'half',
  }));

  expect(res.status).toBe(413);
  expect(await res.text()).toBe('Payload Too Large');
  expect(called).toBe(false);
});

test('cloudflare returns 413 when a later chunk pushes a partial valid body over the limit', async () => {
  let called = false;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(1));
      controller.enqueue(new Uint8Array(2));
      controller.close();
    },
  });

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [SECRET], maxBodyBytes: 2 }),
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: stream,
      headers: { 'content-type': 'application/octet-stream' },
      // @ts-expect-error duplex is required by some runtimes for streaming bodies
      duplex: 'half',
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(413);
  expect(await res.text()).toBe('Payload Too Large');
  expect(called).toBe(false);
});

test('hono returns 413 when a later chunk pushes a partial valid body over the limit', async () => {
  let called = false;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(1));
      controller.enqueue(new Uint8Array(2));
      controller.close();
    },
  });

  const app = new Hono();
  app.post('/webhook', createHonoMiddleware({ provider: 'github', secrets: [SECRET], maxBodyBytes: 2 }), (c) => {
    called = true;

    return c.text('ok', 200);
  });

  const res = await app.request('/webhook', {
    method: 'POST',
    body: stream,
    headers: { 'content-type': 'application/octet-stream' },
    // @ts-expect-error duplex is required by some runtimes for streaming bodies
    duplex: 'half',
  });

  expect(res.status).toBe(413);
  expect(await res.text()).toBe('Payload Too Large');
  expect(called).toBe(false);
});

// ---------------------------------------------------------------------------
// 3. Web Request: zero-length chunks before a real overflow
// ---------------------------------------------------------------------------

test('nextjs returns 413 when zero-length chunks precede an oversized chunk', async () => {
  let called = false;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(0));
      controller.enqueue(new Uint8Array(0));
      controller.enqueue(new Uint8Array(2));
      controller.close();
    },
  });

  const handler = createNextHandler({
    provider: 'github',
    secrets: [SECRET],
    maxBodyBytes: 1,
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: stream,
    headers: { 'content-type': 'application/octet-stream' },
    // @ts-expect-error duplex is required by some runtimes for streaming bodies
    duplex: 'half',
  }));

  expect(res.status).toBe(413);
  expect(await res.text()).toBe('Payload Too Large');
  expect(called).toBe(false);
});

test('cloudflare returns 413 when zero-length chunks precede an oversized chunk', async () => {
  let called = false;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(0));
      controller.enqueue(new Uint8Array(0));
      controller.enqueue(new Uint8Array(2));
      controller.close();
    },
  });

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [SECRET], maxBodyBytes: 1 }),
    handler: async () => { called = true;

 return new Response('ok', { status: 200 }); },
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: stream,
      headers: { 'content-type': 'application/octet-stream' },
      // @ts-expect-error duplex is required by some runtimes for streaming bodies
      duplex: 'half',
    }),
    {},
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(413);
  expect(await res.text()).toBe('Payload Too Large');
  expect(called).toBe(false);
});

// ---------------------------------------------------------------------------
// 4. Express (readNodeStream): partial and zero-length chunk overflow
// ---------------------------------------------------------------------------

test('readNodeStream returns 413 when a later chunk pushes a partial valid body over the limit', async () => {
  async function* chunks() {
    yield new Uint8Array(1);
    yield new Uint8Array(2);
  }

  await expect(readNodeStream(chunks(), 2)).rejects.toMatchObject({ status: 413 });
});

test('readNodeStream returns 413 when zero-length chunks precede an oversized chunk', async () => {
  async function* chunks() {
    yield new Uint8Array(0);
    yield new Uint8Array(0);
    yield new Uint8Array(2);
  }

  await expect(readNodeStream(chunks(), 1)).rejects.toMatchObject({ status: 413 });
});

test('readNodeStream returns 500 when the stream errors after partial valid bytes', async () => {
  async function* chunks() {
    yield new Uint8Array(1);
    throw new Error('stream broke midway');
  }

  await expect(readNodeStream(chunks(), 100)).rejects.toMatchObject({ status: 500 });
});

// ---------------------------------------------------------------------------
// 5. Generic error bodies omit distinct long canaries
// ---------------------------------------------------------------------------

const CANARY_PAYLOAD = 'phase6-stream-canary-payload-9f2e1a2b';
const CANARY_SECRET = 'phase6-stream-canary-secret-7b3d2c4e';
const CANARY_SIGNATURE_HEX = 'phase6streamcanarysignaturehex4a8c1f2e3b5d7a9c';
const CANARY_ID = 'phase6-stream-canary-delivery-id-1e7b3c5d';

const CANARY_TOKENS = [CANARY_PAYLOAD, CANARY_SECRET, CANARY_SIGNATURE_HEX, CANARY_ID];

function assertNoCanary(body: string): void {
  for (const token of CANARY_TOKENS) {
    expect(body).not.toContain(token);
  }
}

test('nextjs overflow error body omits canaries', async () => {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(2));
      controller.close();
    },
  });

  const handler = createNextHandler({
    provider: 'github',
    secrets: [CANARY_SECRET],
    maxBodyBytes: 1,
    handler: async () => new Response('ok', { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: stream,
    headers: { 'content-type': 'application/octet-stream' },
    // @ts-expect-error duplex is required by some runtimes for streaming bodies
    duplex: 'half',
  }));

  const text = await res.text();
  expect(res.status).toBe(413);
  expect(text).toBe('Payload Too Large');
  assertNoCanary(text);
});

test('cloudflare overflow error body omits canaries', async () => {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(2));
      controller.close();
    },
  });

  const handler = createWorkerHandler({
    options: () => ({ provider: 'github', secrets: [CANARY_SECRET], maxBodyBytes: 1 }),
    handler: async () => new Response('ok', { status: 200 }),
  });

  const res = await handler(
    new Request('https://example.test/webhook', {
      method: 'POST',
      body: stream,
      headers: { 'content-type': 'application/octet-stream' },
      // @ts-expect-error duplex is required by some runtimes for streaming bodies
      duplex: 'half',
    }),
    {},
    { waitUntil: () => undefined },
  );

  const text = await res.text();
  expect(res.status).toBe(413);
  expect(text).toBe('Payload Too Large');
  assertNoCanary(text);
});
