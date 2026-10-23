import { createHash, createHmac, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { createServer } from 'node:http';
import express from 'express';
import { jest } from '@jest/globals';
import type { ErrorRequestHandler } from 'express';
import { Hono } from 'hono';
import { isTcpAddress } from './signing.js';
import type { FalVerifyOptions, VerificationSuccess } from '../../src/types.js';
import { createWebhookMiddleware as expressMiddleware } from '../../src/adapters/express.js';
import { createWebhookMiddleware as honoMiddleware } from '../../src/adapters/hono.js';
import { createWebhookHandler as nextHandler } from '../../src/adapters/nextjs.js';
import { createWebhookHandler as workerHandler } from '../../src/adapters/cloudflare.js';

jest.setTimeout(20000);

const NOW = 1700000100;
const USER = 'phase9-account';
const seed = Buffer.alloc(32, 41);
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const publicKey = new Uint8Array(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(12));
const bytes = new Uint8Array([0, 255, 254, 34, 128]);

type Framework = 'express' | 'hono' | 'nextjs' | 'cloudflare';

const frameworks: readonly Framework[] = ['express', 'hono', 'nextjs', 'cloudflare'];

type Handler = (success: VerificationSuccess) => Response;

function headers(user = USER, timestamp = NOW) {
  const requestId = 'phase9-request';
  const message = `${requestId}\n${user}\n${timestamp}\n${createHash('sha256').update(bytes).digest('hex')}`;

  return { 'x-fal-webhook-request-id': requestId, 'x-fal-webhook-user-id': user,
    'x-fal-webhook-timestamp': String(timestamp),
    'x-fal-webhook-signature': sign(null, Buffer.from(message), privateKey).toString('hex') };
}

function options(): FalVerifyOptions {
  return { provider: 'fal', publicKeys: [new Uint8Array(publicKey)], expectedUserId: USER, now: () => NOW };
}

function request(fields: Record<string, string>): Request {
  return new Request('http://localhost/webhook', { method: 'POST', headers: fields, body: new Uint8Array(bytes) });
}

async function run(
  framework: Framework, configured: FalVerifyOptions, fields: Record<string, string>, handler: Handler,
): Promise<Response> {
  if (framework === 'nextjs') {
    return nextHandler({ ...configured, handler: (_request, success) => handler(success) })(request(fields));
  }

  if (framework === 'cloudflare') {
    return workerHandler({ options: () => configured, handler: (_request, _env, _ctx, success) => handler(success) })(request(fields), {}, {});
  }

  if (framework === 'hono') {
    const app = new Hono();
    app.use('*', honoMiddleware(configured));
    app.post('/webhook', (context) => {
      const success = context.get('webhook');

      if (!success) throw new Error('Expected verification');

      return handler(success);
    });

    return app.fetch(request(fields));
  }

  const app = express();
  app.use(expressMiddleware(configured));
  app.post('/webhook', (incoming, response) => {
    if (!incoming.webhook) throw new Error('Expected verification');

    const result = handler(incoming.webhook);
    response.status(result.status).send('handled');
  });
  const errorHandler: ErrorRequestHandler = (_error, _incoming, response, _next) => { response.status(500).send('application-error'); };

  app.use(errorHandler);
  const server = createServer(app);

  await new Promise<void>((resolve) => { server.listen(0, '127.0.0.1', resolve); });

  try {
    const address = server.address();

    if (!isTcpAddress(address)) throw new Error('Expected TCP port');

    const result = await fetch(`http://127.0.0.1:${address.port}/webhook`, { method: 'POST', headers: fields, body: new Uint8Array(bytes), signal: AbortSignal.timeout(10000) });
    const text = await result.text();

    return new Response(text, { status: result.status });
  } finally {
    await new Promise<void>((resolve, reject) => { server.close((error) => { if (error) reject(error); else resolve(); }); });
  }
}

for (const framework of frameworks) {
  test(`${framework} authenticates actual fal signatures over invalid UTF8 and preserves identity`, async () => {
    let count = 0;

    const response = await run(framework, options(), headers(), (success) => {
      count++;
      expect(success.rawBody).toEqual(bytes);
      expect(success.provider).toBe('fal');
      expect(success.identity).toEqual({ deliveryId: null, eventId: null, timestamp: NOW, authenticatedFields: ['timestamp'] });

      return new Response('ok');
    });

    expect(response.status).toBe(200);
    expect(count).toBe(1);
  });

  test(`${framework} rejects an authentic delivery for a different account`, async () => {
    let count = 0;

    const response = await run(framework, options(), headers('other-account'), () => { count++;

 return new Response('bad'); });

    expect(response.status).toBe(400);
    expect(await response.text()).toBe('Bad Request');
    expect(count).toBe(0);
  });

  test(`${framework} rejects a bad MAC despite stale time and valid alien headers`, async () => {
    let count = 0;
    const fields = { ...headers(USER, NOW - 301), 'x-fal-webhook-signature': '00'.repeat(64), 'x-vercel-signature': 'aa'.repeat(20) };

    const response = await run(framework, options(), fields, () => { count++;

 return new Response('bad'); });

    expect(response.status).toBe(400);
    expect(await response.text()).toBe('Bad Request');
    expect(count).toBe(0);
  });

  test(`${framework} contains invalid key configuration before calling user code`, async () => {
    let count = 0;

    const response = await run(framework, { ...options(), publicKeys: [new Uint8Array(31)] }, headers(), () => { count++;

 return new Response('bad'); });

    expect(response.status).toBe(500);
    expect(await response.text()).toBe('Internal Server Error');
    expect(count).toBe(0);
  });
}


test('Next preserves old HMAC secret getter evaluation once at construction', async () => {
  let reads = 0;
  let current = 'original-synthetic-secret';
  const signature = createHmac('sha256', current).update(bytes).digest('hex');

  const handler = nextHandler({ provider: 'github', get secrets() { reads++;

 return [current]; }, handler: () => new Response('ok') });

  current = 'later-synthetic-secret';
  const response = await handler(request({ 'x-hub-signature-256': `sha256=${signature}` }));

  expect(response.status).toBe(200);
  expect(reads).toBe(1);
});

test('Next does not launder a self-replacing fal credential accessor into valid setup', async () => {
  const configured = { ...options(), handler: () => new Response('unexpected') };
  Object.defineProperty(configured, 'publicKeys', { enumerable: true, configurable: true,
    get() { Object.defineProperty(configured, 'publicKeys', { value: [publicKey], enumerable: true });

 return [publicKey]; } });
  const incoming = request(headers());
  const response = await nextHandler(configured)(incoming);

  expect(response.status).toBe(500);
  expect(await response.text()).toBe('Internal Server Error');
  expect(incoming.bodyUsed).toBe(false);
});

test('Next preserves valid non-enumerable fal credential data properties', async () => {
  const configured = { ...options(), handler: () => new Response('ok') };
  Object.defineProperty(configured, 'publicKeys', { value: [publicKey], enumerable: false });
  Object.defineProperty(configured, 'expectedUserId', { value: USER, enumerable: false });
  const response = await nextHandler(configured)(request(headers()));

  expect(response.status).toBe(200);
});


for (const field of ['publicKeys', 'expectedUserId']) {
  test(`Next preserves Vercel forbidden non-enumerable own ${field}`, async () => {
    const key = 'synthetic-vercel-secret';
    const signature = createHmac('sha1', key).update(bytes).digest('hex');
    const configured = { provider: 'vercel' as const, secrets: [key], handler: () => new Response('unexpected') };
    Object.defineProperty(configured, field, { value: undefined, enumerable: false });
    const incoming = request({ 'x-vercel-signature': signature });
    const response = await nextHandler(configured)(incoming);

    expect(response.status).toBe(500);
    expect(incoming.bodyUsed).toBe(false);
  });
}
