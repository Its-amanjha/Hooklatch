import { isTcpAddress } from '../adapters/signing.js';
import { createHmac } from 'node:crypto';
import { HooklatchError } from '../../src/index.js';
import { createWebhookHandler as nextHandler } from '../../src/adapters/nextjs.js';
import { createWebhookHandler as workerHandler } from '../../src/adapters/cloudflare.js';
import { createWebhookMiddleware } from '../../src/adapters/express.js';
import express from 'express';

const secret = 'integration_synthetic_key';

function request(): Request {
  const body = 'hello';

  return new Request('https://example.test/hook', { method: 'POST', body,
    headers: { 'x-hub-signature-256': `sha256=${createHmac('sha256', secret).update(body).digest('hex')}` } });
}

const options = { provider: 'github' as const, secrets: [secret] };

test('Next handler HooklatchError propagates as an application error after successful verification', async () => {
  const applicationError = new HooklatchError('internal', 'Application failure');
  const handler = nextHandler({ ...options, handler() { throw applicationError; } });
  await expect(handler(request())).rejects.toBe(applicationError);
});

test('Workers handler HooklatchError propagates as an application error after successful verification', async () => {
  const applicationError = new HooklatchError('internal', 'Application failure');
  const handler = workerHandler({ options: () => options, handler() { throw applicationError; } });
  await expect(handler(request(), {}, {})).rejects.toBe(applicationError);
});

test('Web adapter rejects invalid body limits before consuming the Request', async () => {
  const input = request();
  const handler = nextHandler({ ...options, maxBodyBytes: Infinity, handler: () => new Response('ok') });
  expect((await handler(input)).status).toBe(500);
  expect(input.bodyUsed).toBe(false);
});

test('Workers option resolver failures produce a generic setup response', async () => {
  const handler = workerHandler({ options() { throw new Error('Private environment detail'); }, handler: () => new Response('ok') });
  const response = await handler(request(), {}, {});
  expect(response.status).toBe(500);
  expect(await response.text()).toBe('Internal Server Error');
});

test('Express rejects invalid body limits before pulling any stream bytes', async () => {
  let reads = 0;
  const app = express();
  app.use((req, _res, next) => {
    const originalIterator = req[Symbol.asyncIterator].bind(req);
    req[Symbol.asyncIterator] = function () {
      reads += 1;

      return originalIterator();
    };

    next();
  });
  app.use(createWebhookMiddleware({ ...options, maxBodyBytes: NaN }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });

  try {
    const address = server.address();

    if (!isTcpAddress(address)) throw new Error('Expected TCP address');
    const response = await fetch(`http://127.0.0.1:${address.port}`, { method: 'POST', body: 'unread payload' });
    expect(response.status).toBe(500);
    expect(await response.text()).toBe('Internal Server Error');
    expect(reads).toBe(0);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
