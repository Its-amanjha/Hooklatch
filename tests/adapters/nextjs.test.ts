import { signedHeaders } from './signing.js';
import { createWebhookHandler } from '../../src/adapters/nextjs.js';

function makeRequest(body: string, headers: Record<string, string> = {}): Request {
  return new Request('https://example.test/webhook', {
    method: 'POST',
    body,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

test('returns 400 on verification failure', async () => {
  const handler = createWebhookHandler({
    provider: 'github',
    secrets: ['s'],
    handler: async (_req, _success) => new Response('ok', { status: 200 }),
  });

  const res = await handler(makeRequest('{}'));
  expect(res.status).toBe(400);
});

test('passes verified raw bytes to handler', async () => {
  const handler = createWebhookHandler({
    provider: 'github',
    secrets: ['s'],
    handler: async (_req, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });

  const res = await handler(makeRequest('hello', signedHeaders('hello')));
  expect(res.status).toBe(200);
  expect(await res.text()).toBe('5');
});

test('returns 413 when body exceeds limit', async () => {
  const handler = createWebhookHandler({
    provider: 'github',
    secrets: ['s'],
    maxBodyBytes: 2,
    handler: async () => new Response('ok', { status: 200 }),
  });

  const res = await handler(makeRequest('hello', signedHeaders('hello')));
  expect(res.status).toBe(413);
});

test('returns 400 for unsupported content encoding', async () => {
  const handler = createWebhookHandler({
    provider: 'github',
    secrets: ['s'],
    handler: async () => new Response('ok', { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', {
    method: 'POST',
    body: '{}',
    headers: { 'content-encoding': 'gzip' },
  }));

  expect(res.status).toBe(400);
});

test('propagates application handler errors', async () => {
  const handler = createWebhookHandler({
    provider: 'github',
    secrets: ['s'],
    handler: async () => { throw new Error('boom'); },
  });

  await expect(handler(makeRequest('hello', signedHeaders('hello')))).rejects.toThrow('boom');
});

