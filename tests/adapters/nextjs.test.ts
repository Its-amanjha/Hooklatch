import { jest } from '@jest/globals';

await jest.unstable_mockModule('../../src/index.js', () => ({
  verifyRequest: jest.fn(),
}));

const { createWebhookHandler } = await import('../../src/adapters/nextjs.js');
const { verifyRequest } = await import('../../src/index.js');
const verifyMock = verifyRequest as jest.MockedFunction<typeof verifyRequest>;

function makeRequest(body: string, headers: Record<string, string> = {}): Request {
  return new Request('https://example.test/webhook', {
    method: 'POST',
    body,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

beforeEach(() => {
  verifyMock.mockReset();
});

test('returns 400 on verification failure', async () => {
  verifyMock.mockResolvedValue({ ok: false, provider: 'github', reason: 'invalid-signature', message: 'bad' });
  const handler = createWebhookHandler({
    provider: 'github',
    secrets: ['s'],
    handler: async (_req, _success) => new Response('ok', { status: 200 }),
  });
  const res = await handler(makeRequest('{}'));
  expect(res.status).toBe(400);
});

test('passes verified raw bytes to handler', async () => {
  const raw = new TextEncoder().encode('hello');
  verifyMock.mockResolvedValue({ ok: true, provider: 'github', rawBody: raw, identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] } });
  const handler = createWebhookHandler({
    provider: 'github',
    secrets: ['s'],
    handler: async (_req, success) => new Response(String(success.rawBody.byteLength), { status: 200 }),
  });
  const res = await handler(makeRequest('hello'));
  expect(res.status).toBe(200);
  expect(await res.text()).toBe('5');
});

test('returns 413 when body exceeds limit', async () => {
  verifyMock.mockResolvedValue({ ok: false, provider: 'github', reason: 'body-too-large', message: 'too large' });
  const handler = createWebhookHandler({
    provider: 'github',
    secrets: ['s'],
    maxBodyBytes: 2,
    handler: async () => new Response('ok', { status: 200 }),
  });
  const res = await handler(makeRequest('hello'));
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
  const raw = new TextEncoder().encode('hello');
  verifyMock.mockResolvedValue({ ok: true, provider: 'github', rawBody: raw, identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] } });
  const handler = createWebhookHandler({
    provider: 'github',
    secrets: ['s'],
    handler: async () => { throw new Error('boom'); },
  });
  await expect(handler(makeRequest('hello'))).rejects.toThrow('boom');
});


