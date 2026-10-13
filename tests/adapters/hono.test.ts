import { jest } from '@jest/globals';
import type { WebhookVariables } from '../../src/adapters/hono.js';

await jest.unstable_mockModule('../../src/index.js', () => ({
  verifyRequest: jest.fn(),
}));

const { createWebhookMiddleware } = await import('../../src/adapters/hono.js');
const { verifyRequest } = await import('../../src/index.js');
const { Hono } = await import('hono');
const verifyMock = verifyRequest as jest.MockedFunction<typeof verifyRequest>;

beforeEach(() => verifyMock.mockReset());

test('sets webhook variable and calls next on success', async () => {
  const raw = new TextEncoder().encode('hi');
  verifyMock.mockResolvedValue({ ok: true, provider: 'github', rawBody: raw, identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] } });
  const app = new Hono<{ Variables: WebhookVariables }>();
  app.post('/webhook', createWebhookMiddleware({ provider: 'github', secrets: ['s'] }), (c) => {
    const w = c.get('webhook');
    return c.text(`ok:${w.rawBody.byteLength}`, 200);
  });
  const res = await app.request('/webhook', { method: 'POST', body: 'hi', headers: { 'content-type': 'text/plain' } });
  expect(res.status).toBe(200);
  expect(await res.text()).toBe('ok:2');
});

test('returns 400 on verification failure', async () => {
  verifyMock.mockResolvedValue({ ok: false, provider: 'github', reason: 'invalid-signature', message: 'bad' });
  const app = new Hono();
  app.post('/webhook', createWebhookMiddleware({ provider: 'github', secrets: ['s'] }), (c) => c.text('ok', 200));
  const res = await app.request('/webhook', { method: 'POST', body: 'hi' });
  expect(res.status).toBe(400);
});

test('returns 413 on overflow', async () => {
  verifyMock.mockResolvedValue({ ok: false, provider: 'github', reason: 'body-too-large', message: 'too large' });
  const app = new Hono();
  app.post('/webhook', createWebhookMiddleware({ provider: 'github', secrets: ['s'], maxBodyBytes: 1 }), (c) => c.text('ok', 200));
  const res = await app.request('/webhook', { method: 'POST', body: 'hello' });
  expect(res.status).toBe(413);
});


