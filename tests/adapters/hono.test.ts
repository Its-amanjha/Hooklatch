import { signedHeaders } from './signing.js';
import { Hono } from 'hono';
import { createWebhookMiddleware, type WebhookVariables } from '../../src/adapters/hono.js';

test('sets webhook variable and calls next on success', async () => {
  const app = new Hono<{ Variables: WebhookVariables }>();
  app.post('/webhook', createWebhookMiddleware({ provider: 'github', secrets: ['s'] }), (c) => {
    const w = c.get('webhook');

    return c.text(`ok:${w.rawBody.byteLength}`, 200);
  });
  const res = await app.request('/webhook', { method: 'POST', body: 'hi', headers: { 'content-type': 'text/plain', ...signedHeaders('hi') } });
  expect(res.status).toBe(200);
  expect(await res.text()).toBe('ok:2');
});

test('returns 400 on verification failure', async () => {
  const app = new Hono();
  app.post('/webhook', createWebhookMiddleware({ provider: 'github', secrets: ['s'] }), (c) => c.text('ok', 200));
  const res = await app.request('/webhook', { method: 'POST', body: 'hi' });
  expect(res.status).toBe(400);
});

test('returns 413 on overflow', async () => {
  const app = new Hono();
  app.post('/webhook', createWebhookMiddleware({ provider: 'github', secrets: ['s'], maxBodyBytes: 1 }), (c) => c.text('ok', 200));
  const res = await app.request('/webhook', { method: 'POST', body: 'hello' });
  expect(res.status).toBe(413);
});

