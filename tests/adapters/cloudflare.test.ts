import { signedHeaders } from './signing.js';
import { createWebhookHandler } from '../../src/adapters/cloudflare.js';

test('resolves secrets from env', async () => {
  const handler = createWebhookHandler({
    options: (env: { secret: string }) => ({ provider: 'github', secrets: [env.secret] }),
    handler: async (_req, env, _ctx, success) => new Response(`${env.secret}:${success.rawBody.byteLength}`, { status: 200 }),
  });

  const res = await handler(
    new Request('https://example.test/webhook', { method: 'POST', body: 'hi', headers: signedHeaders('hi', 'shh') }),
    { secret: 'shh' },
    { waitUntil: () => undefined },
  );

  expect(res.status).toBe(200);
  expect(await res.text()).toBe('shh:2');
});

test('returns 500 on HooklatchError', async () => {
  const handler = createWebhookHandler({
    options: () => ({ provider: 'github', secrets: [] }),
    handler: async () => new Response('ok', { status: 200 }),
  });

  const res = await handler(new Request('https://example.test/webhook', { method: 'POST', body: 'hi' }), {}, {});
  expect(res.status).toBe(500);
});

