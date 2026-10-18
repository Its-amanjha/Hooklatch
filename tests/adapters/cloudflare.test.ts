import { jest } from '@jest/globals';

await jest.unstable_mockModule('../../src/index.js', () => ({
  verifyRequest: jest.fn(),
}));

const { createWebhookHandler } = await import('../../src/adapters/cloudflare.js');
const { verifyRequest } = await import('../../src/index.js');
const verifyMock = verifyRequest as jest.MockedFunction<typeof verifyRequest>;

beforeEach(() => verifyMock.mockReset());

test('resolves secrets from env', async () => {
  const raw = new TextEncoder().encode('hi');
  verifyMock.mockResolvedValue({ ok: true, provider: 'stripe', rawBody: raw, identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] } });
  const handler = createWebhookHandler({
    options: (env: { secret: string }) => ({ provider: 'stripe', secrets: [env.secret] }),
    handler: async (_req, env, _ctx, success) => new Response(`${env.secret}:${success.rawBody.byteLength}`, { status: 200 }),
  });
  const res = await handler(
    new Request('https://example.test/webhook', { method: 'POST', body: 'hi' }),
    { secret: 'shh' },
    { waitUntil: () => undefined },
  );
  expect(res.status).toBe(200);
  expect(await res.text()).toBe('shh:2');
});

test('returns 500 on HooklatchError', async () => {
  verifyMock.mockRejectedValue(Object.assign(new Error('bad'), { name: 'HooklatchError' }));
  const handler = createWebhookHandler({
    options: () => ({ provider: 'stripe', secrets: ['s'] }),
    handler: async () => new Response('ok', { status: 200 }),
  });
  const res = await handler(new Request('https://example.test/webhook', { method: 'POST', body: 'hi' }), {}, {});
  expect(res.status).toBe(500);
});


