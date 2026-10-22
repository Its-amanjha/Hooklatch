import { createHmac } from 'node:crypto';
import { createVerifier, HooklatchError } from '../../src/index.js';
import { createWebhookHandler } from '../../src/adapters/nextjs.js';
import type { NextWebhookHandlerOptions } from '../../src/adapters/nextjs.js';
import type { VerifyOptions } from '../../src/index.js';

const NOW = 1700000100;
const ID = 'hidden-configuration-message';
const BODY = new TextEncoder().encode('hidden-configuration-body');
const SECRET = `whsec_${Buffer.alloc(24, 7).toString('base64')}`;

test.each(['signature', 'timestamp'] as const)('Grafana rejects an original Unicode %s header even if lowercasing makes it ASCII', (role) => {
  const options: VerifyOptions = { provider: 'grafana', secrets: [SECRET], providerOptions: role === 'signature'
    ? { mode: 'body', signatureHeader: 'X-\u212a' }
    : { mode: 'timestamped', timestampHeader: 'X-\u212a' } };

  let caught: unknown;

  try { createVerifier(options); }
  catch (error) { caught = error; }

  expect(caught).toBeInstanceOf(HooklatchError);

  if (!(caught instanceof HooklatchError)) throw new Error('Expected a typed setup failure');
  expect(caught.code).toBe('invalid-options');
});

test('Next preserves non-enumerable own Polar legacy configuration', async () => {
  let calls = 0;

  const options: NextWebhookHandlerOptions = { provider: 'polar', secrets: [SECRET], now: () => NOW,
    handler: (_request, success) => {
      calls += 1;
      expect(success.identity.eventId).toBe(ID);
      expect(success.rawBody).toEqual(BODY);

      return new Response('accepted');
    } };

  Object.defineProperty(options, 'providerOptions', { value: { secretMode: 'legacy' }, enumerable: false });
  const signature = createHmac('sha256', SECRET).update(`${ID}.${NOW}.`).update(BODY).digest('base64');

  const response = await createWebhookHandler(options)(new Request('https://hooklatch.test/', {
    method: 'POST', body: new Uint8Array(BODY), headers: {
      'webhook-id': ID, 'webhook-timestamp': String(NOW), 'webhook-signature': `v1,${signature}`,
    },
  }));

  expect(response.status).toBe(200);
  expect(await response.text()).toBe('accepted');
  expect(calls).toBe(1);
});

test.each(['github', 'polar'] as const)('Next rejects non-enumerable own undefined config for %s before body reads', async (provider) => {
  let calls = 0;

  const common = { secrets: [SECRET], now: () => NOW, handler: () => {
    calls += 1;

    return new Response('accepted');
  } };

  const options: NextWebhookHandlerOptions = provider === 'github'
    ? { ...common, provider: 'github' } : { ...common, provider: 'polar' };
  // Deliberately introduce invalid runtime presence; omission would be valid.

  Object.defineProperty(options, 'providerOptions', { value: undefined, enumerable: false });

  const signature = provider === 'github'
    ? `sha256=${createHmac('sha256', SECRET).update(BODY).digest('hex')}`
    : `v1,${createHmac('sha256', Buffer.from(SECRET.slice(6), 'base64')).update(`${ID}.${NOW}.`).update(BODY).digest('base64')}`;

  const request = new Request('https://hooklatch.test/', { method: 'POST', body: new Uint8Array(BODY), headers: {
    'x-hub-signature-256': signature, 'webhook-id': ID, 'webhook-timestamp': String(NOW), 'webhook-signature': signature,
  } });

  const response = await createWebhookHandler(options)(request);
  expect(response.status).toBe(500);
  expect(await response.text()).toBe('Internal Server Error');
  expect(request.bodyUsed).toBe(false);
  expect(calls).toBe(0);
});
