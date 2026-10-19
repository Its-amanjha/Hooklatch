import { createHmac } from 'node:crypto';
import { createStandardWebhooksProtocol } from '../../src/providers/standard-webhooks-protocol.js';
import { verifyHmac } from '../../src/internal/crypto.js';

test('builds a literal provider descriptor before public registration', async () => {
  const descriptor = createStandardWebhooksProtocol('unregistered-protocol-test', 'Protocol test', {
    id: 'webhook-id', timestamp: 'webhook-timestamp', signature: 'webhook-signature',
  });

  const provider: 'unregistered-protocol-test' = descriptor.provider;
  const key = new Uint8Array(32).fill(17);
  const body = new Uint8Array([0, 255, 10]);
  const message = Buffer.concat([Buffer.from('msg_factory.1792368000.'), body]);
  const signature = createHmac('sha256', key).update(message).digest('base64');

  const parsed = descriptor.parse(new Map([
    ['webhook-id', 'msg_factory'], ['webhook-timestamp', '1792368000'],
    ['webhook-signature', `v1,${signature}`],
  ]), body);

  expect(provider).toBe('unregistered-protocol-test');
  expect(parsed.ok).toBe(true);

  if (!parsed.ok) throw new Error('Expected valid protocol input.');

  expect(parsed.signedContent).toEqual(new Uint8Array(message));
  expect(await verifyHmac([descriptor.decodeSecret(Buffer.from(key).toString('base64'))], parsed.signatures, parsed.signedContent)).toBe(true);
});
