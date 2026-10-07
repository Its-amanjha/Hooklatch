import { createHmac } from 'node:crypto';
import { prepareVerifier, verifyPrepared, readClock } from '../../src/internal/verification.js';
import { utf8 } from '../../src/internal/bytes.js';
import type { ProviderDescriptor } from '../../src/internal/provider.js';

const descriptor: ProviderDescriptor = {
  provider: 'stripe', decodeSecret: utf8,
  parse(headers, body) {
    const signature = headers.get('signature');
    if (!signature) return { ok: false, reason: 'missing-signature', message: 'Missing signature.' };
    return { ok: true, signatures: [Uint8Array.from(Buffer.from(signature, 'hex'))],
      signedContent: body, identity: { eventId: null, deliveryId: null,
        timestamp: Number(headers.get('timestamp') ?? 1000), authenticatedFields: ['timestamp'] } };
  },
};
function input(body = 'hello', timestamp = '1000', key = 'test-key') {
  return { rawBody: utf8(body), headers: { timestamp,
    signature: createHmac('sha256', key).update(body).digest('hex') } };
}
const options = { provider: 'stripe' as const, secrets: ['test-key'], now: () => 1000 };

test('orchestration snapshots caller bytes and secret configuration before awaits', async () => {
  const secrets = ['test-key'];
  const prepared = prepareVerifier({ ...options, secrets }, descriptor);
  secrets[0] = 'changed';
  const request = input();
  const pending = verifyPrepared(request, prepared);
  request.rawBody.fill(0);
  request.headers.signature = 'bad';
  const result = await pending;
  expect(result.ok).toBe(true);
  if (result.ok) expect(result.rawBody).toEqual(utf8('hello'));
});

test('freshness is checked only after successful cryptography and has inclusive boundaries', async () => {
  const prepared = prepareVerifier(options, descriptor);
  expect(await verifyPrepared(input('hello', '699', 'wrong'), prepared)).toMatchObject({ reason: 'invalid-signature' });
  expect(await verifyPrepared(input('hello', '699'), prepared)).toMatchObject({ reason: 'timestamp-expired' });
  expect(await verifyPrepared(input('hello', '1301'), prepared)).toMatchObject({ reason: 'timestamp-future' });
  for (const timestamp of ['700', '1300']) expect((await verifyPrepared(input('hello', timestamp), prepared)).ok).toBe(true);
});

test('zero tolerance does not bypass freshness and body limits precede parser work', async () => {
  const prepared = prepareVerifier({ ...options, toleranceSeconds: 0 }, descriptor);
  expect((await verifyPrepared(input(), prepared)).ok).toBe(true);
  expect(await verifyPrepared(input('hello', '999'), prepared)).toMatchObject({ reason: 'timestamp-expired' });
  const limited = prepareVerifier({ ...options, maxBodyBytes: 1 }, descriptor);
  expect(await verifyPrepared({ rawBody: utf8('xx'), headers: {} }, limited)).toMatchObject({ reason: 'body-too-large' });
});

test('clock exceptions and non-finite values become safe typed errors', () => {
  for (const now of [() => NaN, () => Infinity, () => { throw new Error('private'); }]) {
    expect(() => readClock(prepareVerifier({ ...options, now }, descriptor))).toThrow('Invalid verification clock.');
  }
});
