import { createHmac } from 'node:crypto';
import { normalizeHeaders } from '../../src/internal/headers.js';
import { verifyHmac } from '../../src/internal/crypto.js';
import { dodoPaymentsDescriptor } from '../../src/providers/dodo-payments.js';
import { gitlabDescriptor } from '../../src/providers/gitlab.js';
import { replicateDescriptor } from '../../src/providers/replicate.js';

const KEY = Buffer.alloc(32, 23);
const BODY = new Uint8Array([255, 0, 128, 10]);
const ID = 'msg_canonical_boundary';
const TIMESTAMP = '1792368000';

const SIGNATURE = `v1,${createHmac('sha256', KEY)
  .update(Buffer.concat([Buffer.from(`${ID}.${TIMESTAMP}.`), BODY])).digest('base64')}`;

const canonical = (): [string, string][] => [
  ['webhook-id', ID], ['webhook-timestamp', TIMESTAMP], ['webhook-signature', SIGNATURE],
];

const branded: [string, string][] = [
  ['svix-id', ID], ['svix-timestamp', TIMESTAMP], ['svix-signature', SIGNATURE],
];

describe.each([dodoPaymentsDescriptor, gitlabDescriptor, replicateDescriptor])('$provider canonical-only boundaries', (descriptor) => {
  test('ignores branded headers instead of using them to repair canonical fields', () => {
    const cases: readonly { headers: [string, string][]; reason: string }[] = [
      { headers: branded, reason: 'missing-signature' },
      { headers: [...branded, ['webhook-signature', SIGNATURE]], reason: 'missing-identity' },
      { headers: [...branded, ['webhook-id', ID], ['webhook-signature', SIGNATURE]], reason: 'missing-timestamp' },
      { headers: [...branded, ['webhook-id', ID], ['webhook-signature', SIGNATURE], ['webhook-timestamp', 'invalid']], reason: 'malformed-signature' },
    ];

    for (const { headers, reason } of cases) {
      expect(descriptor.parse(normalizeHeaders(headers), BODY)).toMatchObject({ ok: false, reason });
    }
  });

  test.each(['webhook-id', 'webhook-timestamp', 'webhook-signature'])('rejects duplicate case-folded %s', (name) => {
    const headers = canonical();
    const value = headers.find(([key]) => key === name)?.[1];

    if (value === undefined) throw new Error('Missing canonical test header.');

    headers.push([name.toUpperCase(), value]);
    expect(descriptor.parse(normalizeHeaders(headers), BODY)).toMatchObject({ ok: false, reason: 'malformed-signature' });
  });

  test('authenticates canonical bytes despite divergent ignored branded metadata', async () => {
    const parsed = descriptor.parse(normalizeHeaders([
      ...canonical(), ['svix-id', 'different'], ['svix-timestamp', '0'], ['svix-signature', 'invalid'],
    ]), BODY);

    expect(parsed.ok).toBe(true);

    if (!parsed.ok) throw new Error('Expected valid canonical input.');

    expect(parsed.identity.eventId).toBe(ID);
    expect(await verifyHmac([descriptor.decodeSecret(KEY.toString('base64'))], parsed.signatures, parsed.signedContent)).toBe(true);
  });
});
