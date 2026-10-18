import { concatBytes, decodeBase64, utf8 } from '../../src/internal/bytes.js';
import { verifyHmac } from '../../src/internal/crypto.js';
import { normalizeHeaders } from '../../src/internal/headers.js';
import { standardWebhooksDescriptor as descriptor, stripeDescriptor } from '../../src/providers/index.js';
import type { HeaderInput } from '../../src/types.js';
import { base64Of, expectFailure, expectOk, headerMap, hmacBase64, ternErrorCode } from './helpers.js';

const SECRET = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
const ID = 'msg_p5jXN8AQM9LWM0D4loKWxJek';
const TIMESTAMP = '1614265330';
const BODY = utf8('{"test": 2432232314}');
const VECTOR = 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=';

const headersFor = (
  signature: string,
  id: string | null = ID,
  timestamp: string | null = TIMESTAMP,
): Record<string, string> => {
  const record: Record<string, string> = { 'webhook-signature': signature };
  if (id !== null) record['webhook-id'] = id;
  if (timestamp !== null) record['webhook-timestamp'] = timestamp;
  return record;
};

// Reference: https://github.com/standard-webhooks/standard-webhooks/blob/7537d2a2d3d52d8f2e0ecd12527af4a9307fd81b/libraries/javascript/src/webhook.test.ts
// Source license metadata caveat: docs/PROVENANCE.md#unresolved-reference-metadata.
test('verifies the published Standard Webhooks reference vector', async () => {
  const parsed = expectOk(descriptor.parse(headerMap(headersFor(VECTOR)), BODY));
  expect(parsed.signatures).toHaveLength(1);
  expect(parsed.signedContent).toEqual(concatBytes(utf8(`${ID}.${TIMESTAMP}.`), BODY));
  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: ID,
    timestamp: Number(TIMESTAMP),
    authenticatedFields: ['eventId', 'timestamp'],
  });
  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('derives the key by Base64-decoding the secret after an optional whsec_ prefix', () => {
  const expected = decodeBase64('MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw');
  expect(descriptor.decodeSecret(SECRET)).toEqual(expected);
  expect(descriptor.decodeSecret('MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw')).toEqual(expected);
  // The key deriving trap: this decoded key is not the literal secret string.
  expect(descriptor.decodeSecret(SECRET)).not.toEqual(utf8(SECRET));
  expect(descriptor.decodeSecret(SECRET)).not.toEqual(stripeDescriptor.decodeSecret(SECRET));
});

test('rejects invalid Standard Webhooks secrets with a typed error', () => {
  for (const secret of ['', 'whsec_', 'not base64!', base64Of(new Uint8Array(23)), base64Of(new Uint8Array(65))]) {
    expect(ternErrorCode(() => descriptor.decodeSecret(secret))).toBe('invalid-secret');
  }
});

test('accepts multiple whitespace-separated v1 signatures for rotation', async () => {
  const signed = concatBytes(utf8(`${ID}.${TIMESTAMP}.`), BODY);
  const retiring = hmacBase64('other-key', signed);
  const parsed = expectOk(
    descriptor.parse(headerMap(headersFor(`v1,${retiring} v1,${VECTOR.slice(3)}`)), BODY),
  );
  expect(parsed.signatures).toHaveLength(2);
  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('rejects HTTP comma-combined duplicate signature values as malformed', () => {
  const signature = VECTOR.slice(3);
  expect(
    expectFailure(
      descriptor.parse(
        headerMap({
          'webhook-id': ID,
          'webhook-timestamp': TIMESTAMP,
          'webhook-signature': [`v1,${signature}`, `v1,${signature}`],
        }),
        BODY,
      ),
    ).reason,
  ).toBe('malformed-signature');
});

test('fails closed on a malformed recognized signature even when another v1 is valid', () => {
  const signature = VECTOR.slice(3);
  for (const bad of ['@@@', 'bad', '']) {
    const header = bad === '' ? `v1, v1,${signature}` : `v1,${bad} v1,${signature}`;
    expect(expectFailure(descriptor.parse(headerMap(headersFor(header)), BODY)).reason)
      .toBe('malformed-signature');
  }
});

test('reports unsupported-only schemes and absent metadata distinctly', () => {
  expect(expectFailure(descriptor.parse(headerMap({}), BODY)).reason).toBe('missing-signature');
  expect(
    expectFailure(descriptor.parse(headerMap(headersFor('v1a,hnO3f9T8Ytu9HwrXslvumlUpqtNVqkhqw/enGzPCXe5BdqzCInXqYXFymVJaA7AZdpXwVLPo3mNl8EM+m7TBAg==')), BODY)).reason,
  ).toBe('unsupported-scheme');
  expect(expectFailure(descriptor.parse(headerMap(headersFor(VECTOR, null)), BODY)).reason)
    .toBe('missing-identity');
  expect(expectFailure(descriptor.parse(headerMap(headersFor(VECTOR, ID, null)), BODY)).reason)
    .toBe('missing-timestamp');
});

test('rejects malformed ids and timestamps as malformed signatures', () => {
  expect(expectFailure(descriptor.parse(headerMap(headersFor(VECTOR, 'has.dot')), BODY)).reason)
    .toBe('malformed-signature');
  // A comma indicates an HTTP-combined duplicate singleton id.
  expect(expectFailure(descriptor.parse(headerMap(headersFor(VECTOR, 'a, b')), BODY)).reason)
    .toBe('malformed-signature');
  for (const timestamp of ['01', '-1', '1.5', '1, 2', '99999999999999999999']) {
    expect(expectFailure(descriptor.parse(headerMap(headersFor(VECTOR, ID, timestamp)), BODY)).reason)
      .toBe('malformed-signature');
  }
  // Zero is a canonical nonnegative timestamp.
  expect(expectOk(descriptor.parse(headerMap(headersFor(VECTOR, ID, '0')), BODY)).identity.timestamp).toBe(0);
});

test('parses headers identically across record, tuple, and Headers representations', () => {
  const signature = VECTOR.slice(3);
  const tuple: [string, string][] = [
    ['Webhook-Id', ID],
    ['WEBHOOK-TIMESTAMP', TIMESTAMP],
    ['webhook-signature', `v1,${signature}`],
  ];
  const record: HeaderInput = { 'webhook-id': ID, 'webhook-timestamp': TIMESTAMP, 'webhook-signature': `${VECTOR}` };

  const fromRecord = expectOk(descriptor.parse(normalizeHeaders(record), BODY));
  const fromTuple = expectOk(descriptor.parse(normalizeHeaders(tuple), BODY));
  const fromHeaders = expectOk(descriptor.parse(normalizeHeaders(new Headers(tuple)), BODY));
  expect(fromRecord.signedContent).toEqual(fromTuple.signedContent);
  expect(fromRecord.signedContent).toEqual(fromHeaders.signedContent);
  expect(fromTuple.identity).toEqual(fromHeaders.identity);
});

test('a well-formed but wrong signature parses and fails cryptographic verification', async () => {
  const wrong = hmacBase64('wrong-key', concatBytes(utf8(`${ID}.${TIMESTAMP}.`), BODY));
  const parsed = expectOk(descriptor.parse(headerMap(headersFor(`v1,${wrong}`)), BODY));
  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(false);
});
