import { verifyHmac } from '../../src/internal/crypto.js';
import { normalizeHeaders } from '../../src/internal/headers.js';
import { dodoPaymentsDescriptor as descriptor } from '../../src/providers/dodo-payments.js';
import type { HeaderInput, VerificationFailureReason } from '../../src/types.js';
import { expectFailure, expectOk, headerMap, hmacBase64, ternErrorCode } from './helpers.js';

// Synthetic phase-4 anchors only. No Dodo Payments-published signature vector is
// claimed and no live endpoint was called. All keys, ids and payloads are
// deliberately non-secret test material.
const KEY = Buffer.alloc(32, 0x44);
const OTHER_KEY = Buffer.alloc(32, 0x99);
const SECRET = KEY.toString('base64');
const ID = 'msg_phase4_dodo_0001';
const TIMESTAMP = '1792368000';

const BODY = Buffer.from(
  '{"type":"payment.succeeded","data":{"id":"pay_synthetic"},"nul":"\\u0000"}',
  'utf8',
);

const tokenFor = (key: Buffer, id: string, timestamp: string, body: Uint8Array): string =>
  `v1,${hmacBase64(key, Buffer.concat([Buffer.from(`${id}.${timestamp}.`, 'utf8'), Buffer.from(body)]))}`;

const signatureFor = (
  key: Buffer = KEY,
  id: string = ID,
  timestamp: string = TIMESTAMP,
  body: Uint8Array = BODY,
): string => tokenFor(key, id, timestamp, body);

type CanonicalHeaders = {
  'webhook-signature': string;
  'webhook-id'?: string;
  'webhook-timestamp'?: string;
}

const headersFor = (
  value: string,
  id: string | null = ID,
  timestamp: string | null = TIMESTAMP,
): CanonicalHeaders => {
  const record: CanonicalHeaders = { 'webhook-signature': value };

  if (id !== null) record['webhook-id'] = id;

  if (timestamp !== null) record['webhook-timestamp'] = timestamp;

  return record;
};

const signed = (id: string, timestamp: string, body: Uint8Array): Buffer =>
  Buffer.concat([Buffer.from(`${id}.${timestamp}.`, 'utf8'), Buffer.from(body)]);

test('verifies an independently signed canonical payload over exact raw bytes', async () => {
  // A nonzero-offset view proves the descriptor signs the received view, not a copy of a larger buffer.
  const backing = new Uint8Array(BODY.byteLength + 4);

  backing.set(BODY, 2);
  const body = backing.subarray(2, 2 + BODY.byteLength);
  const expected = signed(ID, TIMESTAMP, body);
  const parsed = expectOk(descriptor.parse(headerMap(headersFor(signatureFor(KEY, ID, TIMESTAMP, body))), body));

  expect(parsed.signatures).toHaveLength(1);
  expect(Buffer.from(parsed.signedContent).equals(expected)).toBe(true);
  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: ID,
    timestamp: Number(TIMESTAMP),
    authenticatedFields: ['eventId', 'timestamp'],
  });
  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
  expect(await verifyHmac([descriptor.decodeSecret(`whsec_${SECRET}`)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('Base64-decodes the secret, accepting an optional whsec_ prefix and 24-64 byte keys', () => {
  expect(Buffer.from(descriptor.decodeSecret(SECRET)).equals(KEY)).toBe(true);
  expect(Buffer.from(descriptor.decodeSecret(`whsec_${SECRET}`)).equals(KEY)).toBe(true);
  expect(Buffer.from(descriptor.decodeSecret(SECRET)).equals(Buffer.from(SECRET, 'utf8')))
    .toBe(false);
  expect(descriptor.decodeSecret(Buffer.alloc(24, 0x01).toString('base64')))
    .toHaveLength(24);
  expect(descriptor.decodeSecret(Buffer.alloc(64, 0x02).toString('base64')))
    .toHaveLength(64);

  const rejected = [
    '',
    'whsec_',
    'not base64!',
    Buffer.alloc(23, 0x01).toString('base64'),
    Buffer.alloc(65, 0x02).toString('base64'),
  ];

  for (const secret of rejected) {
    expect(ternErrorCode(() => descriptor.decodeSecret(secret))).toBe('invalid-secret');
  }
});

test('rejects noncanonical Base64 that decodes to the same key bytes', () => {
  const padded = KEY.toString('base64');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const finalIndex = alphabet.indexOf(padded.charAt(padded.length - 2));
  const noncanonical = `${padded.slice(0, -2)}${alphabet.charAt(finalIndex | 1)}=`;

  expect(finalIndex).toBeGreaterThanOrEqual(0);
  expect(noncanonical).not.toBe(padded);
  expect(Buffer.from(noncanonical, 'base64').equals(KEY)).toBe(true);
  expect(ternErrorCode(() => descriptor.decodeSecret(noncanonical))).toBe('invalid-secret');
  expect(ternErrorCode(() => descriptor.decodeSecret(`${padded}=`))).toBe('invalid-secret');
});

test('preserves empty, binary, NUL, BOM, invalid UTF-8, unicode and long bodies exactly', async () => {
  const backing = new Uint8Array(600);

  for (let index = 0; index < backing.byteLength; index += 1) {
    backing[index] = (index * 37) % 256;
  }

  const bodies: readonly Uint8Array[] = [
    new Uint8Array(),
    Buffer.from('not json {', 'utf8'),
    new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28]),
    new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
    new Uint8Array([0x00]),
    Buffer.from('{"unicode":"héllo-秘密"}', 'utf8'),
    backing.subarray(7, 507),
  ];

  for (const body of bodies) {
    const parsed = expectOk(descriptor.parse(headerMap(headersFor(signatureFor(KEY, ID, TIMESTAMP, body))), body));

    expect(Buffer.from(parsed.signedContent).equals(signed(ID, TIMESTAMP, body))).toBe(true);
    expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
      .toBe(true);
  }
});

test('fails cryptographic verification on body tamper, digest tamper, or a wrong key', async () => {
  const tampered = new Uint8Array(BODY);

  tampered[0] = (tampered[0] ?? 0) ^ 0x01;
  const bodyParsed = expectOk(descriptor.parse(headerMap(headersFor(signatureFor())), tampered));

  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], bodyParsed.signatures, bodyParsed.signedContent))
    .toBe(false);

  const digest = Buffer.from(signatureFor().slice(3), 'base64');

  digest[0] = (digest[0] ?? 0) ^ 0x01;

  const digestParsed = expectOk(
    descriptor.parse(headerMap(headersFor(`v1,${digest.toString('base64')}`)), BODY),
  );

  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], digestParsed.signatures, digestParsed.signedContent))
    .toBe(false);

  const valid = expectOk(descriptor.parse(headerMap(headersFor(signatureFor())), BODY));

  expect(await verifyHmac([descriptor.decodeSecret(OTHER_KEY.toString('base64'))], valid.signatures, valid.signedContent))
    .toBe(false);
});

test('accepts rotation tokens when only the second key or token matches, in both orders', async () => {
  const oldKey = Buffer.alloc(32, 0x11);
  const newKey = Buffer.alloc(32, 0x22);
  const oldSecret = oldKey.toString('base64');
  const newSecret = newKey.toString('base64');
  const oldToken = signatureFor(oldKey);
  const newToken = signatureFor(newKey);

  for (const secrets of [[oldSecret, newSecret], [newSecret, oldSecret]]) {
    const parsed = expectOk(descriptor.parse(headerMap(headersFor(newToken)), BODY));

    expect(parsed.signatures).toHaveLength(1);
    expect(await verifyHmac(
      secrets.map((secret) => descriptor.decodeSecret(secret)),
      parsed.signatures,
      parsed.signedContent,
    )).toBe(true);
  }

  for (const value of [`${oldToken} ${newToken}`, `${newToken} ${oldToken}`]) {
    const parsed = expectOk(descriptor.parse(headerMap(headersFor(value)), BODY));

    expect(parsed.signatures).toHaveLength(2);
    expect(await verifyHmac([descriptor.decodeSecret(newSecret)], parsed.signatures, parsed.signedContent))
      .toBe(true);
    expect(await verifyHmac([descriptor.decodeSecret(OTHER_KEY.toString('base64'))], parsed.signatures, parsed.signedContent))
      .toBe(false);
  }
});

test('fails closed when a recognized v1 sibling is malformed', () => {
  const valid = signatureFor();

  for (const value of [
    `v1,@@@ ${valid}`,
    `${valid} v1,@@@`,
    `${valid} v1,`,
    `v1, v1,${valid.slice(3)}`,
    `${valid} v1,AAAA`,
    `${valid} v1,${'a'.repeat(64)}`,
  ]) {
    expect(expectFailure(descriptor.parse(headerMap(headersFor(value)), BODY)).reason)
      .toBe('malformed-signature');
  }

  // HTTP comma-combination of duplicate singleton headers is malformed, not a rotation list.
  expect(expectFailure(
    descriptor.parse(headerMap({ ...headersFor(valid), 'webhook-signature': [valid, valid] }), BODY),
  ).reason).toBe('malformed-signature');
});

test('reports absent, unsupported, and required canonical fields distinctly', () => {
  expect(expectFailure(descriptor.parse(headerMap({}), BODY)).reason).toBe('missing-signature');
  expect(expectFailure(descriptor.parse(headerMap(headersFor('')), BODY)).reason).toBe('missing-signature');
  expect(expectFailure(descriptor.parse(headerMap(headersFor('   ')), BODY)).reason).toBe('missing-signature');
  expect(expectFailure(descriptor.parse(headerMap(headersFor(`v1a,${signatureFor().slice(3)}`)), BODY)).reason)
    .toBe('unsupported-scheme');
  expect(expectFailure(descriptor.parse(headerMap(headersFor('v2,abc')), BODY)).reason)
    .toBe('unsupported-scheme');
  expect(expectFailure(descriptor.parse(headerMap(headersFor(signatureFor(), null)), BODY)).reason)
    .toBe('missing-identity');
  expect(expectFailure(descriptor.parse(headerMap(headersFor(signatureFor(), '', TIMESTAMP)), BODY)).reason)
    .toBe('missing-identity');
  expect(expectFailure(descriptor.parse(headerMap(headersFor(signatureFor(), ID, null)), BODY)).reason)
    .toBe('missing-timestamp');
  expect(expectFailure(descriptor.parse(headerMap(headersFor(signatureFor(), ID, '')), BODY)).reason)
    .toBe('missing-timestamp');
  expect(expectFailure(descriptor.parse(headerMap(headersFor(signatureFor(), 'has.dot')), BODY)).reason)
    .toBe('malformed-signature');
  expect(expectFailure(descriptor.parse(headerMap(headersFor(signatureFor(), 'a, b')), BODY)).reason)
    .toBe('malformed-signature');
  expect(expectFailure(descriptor.parse(headerMap(headersFor(`v1,${signatureFor().slice(3)}`, ID, 'nope')), BODY)).reason)
    .toBe('malformed-signature');
});

test('accepts only canonical nonnegative safe-decimal timestamps', () => {
  for (const timestamp of ['0', '1', TIMESTAMP, String(Number.MAX_SAFE_INTEGER)]) {
    const parsed = expectOk(
      descriptor.parse(headerMap(headersFor(signatureFor(KEY, ID, timestamp), ID, timestamp)), BODY),
    );

    expect(parsed.identity.timestamp).toBe(Number(timestamp));
    expect(Buffer.from(parsed.signedContent).equals(signed(ID, timestamp, BODY))).toBe(true);
  }

  for (const timestamp of [
    '00', '01', '+1', '-1', '1.0', '1e3', ' 1', '1,2',
    '9007199254740992', '99999999999999999999',
  ]) {
    expect(expectFailure(
      descriptor.parse(headerMap(headersFor(signatureFor(), ID, timestamp)), BODY),
    ).reason).toBe('malformed-signature');
  }
});

test('formats identity without authenticating any vendor-specific field', () => {
  const vendorHeaders = {
    ...headersFor(signatureFor()),
    'x-dodo-payments-event-id': 'evt_synthetic_marker',
    'x-dodo-payments-signature': 'ignored',
  };

  const parsed = expectOk(descriptor.parse(headerMap(vendorHeaders), BODY));

  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: ID,
    timestamp: Number(TIMESTAMP),
    authenticatedFields: ['eventId', 'timestamp'],
  });
  expect(descriptor.provider).toBe('dodo-payments');
});

test('normalizes header name case across record, tuple, and Headers inputs', () => {
  const signature = signatureFor();

  const tuple: [string, string][] = [
    ['Webhook-Id', ID],
    ['WEBHOOK-TIMESTAMP', TIMESTAMP],
    ['webhook-signature', signature],
  ];

  const record: HeaderInput = {
    'webhook-id': ID,
    'webhook-timestamp': TIMESTAMP,
    'Webhook-Signature': signature,
  };

  const expected = signed(ID, TIMESTAMP, BODY);

  for (const headers of [
    normalizeHeaders(tuple),
    normalizeHeaders(new Headers(tuple)),
    normalizeHeaders(record),
  ]) {
    const parsed = expectOk(descriptor.parse(headers, BODY));

    expect(Buffer.from(parsed.signedContent).equals(expected)).toBe(true);
  }
});

test('returns typed failures without exposing a parsed payload', () => {
  const cases: readonly (readonly [string, VerificationFailureReason])[] = [
    ['v1,AAAA', 'malformed-signature'],
    ['v1,not-base64!', 'malformed-signature'],
  ];

  for (const [value, reason] of cases) {
    const failure = expectFailure(descriptor.parse(headerMap(headersFor(value)), BODY));

    expect(failure.reason).toBe(reason);
    expect(failure.ok).toBe(false);
    expect(failure.message.length).toBeGreaterThan(0);
  }
});
