import { concatBytes, utf8 } from '../../src/internal/bytes.js';
import { verifyHmac } from '../../src/internal/crypto.js';
import { normalizeHeaders } from '../../src/internal/headers.js';
import { paddleDescriptor as descriptor } from '../../src/providers/paddle.js';
import type { HeaderInput } from '../../src/types.js';
import { expectFailure, expectOk, headerMap, hmacHex, ternErrorCode } from './helpers.js';

// Official Paddle Node SDK fixtures, pinned at commit
// 651261beddfc65ba5f861729dca17044cbeffb5f.
// Source: https://github.com/PaddleHQ/paddle-node-sdk/blob/651261beddfc65ba5f861729dca17044cbeffb5f/src/__tests__/notifications/webhooks-validator.node.test.ts
// Docs: https://developer.paddle.com/webhooks/about/signature-verification/
const SECRET = 'VALID_SECRET';
const TIMESTAMP = '1698796800';
const BODY = utf8('{"data": ["1", "2"]}');
const VECTOR_HEX = 'a300428748dce5c70e4da19bffd60769591ea969c99dea3105d0ec9612cf43f9';
const BODY_2 = utf8('{"data": "value"}');
const VECTOR_HEX_2 = '28981e941fae76e53db32f3d2a83cb69db41476595e84e1970a1b5d98f62b261';

// Synthetic (not provider-published) rotation vector.
const ROTATE_BODY = utf8('{"event_id":"evt_synthetic_rotate","event_type":"subscription.updated"}');
const OLD_SECRET = 'pdl_ntfset_synthetic_old_secret';
const NEW_SECRET = 'pdl_ntfset_synthetic_new_secret';
const OLD_HEX = 'd0a559f180607c27b0cd5edf19f8cefa8518a2c17e85c8726a9a738946833786';
const NEW_HEX = '35062070dd72913bbb4cdfe602fd454beda571cd72838eab3f7c77da9a1e7177';

const signed = (timestamp: string, body: Uint8Array): Uint8Array => concatBytes(utf8(`${timestamp}:`), body);
const header = (value: string): ReturnType<typeof headerMap> => headerMap({ 'paddle-signature': value });

test('verifies the published Paddle vector over exact timestamp text and raw body', async () => {
  const parsed = expectOk(descriptor.parse(header(`ts=${TIMESTAMP};h1=${VECTOR_HEX}`), BODY));

  // Independent re-computation of the pinned official fixture.
  expect(hmacHex(SECRET, signed(TIMESTAMP, BODY))).toBe(VECTOR_HEX);
  expect(parsed.signedContent).toEqual(signed(TIMESTAMP, BODY));
  expect(parsed.signatures).toHaveLength(1);
  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: Number(TIMESTAMP),
    authenticatedFields: ['timestamp'],
  });
  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('accepts the published repeated-h1 plus unknown-h2 fixture', async () => {
  const value = `ts=${TIMESTAMP};h1=${VECTOR_HEX_2};h1=${VECTOR_HEX_2};h2=RANDOM_HASH`;
  const parsed = expectOk(descriptor.parse(header(value), BODY_2));

  expect(hmacHex(SECRET, signed(TIMESTAMP, BODY_2))).toBe(VECTOR_HEX_2);
  expect(parsed.signatures).toHaveLength(2);
  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('accepts distinct h1 values as a Hooklatch rotation accept-set', async () => {
  const parsed = expectOk(descriptor.parse(header(`ts=${TIMESTAMP};h1=${OLD_HEX};h1=${NEW_HEX}`), ROTATE_BODY));

  expect(parsed.signatures).toHaveLength(2);
  expect(await verifyHmac([descriptor.decodeSecret(OLD_SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
  expect(await verifyHmac([descriptor.decodeSecret(NEW_SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
  expect(await verifyHmac([descriptor.decodeSecret('pdl_ntfset_unrelated')], parsed.signatures, parsed.signedContent))
    .toBe(false);
});

test('fails closed when any h1 is malformed, even beside a valid h1', () => {
  for (const bad of ['zz', 'abc', 'g'.repeat(64), VECTOR_HEX.slice(1), `${VECTOR_HEX}00`]) {
    expect(expectFailure(descriptor.parse(header(`ts=${TIMESTAMP};h1=${bad};h1=${VECTOR_HEX}`), BODY)).reason)
      .toBe('malformed-signature');
    expect(expectFailure(descriptor.parse(header(`ts=${TIMESTAMP};h1=${VECTOR_HEX};h1=${bad}`), BODY)).reason)
      .toBe('malformed-signature');
  }
});

test('accepts either hex case for h1', async () => {
  for (const value of [VECTOR_HEX.toUpperCase(), VECTOR_HEX.replace(/[a-f]/g, (char) => char.toUpperCase())]) {
    const parsed = expectOk(descriptor.parse(header(`ts=${TIMESTAMP};h1=${value}`), BODY));
    expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
      .toBe(true);
  }
});

test('accepts only canonical nonnegative safe decimal timestamps', () => {
  for (const timestamp of ['0', '1', TIMESTAMP, String(Number.MAX_SAFE_INTEGER)]) {
    const parsed = expectOk(descriptor.parse(header(`ts=${timestamp};h1=${VECTOR_HEX}`), BODY));
    expect(parsed.identity.timestamp).toBe(Number(timestamp));
    expect(parsed.signedContent).toEqual(signed(timestamp, BODY));
  }

  const malformed = [
    '', '00', '01', '+1', '-1', '1.0', '1e3', ' 1', '1,2',
    '9007199254740992', '99999999999999999999',
  ];

  for (const timestamp of malformed) {
    expect(expectFailure(descriptor.parse(header(`ts=${timestamp};h1=${VECTOR_HEX}`), BODY)).reason)
      .toBe('malformed-signature');
  }

  // Outer segment whitespace is trimmed: `ts=1 ` in a segment is canonical again.
  expect(expectOk(descriptor.parse(header(`ts=1 ;h1=${VECTOR_HEX}`), BODY)).identity.timestamp).toBe(1);
});

test('rejects duplicate ts fields even when their values agree', () => {
  expect(expectFailure(descriptor.parse(header(`ts=${TIMESTAMP};ts=${TIMESTAMP};h1=${VECTOR_HEX}`), BODY)).reason)
    .toBe('malformed-signature');
  expect(expectFailure(descriptor.parse(header(`ts=${TIMESTAMP};ts=1698796801;h1=${VECTOR_HEX}`), BODY)).reason)
    .toBe('malformed-signature');
});

test('ignores structurally valid unknown fields but rejects invalid ones', () => {
  expect(expectOk(descriptor.parse(header(`ts=${TIMESTAMP};h1=${VECTOR_HEX};h2=RANDOM_HASH`), BODY)).ok)
    .toBe(true);
  expect(expectOk(descriptor.parse(header(` ts=${TIMESTAMP} ; h1=${VECTOR_HEX} ; future_TOKEN=abc-123 `), BODY)).ok)
    .toBe(true);

  const malformed = [
    'ts=1698796800;h1=' + VECTOR_HEX + ';h2=a=b',
    'ts=1698796800;h1=' + VECTOR_HEX + ';h2=a b',
    'ts=1698796800;h1=' + VECTOR_HEX + ';h2=',
    'ts=1698796800;h1=' + VECTOR_HEX + ';h2=a,b',
    'ts=1698796800;h1=' + VECTOR_HEX + ';h2=a;',
    'ts=1698796800;h1=' + VECTOR_HEX + ';;',
    'ts=1698796800;h1=' + VECTOR_HEX + ';bad key=value',
    'ts=1698796800;h1=' + VECTOR_HEX + ';=value',
  ];

  for (const value of malformed) {
    expect(expectFailure(descriptor.parse(header(value), BODY)).reason).toBe('malformed-signature');
  }
});

test('reports missing, unsupported, and ordering failures distinctly', () => {
  expect(expectFailure(descriptor.parse(header(''), BODY)).reason).toBe('missing-signature');
  expect(expectFailure(descriptor.parse(header('   '), BODY)).reason).toBe('missing-signature');
  expect(expectFailure(descriptor.parse(header(`ts=${TIMESTAMP}`), BODY)).reason).toBe('missing-signature');
  expect(expectFailure(descriptor.parse(header('h2=RANDOM_HASH'), BODY)).reason).toBe('unsupported-scheme');
  expect(expectFailure(descriptor.parse(header(`ts=${TIMESTAMP};h2=RANDOM_HASH`), BODY)).reason)
    .toBe('unsupported-scheme');
  expect(expectFailure(descriptor.parse(header(`h1=${VECTOR_HEX}`), BODY)).reason).toBe('missing-timestamp');
  expect(expectFailure(descriptor.parse(header(`ts=bad;h1=${VECTOR_HEX}`), BODY)).reason)
    .toBe('malformed-signature');
  expect(expectFailure(descriptor.parse(header('ts=bad;h2=RANDOM_HASH'), BODY)).reason)
    .toBe('malformed-signature');
});

test('rejects comma-combined duplicate header values', () => {
  expect(expectFailure(descriptor.parse(header(`ts=${TIMESTAMP};h1=${VECTOR_HEX},h1=${VECTOR_HEX}`), BODY)).reason)
    .toBe('malformed-signature');
});

test('never treats an unauthenticated future timestamp differently at parse time', () => {
  // The descriptor formats and returns identity only; clock policy belongs to core.
  const parsed = expectOk(descriptor.parse(header(`ts=9999999999;h1=${VECTOR_HEX}`), BODY));
  expect(parsed.identity.timestamp).toBe(9999999999);
});

test('a tampered body parses but fails cryptographic verification', async () => {
  const parsed = expectOk(descriptor.parse(header(`ts=${TIMESTAMP};h1=${VECTOR_HEX}`), utf8('{"data": ["1", "3"]}')));

  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(false);
});

test('preserves non-JSON, empty, and invalid UTF-8 raw body bytes exactly', async () => {
  const bodies = [
    utf8('not json {'),
    new Uint8Array(0),
    new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28]),
  ];

  for (const body of bodies) {
    const signature = hmacHex(SECRET, signed(TIMESTAMP, body));
    const parsed = expectOk(descriptor.parse(header(`ts=${TIMESTAMP};h1=${signature}`), body));

    expect(parsed.signedContent).toEqual(signed(TIMESTAMP, body));
    expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
      .toBe(true);
  }
});

test('keeps the literal Paddle secret, untrimmed, with no prefix inference', () => {
  expect(descriptor.decodeSecret(OLD_SECRET)).toEqual(utf8(OLD_SECRET));
  expect(descriptor.decodeSecret(' padded secret ')).toEqual(utf8(' padded secret '));
  expect(descriptor.decodeSecret(OLD_SECRET)).not.toEqual(utf8(OLD_SECRET.replace('pdl_ntfset_', '')));

  // Same nonempty-literal policy as other providers: only empty is rejected.
  expect(ternErrorCode(() => descriptor.decodeSecret(''))).toBe('invalid-secret');
});

test('normalizes header name case across record, tuple, and Headers inputs', () => {
  const expected = expectOk(descriptor.parse(header(`ts=${TIMESTAMP};h1=${VECTOR_HEX}`), BODY));
  const tuple: [string, string][] = [['Paddle-Signature', `ts=${TIMESTAMP};h1=${VECTOR_HEX}`]];
  const record: HeaderInput = { 'PADDLE-SIGNATURE': `ts=${TIMESTAMP};h1=${VECTOR_HEX}` };

  const fromTuple = expectOk(descriptor.parse(normalizeHeaders(tuple), BODY));
  const fromHeaders = expectOk(descriptor.parse(normalizeHeaders(new Headers(tuple)), BODY));
  const fromRecord = expectOk(descriptor.parse(normalizeHeaders(record), BODY));

  expect(fromTuple.signedContent).toEqual(expected.signedContent);
  expect(fromHeaders.signedContent).toEqual(expected.signedContent);
  expect(fromRecord.signedContent).toEqual(expected.signedContent);
});
