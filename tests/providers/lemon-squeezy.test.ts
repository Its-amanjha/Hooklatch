import { utf8 } from '../../src/internal/bytes.js';
import { verifyHmac } from '../../src/internal/crypto.js';
import { normalizeHeaders } from '../../src/internal/headers.js';
import { lemonSqueezyDescriptor } from '../../src/providers/lemon-squeezy.js';
import { expectFailure, expectOk, headerMap, hmacHex, ternErrorCode } from './helpers.js';

// Synthetic anchors computed independently with node:crypto. The research
// review found no published vector in the cited signing documentation:
// https://docs.lemonsqueezy.com/help/webhooks/signing-requests
// No fixture below is labeled official.
const SECRET = 'synthetic_lemon_secret';

const BODY = utf8(
  '{"meta":{"event_name":"order_created"},"data":{"type":"orders","id":"1","attributes":{"status":"paid"}}}',
);

const ANCHOR_HEX = 'e79a0b1cbfed5b8942144dadc958880e24616a50bdc347c23184d8565d36b47a';

test('verifies a synthetic hex anchor over the exact raw body', async () => {
  // Recompute the recorded synthetic anchor independently inside this suite.
  expect(hmacHex(SECRET, BODY)).toBe(ANCHOR_HEX);

  const parsed = expectOk(lemonSqueezyDescriptor.parse(headerMap({ 'x-signature': ANCHOR_HEX }), BODY));

  expect(lemonSqueezyDescriptor.provider).toBe('lemon-squeezy');
  expect(parsed.signatures).toHaveLength(1);
  expect(parsed.signedContent).toEqual(BODY);
  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: null,
    authenticatedFields: [],
  });
  expect(await verifyHmac([lemonSqueezyDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('accepts uppercase hex and a case-insensitive header name', async () => {
  const parsed = expectOk(
    lemonSqueezyDescriptor.parse(headerMap({ 'X-Signature': ANCHOR_HEX.toUpperCase() }), BODY),
  );

  expect(await verifyHmac([lemonSqueezyDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('rejects a tampered body and a wrong secret', async () => {
  const tampered = expectOk(
    lemonSqueezyDescriptor.parse(
      headerMap({ 'x-signature': ANCHOR_HEX }),
      utf8('{"meta":{"event_name":"order_updated"}}'),
    ),
  );

  expect(await verifyHmac([lemonSqueezyDescriptor.decodeSecret(SECRET)], tampered.signatures, tampered.signedContent))
    .toBe(false);

  const valid = expectOk(lemonSqueezyDescriptor.parse(headerMap({ 'x-signature': ANCHOR_HEX }), BODY));

  expect(await verifyHmac([lemonSqueezyDescriptor.decodeSecret('other_secret')], valid.signatures, valid.signedContent))
    .toBe(false);
});

test('reports absent and blank signature headers as missing', () => {
  expect(expectFailure(lemonSqueezyDescriptor.parse(headerMap({}), BODY)).reason).toBe('missing-signature');
  expect(expectFailure(lemonSqueezyDescriptor.parse(headerMap({ 'x-signature': '' }), BODY)).reason)
    .toBe('missing-signature');
  expect(expectFailure(lemonSqueezyDescriptor.parse(headerMap({ 'x-signature': '   ' }), BODY)).reason)
    .toBe('missing-signature');
});

test('rejects malformed signature values', () => {
  for (const value of [
    'not-a-signature',
    `sha256=${ANCHOR_HEX}`,
    ANCHOR_HEX.slice(0, 63),
    ANCHOR_HEX.slice(0, 62),
    `${ANCHOR_HEX}ab`,
    'g'.repeat(64),
    ` ${ANCHOR_HEX}`,
  ]) {
    expect(expectFailure(lemonSqueezyDescriptor.parse(headerMap({ 'x-signature': value }), BODY)).reason)
      .toBe('malformed-signature');
  }
});

test('rejects duplicate and comma-combined header values', () => {
  // HTTP comma-combined duplicates are never a valid single hex digest.
  expect(
    expectFailure(
      lemonSqueezyDescriptor.parse(headerMap({ 'x-signature': [ANCHOR_HEX, ANCHOR_HEX] }), BODY),
    ).reason,
  ).toBe('malformed-signature');

  // The same duplicate delivered as a raw header pair list.
  const repeated = normalizeHeaders([
    ['x-signature', ANCHOR_HEX],
    ['X-Signature', ANCHOR_HEX],
  ]);

  expect(expectFailure(lemonSqueezyDescriptor.parse(repeated, BODY)).reason).toBe('malformed-signature');
});

test('preserves empty, non-JSON, and non-UTF-8 bodies byte-exactly', async () => {
  const empty = new Uint8Array();

  const emptyParsed = expectOk(
    lemonSqueezyDescriptor.parse(headerMap({ 'x-signature': hmacHex(SECRET, empty) }), empty),
  );

  expect(emptyParsed.signedContent).toEqual(empty);
  expect(await verifyHmac([lemonSqueezyDescriptor.decodeSecret(SECRET)], emptyParsed.signatures, emptyParsed.signedContent))
    .toBe(true);

  const nonJson = utf8('not json at all');

  const nonJsonParsed = expectOk(
    lemonSqueezyDescriptor.parse(headerMap({ 'x-signature': hmacHex(SECRET, nonJson) }), nonJson),
  );

  expect(nonJsonParsed.signedContent).toEqual(nonJson);
  expect(await verifyHmac([lemonSqueezyDescriptor.decodeSecret(SECRET)], nonJsonParsed.signatures, nonJsonParsed.signedContent))
    .toBe(true);

  const binary = new Uint8Array([0xff, 0xfe, 0x80, 0x00, 0x41]);

  const binaryParsed = expectOk(
    lemonSqueezyDescriptor.parse(headerMap({ 'x-signature': hmacHex(SECRET, binary) }), binary),
  );

  expect(binaryParsed.signedContent).toEqual(binary);
  expect(await verifyHmac([lemonSqueezyDescriptor.decodeSecret(SECRET)], binaryParsed.signatures, binaryParsed.signedContent))
    .toBe(true);
});

test('keys the HMAC with the literal untrimmed secret, including unicode', () => {
  expect(lemonSqueezyDescriptor.decodeSecret('sëcret 🔑 padded ')).toEqual(utf8('sëcret 🔑 padded '));
  expect(lemonSqueezyDescriptor.decodeSecret('secret with spaces')).toEqual(utf8('secret with spaces'));
  expect(ternErrorCode(() => lemonSqueezyDescriptor.decodeSecret(''))).toBe('invalid-secret');
});

test('accepts a configured key rotation set via verifyHmac', async () => {
  const parsed = expectOk(lemonSqueezyDescriptor.parse(headerMap({ 'x-signature': ANCHOR_HEX }), BODY));
  const retiring = lemonSqueezyDescriptor.decodeSecret('retiring_secret');
  const active = lemonSqueezyDescriptor.decodeSecret(SECRET);

  expect(await verifyHmac([retiring, active], parsed.signatures, parsed.signedContent)).toBe(true);
  expect(await verifyHmac([retiring], parsed.signatures, parsed.signedContent)).toBe(false);
});

test('does not require or interpret an event-name header', () => {
  const parsed = expectOk(
    lemonSqueezyDescriptor.parse(
      headerMap({ 'x-signature': ANCHOR_HEX, 'X-Event-Name': 'order_created' }),
      BODY,
    ),
  );

  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: null,
    authenticatedFields: [],
  });
});
