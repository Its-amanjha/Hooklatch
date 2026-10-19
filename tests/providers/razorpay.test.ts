import { createHmac } from 'node:crypto';
import { decodeHex, utf8 } from '../../src/internal/bytes.js';
import { verifyHmac } from '../../src/internal/crypto.js';
import { razorpayDescriptor } from '../../src/providers/razorpay.js';
import { expectFailure, expectOk, headerMap, ternErrorCode } from './helpers.js';

const SECRET = 'synthetic_razorpay_secret';
const OLD_SECRET = 'synthetic_razorpay_old_secret';
const ACTIVE_SECRET = 'synthetic_razorpay_active_secret';
const EVENT_ID = 'evt_synthetic_1';

const BODY = utf8(
  '{"event":"payment.captured","payload":{"payment":{"entity":{"id":"pay_synthetic_1","amount":1000,"currency":"INR"}}}}',
);

/** Independent test-only HMAC anchor; never labeled as a Razorpay-published vector. */
const sign = (secret: string, body: Uint8Array): string =>
  createHmac('sha256', Buffer.from(secret, 'utf8')).update(body).digest('hex');

const signatureHeader = (signature: string) => ({
  'x-razorpay-signature': signature,
  'x-razorpay-event-id': EVENT_ID,
});

test('verifies a locally derived signature over the exact raw body', async () => {
  const signature = sign(SECRET, BODY);

  const parsed = expectOk(razorpayDescriptor.parse(headerMap(signatureHeader(signature)), BODY));

  expect(parsed.signatures).toHaveLength(1);
  expect(parsed.signatures[0]).toEqual(decodeHex(signature));
  expect(parsed.signedContent).toEqual(BODY);
  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: EVENT_ID,
    timestamp: null,
    authenticatedFields: [],
  });
  expect(
    await verifyHmac([razorpayDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('matches a fixed synthetic anchor without claiming official provenance', async () => {
  // LOCAL SYNTHETIC ANCHOR generated with node:crypto for this repository; the
  // cited Razorpay material publishes no signature test vector.
  const signature = '03c42d9505a7b836939b30543e43d9d175ab4caae8b60171f1afbfeaaed2e88e';

  expect(sign(SECRET, BODY)).toBe(signature);

  const parsed = expectOk(
    razorpayDescriptor.parse(headerMap({ 'x-razorpay-signature': signature }), BODY),
  );

  expect(
    await verifyHmac([razorpayDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('accepts either hex case and keys the HMAC with the literal secret', async () => {
  const signature = sign(SECRET, BODY).toUpperCase();

  const parsed = expectOk(razorpayDescriptor.parse(headerMap(signatureHeader(signature)), BODY));

  expect(razorpayDescriptor.decodeSecret('whsec_literal')).toEqual(utf8('whsec_literal'));
  expect(ternErrorCode(() => razorpayDescriptor.decodeSecret(''))).toBe('invalid-secret');
  expect(
    await verifyHmac([razorpayDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('rejects a tampered body and a wrong secret', async () => {
  const signature = sign(SECRET, BODY);

  const tampered = expectOk(
    razorpayDescriptor.parse(headerMap({ 'x-razorpay-signature': signature }), utf8('{"tampered":true}')),
  );

  expect(
    await verifyHmac([razorpayDescriptor.decodeSecret(SECRET)], tampered.signatures, tampered.signedContent),
  ).toBe(false);

  const original = expectOk(
    razorpayDescriptor.parse(headerMap({ 'x-razorpay-signature': signature }), BODY),
  );

  expect(
    await verifyHmac([razorpayDescriptor.decodeSecret('synthetic_other_secret')], original.signatures, original.signedContent),
  ).toBe(false);
});

test('preserves empty, non-JSON and invalid UTF-8 bodies byte-exactly', async () => {
  const bodies = [
    new Uint8Array(),
    utf8('plain text, not JSON'),
    new Uint8Array([0xff, 0xfe, 0x80, 0x00, 0xc3]),
  ];

  for (const body of bodies) {
    const parsed = expectOk(
      razorpayDescriptor.parse(headerMap({ 'x-razorpay-signature': sign(SECRET, body) }), body),
    );

    expect(parsed.signedContent).toEqual(body);
    expect(
      await verifyHmac([razorpayDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
    ).toBe(true);
  }
});

test('accepts old and new secrets together for retry-overlap rotation', async () => {
  const retrySignature = sign(OLD_SECRET, BODY);

  const parsed = expectOk(
    razorpayDescriptor.parse(headerMap({ 'x-razorpay-signature': retrySignature }), BODY),
  );

  expect(
    await verifyHmac([razorpayDescriptor.decodeSecret(ACTIVE_SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(false);
  expect(
    await verifyHmac(
      [razorpayDescriptor.decodeSecret(ACTIVE_SECRET), razorpayDescriptor.decodeSecret(OLD_SECRET)],
      parsed.signatures,
      parsed.signedContent,
    ),
  ).toBe(true);
});

test('uses whitespace and unicode secrets literally without normalization', async () => {
  const padded = '  synthetic secret with spaces  ';
  const unicode = 'clé-秘密-🔐';

  expect(razorpayDescriptor.decodeSecret(padded)).toEqual(utf8(padded));
  expect(razorpayDescriptor.decodeSecret(unicode)).toEqual(utf8(unicode));

  const paddedInput = expectOk(
    razorpayDescriptor.parse(headerMap({ 'x-razorpay-signature': sign(padded, BODY) }), BODY),
  );

  expect(
    await verifyHmac([razorpayDescriptor.decodeSecret(padded)], paddedInput.signatures, paddedInput.signedContent),
  ).toBe(true);
  expect(
    await verifyHmac([razorpayDescriptor.decodeSecret(padded.trim())], paddedInput.signatures, paddedInput.signedContent),
  ).toBe(false);

  const parsed = expectOk(
    razorpayDescriptor.parse(headerMap({ 'x-razorpay-signature': sign(unicode, BODY) }), BODY),
  );

  expect(
    await verifyHmac([razorpayDescriptor.decodeSecret(unicode)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
  expect(
    await verifyHmac([razorpayDescriptor.decodeSecret(padded)], parsed.signatures, parsed.signedContent),
  ).toBe(false);
});

test('reports absent and whitespace-only signatures as missing', () => {
  for (const headers of [
    {},
    { 'x-razorpay-signature': '' },
    { 'x-razorpay-signature': '   ' },
    { 'x-razorpay-event-id': EVENT_ID, 'x-razorpay-signature': '\t ' },
  ]) {
    expect(expectFailure(razorpayDescriptor.parse(headerMap(headers), BODY)).reason).toBe('missing-signature');
  }
});

test('rejects prefixed, non-hex, wrong-length and duplicate signature values as malformed', () => {
  const signature = sign(SECRET, BODY);

  for (const header of [
    `sha256=${signature}`,
    `v1=${signature}`,
    'zz'.repeat(32),
    signature.slice(0, 62),
    `${signature}00`,
    'not-a-signature',
  ]) {
    expect(
      expectFailure(razorpayDescriptor.parse(headerMap({ 'x-razorpay-signature': header }), BODY)).reason,
    ).toBe('malformed-signature');
  }

  expect(
    expectFailure(razorpayDescriptor.parse(headerMap({ 'x-razorpay-signature': '' }), BODY)).reason,
  ).toBe('missing-signature');

  // HTTP comma-combined duplicates and explicit lists are never one digest.
  for (const value of [
    [signature, signature],
    [signature, sign(SECRET, BODY).toUpperCase()],
    [`${signature},${signature}`],
    [`${signature}, ${signature}`],
  ]) {
    expect(
      expectFailure(
        razorpayDescriptor.parse(headerMap({ 'x-razorpay-signature': value }), BODY),
      ).reason,
    ).toBe('malformed-signature');
  }

  // A 31-byte hex payload paired with an otherwise valid event ID still fails.
  expect(
    expectFailure(
      razorpayDescriptor.parse(
        headerMap({ 'x-razorpay-signature': signature.slice(0, 62), 'x-razorpay-event-id': EVENT_ID }),
        BODY,
      ),
    ).reason,
  ).toBe('malformed-signature');
});

test('maps the optional event header to unsigned identity without trimming', async () => {
  const signature = sign(SECRET, BODY);

  for (const [headers, expected] of [
    [{ 'x-razorpay-signature': signature }, null],
    [{ 'x-razorpay-signature': signature, 'x-razorpay-event-id': '   ' }, null],
    [{ 'x-razorpay-signature': signature, 'x-razorpay-event-id': EVENT_ID }, EVENT_ID],
    [{ 'x-razorpay-signature': signature, 'x-razorpay-event-id': ` ${EVENT_ID} ` }, ` ${EVENT_ID} `],
  ] as const) {
    const parsed = expectOk(razorpayDescriptor.parse(headerMap(headers), BODY));

    expect(parsed.identity).toEqual({
      deliveryId: null,
      eventId: expected,
      timestamp: null,
      authenticatedFields: [],
    });
    expect(parsed.signedContent).toEqual(BODY);
    expect(
      await verifyHmac([razorpayDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
    ).toBe(true);
  }
});

test('changing the unsigned event header never changes signed content or authenticity', async () => {
  const signature = sign(SECRET, BODY);

  const first = expectOk(
    razorpayDescriptor.parse(
      headerMap({ 'x-razorpay-signature': signature, 'x-razorpay-event-id': EVENT_ID }),
      BODY,
    ),
  );

  const second = expectOk(
    razorpayDescriptor.parse(
      headerMap({ 'x-razorpay-signature': signature, 'x-razorpay-event-id': 'evt_other' }),
      BODY,
    ),
  );

  expect(first.signedContent).toEqual(second.signedContent);
  expect(first.identity.eventId).not.toBe(second.identity.eventId);
  expect(first.identity.authenticatedFields).toEqual([]);
  expect(first.identity.timestamp).toBeNull();
  expect(
    await verifyHmac([razorpayDescriptor.decodeSecret(SECRET)], second.signatures, second.signedContent),
  ).toBe(true);
});

test('exposes the literal razorpay descriptor identity without a registry change', () => {
  expect(razorpayDescriptor.provider).toBe('razorpay');
});
