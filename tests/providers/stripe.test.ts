import { concatBytes, decodeHex, utf8 } from '../../src/internal/bytes.js';
import { verifyHmac } from '../../src/internal/crypto.js';
import { stripeDescriptor } from '../../src/providers/index.js';
import { expectFailure, expectOk, headerMap, hmacHex, ternErrorCode } from './helpers.js';

const SECRET = 'whsec_test_stripe_secret';
const NOW = 1_700_000_000;
const BODY = utf8('{"id":"evt_test","type":"payment_intent.succeeded"}');

const signedBytesFor = (timestamp: number, body: Uint8Array): Uint8Array =>
  concatBytes(utf8(`${timestamp}.`), body);

const headerFor = (timestamp: number, signatures: readonly string[]): Record<string, string> => ({
  'stripe-signature': [`t=${timestamp}`, ...signatures].join(','),
});

test('verifies a locally derived Stripe signature over the exact signed bytes', async () => {
  const signed = signedBytesFor(NOW, BODY);
  const signature = hmacHex(SECRET, signed);
  const parsed = expectOk(
    stripeDescriptor.parse(headerMap(headerFor(NOW, [`v1=${signature}`])), BODY),
  );

  expect(parsed.signatures).toHaveLength(1);
  expect(parsed.signatures[0]).toEqual(decodeHex(signature));
  expect(parsed.signedContent).toEqual(signed);
  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: NOW,
    authenticatedFields: ['timestamp'],
  });
  expect(
    await verifyHmac([stripeDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('rejects a body that does not match the signed bytes', async () => {
  const signature = hmacHex(SECRET, signedBytesFor(NOW, BODY));
  const tampered = expectOk(
    stripeDescriptor.parse(headerMap(headerFor(NOW, [`v1=${signature}`])), utf8('{"tampered":true}')),
  );
  expect(
    await verifyHmac([stripeDescriptor.decodeSecret(SECRET)], tampered.signatures, tampered.signedContent),
  ).toBe(false);
});

test('keys the HMAC with the literal secret string, including the whsec_ prefix', () => {
  expect(stripeDescriptor.decodeSecret('whsec_abc')).toEqual(utf8('whsec_abc'));
  expect(ternErrorCode(() => stripeDescriptor.decodeSecret(''))).toBe('invalid-secret');
});

test('accepts multiple v1 signatures for zero-downtime key rotation', async () => {
  const signed = signedBytesFor(NOW, BODY);
  const retiring = hmacHex('whsec_retiring', signed);
  const active = hmacHex(SECRET, signed);
  const parsed = expectOk(
    stripeDescriptor.parse(headerMap(headerFor(NOW, [`v1=${retiring}`, `v1=${active}`])), BODY),
  );

  expect(parsed.signatures).toHaveLength(2);
  expect(
    await verifyHmac([stripeDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('permits whitespace around comma-separated items and accepts either hex case', async () => {
  const signature = hmacHex(SECRET, signedBytesFor(NOW, BODY)).toUpperCase();
  const parsed = expectOk(
    stripeDescriptor.parse(
      headerMap({ 'stripe-signature': `t=${NOW}, v1=${signature}` }),
      BODY,
    ),
  );
  expect(
    await verifyHmac([stripeDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('rejects a repeated timestamp as malformed', () => {
  const signature = hmacHex(SECRET, signedBytesFor(NOW, BODY));
  for (const header of [
    `t=${NOW},t=${NOW},v1=${signature}`,
    `t=${NOW},v1=${signature},t=1`,
  ]) {
    expect(expectFailure(stripeDescriptor.parse(headerMap({ 'stripe-signature': header }), BODY)).reason)
      .toBe('malformed-signature');
  }
});

test('fails closed on a malformed recognized signature even when another v1 is valid', () => {
  const signature = hmacHex(SECRET, signedBytesFor(NOW, BODY));
  for (const bad of ['zz', 'abc']) {
    expect(
      expectFailure(stripeDescriptor.parse(headerMap(headerFor(NOW, [`v1=${bad}`, `v1=${signature}`])), BODY)).reason,
    ).toBe('malformed-signature');
  }
  // An empty v1 value is malformed even alongside a valid signature.
  expect(
    expectFailure(
      stripeDescriptor.parse(headerMap({ 'stripe-signature': `t=${NOW},v1=,v1=${signature}` }), BODY),
    ).reason,
  ).toBe('malformed-signature');
  // A 31-byte hex digest is well-formed hex but the wrong length.
  const shortHex = signature.slice(0, 62);
  expect(
    expectFailure(stripeDescriptor.parse(headerMap(headerFor(NOW, [`v1=${shortHex}`])), BODY)).reason,
  ).toBe('malformed-signature');
});

test('reports absent metadata and unsupported-only schemes distinctly', () => {
  const signature = hmacHex(SECRET, signedBytesFor(NOW, BODY));
  const hex32 = hmacHex('other', signedBytesFor(NOW, BODY));

  expect(expectFailure(stripeDescriptor.parse(headerMap({}), BODY)).reason).toBe('missing-signature');
  expect(expectFailure(stripeDescriptor.parse(headerMap({ 'stripe-signature': `t=${NOW}` }), BODY)).reason)
    .toBe('missing-signature');
  expect(expectFailure(stripeDescriptor.parse(headerMap({ 'stripe-signature': `v1=${signature}` }), BODY)).reason)
    .toBe('missing-timestamp');
  expect(expectFailure(stripeDescriptor.parse(headerMap({ 'stripe-signature': `t=${NOW},v0=${hex32}` }), BODY)).reason)
    .toBe('unsupported-scheme');
});

test('ignores a well-formed unknown scheme when a valid v1 signature exists', async () => {
  const signature = hmacHex(SECRET, signedBytesFor(NOW, BODY));
  const parsed = expectOk(
    stripeDescriptor.parse(
      headerMap({ 'stripe-signature': `t=${NOW},v0=v0value,v1=${signature}` }),
      BODY,
    ),
  );
  expect(parsed.signatures).toHaveLength(1);
  expect(
    await verifyHmac([stripeDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('preserves exact body bytes, including binary and multibyte sequences', () => {
  const body = new Uint8Array([0x00, 0xff, 0x80, 0x41, 0xc3, 0xa9, 0x2e]);
  const signature = hmacHex(SECRET, signedBytesFor(NOW, body));
  const parsed = expectOk(stripeDescriptor.parse(headerMap(headerFor(NOW, [`v1=${signature}`])), body));
  expect(parsed.signedContent).toEqual(concatBytes(utf8(`${NOW}.`), body));
  expect(parsed.signedContent.slice(utf8(`${NOW}.`).length)).toEqual(body);
});
