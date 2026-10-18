import { utf8 } from '../../src/internal/bytes.js';
import { verifyHmac } from '../../src/internal/crypto.js';
import { shopifyDescriptor } from '../../src/providers/index.js';
import { base64Of, expectFailure, expectOk, headerMap, hmacBase64, ternErrorCode } from './helpers.js';

const SECRET = 'shpss_test_client_secret';
const BODY = utf8('{"id":9554194432293,"title":"T-Shirt"}');
const DELIVERY = 'wh_delivery_1';
const EVENT = 'ev_merchant_action_1';

test('verifies a locally derived Shopify Base64 HMAC over the exact raw body', async () => {
  const signature = hmacBase64(SECRET, BODY);

  const parsed = expectOk(
    shopifyDescriptor.parse(
      headerMap({
        'x-shopify-hmac-sha256': signature,
        'x-shopify-webhook-id': DELIVERY,
        'x-shopify-event-id': EVENT,
      }),
      BODY,
    ),
  );

  expect(parsed.signatures).toHaveLength(1);
  expect(parsed.signedContent).toEqual(BODY);
  expect(parsed.identity).toEqual({
    deliveryId: DELIVERY,
    eventId: EVENT,
    timestamp: null,
    authenticatedFields: [],
  });
  expect(await verifyHmac([shopifyDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('rejects a tampered body and accepts canonical unpadded Base64', async () => {
  const padded = hmacBase64(SECRET, BODY);
  const unpadded = padded.replace(/=+$/, '');

  const parsed = expectOk(
    shopifyDescriptor.parse(headerMap({ 'x-shopify-hmac-sha256': unpadded }), BODY),
  );

  expect(await verifyHmac([shopifyDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);

  const tampered = expectOk(
    shopifyDescriptor.parse(headerMap({ 'x-shopify-hmac-sha256': padded }), utf8('{"id":1}')),
  );

  expect(await verifyHmac([shopifyDescriptor.decodeSecret(SECRET)], tampered.signatures, tampered.signedContent))
    .toBe(false);
});

test('reports absent and malformed signature headers distinctly', () => {
  expect(expectFailure(shopifyDescriptor.parse(headerMap({}), BODY)).reason).toBe('missing-signature');
  expect(expectFailure(shopifyDescriptor.parse(headerMap({ 'x-shopify-hmac-sha256': '  ' }), BODY)).reason)
    .toBe('missing-signature');

  for (const value of ['@@@', 'not base64', 'Zg==', 'Zg', base64Of(new Uint8Array(31))]) {
    expect(expectFailure(shopifyDescriptor.parse(headerMap({ 'x-shopify-hmac-sha256': value }), BODY)).reason)
      .toBe('malformed-signature');
  }

  // HTTP comma-combined duplicate values are never a valid single Base64 value.
  expect(
    expectFailure(
      shopifyDescriptor.parse(
        headerMap({ 'x-shopify-hmac-sha256': [hmacBase64(SECRET, BODY), hmacBase64(SECRET, BODY)] }),
        BODY,
      ),
    ).reason,
  ).toBe('malformed-signature');
});

test('treats delivery and event ids as unsigned optional metadata', async () => {
  const parsed = expectOk(
    shopifyDescriptor.parse(headerMap({ 'x-shopify-hmac-sha256': hmacBase64(SECRET, BODY) }), BODY),
  );

  expect(parsed.identity.deliveryId).toBeNull();
  expect(parsed.identity.eventId).toBeNull();
  expect(parsed.identity.authenticatedFields).toEqual([]);
  expect(await verifyHmac([shopifyDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('keys the HMAC with the literal client secret and preserves binary bodies', () => {
  expect(shopifyDescriptor.decodeSecret('shpss_abc')).toEqual(utf8('shpss_abc'));
  expect(ternErrorCode(() => shopifyDescriptor.decodeSecret(''))).toBe('invalid-secret');

  const body = new Uint8Array([0x00, 0xff, 0x80, 0x41]);

  const parsed = expectOk(
    shopifyDescriptor.parse(headerMap({ 'x-shopify-hmac-sha256': hmacBase64(SECRET, body) }), body),
  );

  expect(parsed.signedContent).toEqual(body);
});
