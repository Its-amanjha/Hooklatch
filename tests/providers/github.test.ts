import { utf8 } from '../../src/internal/bytes.js';
import { verifyHmac } from '../../src/internal/crypto.js';
import { githubDescriptor } from '../../src/providers/index.js';
import { expectFailure, expectOk, headerMap, hmacHex, ternErrorCode } from './helpers.js';

const SECRET = "It's a Secret to Everybody";
const BODY = utf8('Hello, World!');
const VECTOR_HEX = '757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17';
const DELIVERY = '72d3162e-cc78-11e3-81ab-4c9367dc0958';

test('verifies the published GitHub reference vector over the raw body only', async () => {
  const parsed = expectOk(
    githubDescriptor.parse(
      headerMap({ 'x-hub-signature-256': `sha256=${VECTOR_HEX}`, 'x-github-delivery': DELIVERY }),
      BODY,
    ),
  );

  // Independent cross-check that the published digest equals an HMAC we compute.
  expect(hmacHex(SECRET, BODY)).toBe(VECTOR_HEX);
  expect(parsed.signedContent).toEqual(BODY);
  expect(parsed.identity).toEqual({
    deliveryId: DELIVERY,
    eventId: null,
    timestamp: null,
    authenticatedFields: [],
  });
  expect(await verifyHmac([githubDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('rejects a body that does not match the published signature', async () => {
  const parsed = expectOk(
    githubDescriptor.parse(headerMap({ 'x-hub-signature-256': `sha256=${VECTOR_HEX}` }), utf8('Hello, World?')),
  );
  expect(await verifyHmac([githubDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(false);
});

test('accepts either hex case and keys the HMAC with the literal secret', async () => {
  const parsed = expectOk(
    githubDescriptor.parse(headerMap({ 'x-hub-signature-256': `sha256=${VECTOR_HEX.toUpperCase()}` }), BODY),
  );
  expect(await verifyHmac([githubDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
  expect(githubDescriptor.decodeSecret('secret with spaces')).toEqual(utf8('secret with spaces'));
  expect(ternErrorCode(() => githubDescriptor.decodeSecret(''))).toBe('invalid-secret');
});

test('never treats the legacy SHA-1 scheme as SHA-256', () => {
  const sha1 = hmacHex(SECRET, BODY, 'sha1');
  expect(expectFailure(githubDescriptor.parse(headerMap({ 'x-hub-signature': `sha1=${sha1}` }), BODY)).reason)
    .toBe('unsupported-scheme');
  expect(expectFailure(githubDescriptor.parse(headerMap({ 'x-hub-signature-256': `sha1=${sha1}` }), BODY)).reason)
    .toBe('unsupported-scheme');
});

test('ignores the legacy header when a valid SHA-256 signature exists', async () => {
  const parsed = expectOk(
    githubDescriptor.parse(
      headerMap({
        'x-hub-signature-256': `sha256=${VECTOR_HEX}`,
        'x-hub-signature': `sha1=${hmacHex(SECRET, BODY, 'sha1')}`,
      }),
      BODY,
    ),
  );
  expect(await verifyHmac([githubDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('reports absent and malformed signature headers distinctly', () => {
  expect(expectFailure(githubDescriptor.parse(headerMap({}), BODY)).reason).toBe('missing-signature');
  expect(expectFailure(githubDescriptor.parse(headerMap({ 'x-hub-signature-256': '   ' }), BODY)).reason)
    .toBe('missing-signature');
  for (const value of ['noscheme', 'sha256=zz', 'sha256=', 'sha256=abc']) {
    expect(expectFailure(githubDescriptor.parse(headerMap({ 'x-hub-signature-256': value }), BODY)).reason)
      .toBe('malformed-signature');
  }
  // HTTP comma-combined duplicate values cannot be a single SHA-256 header.
  expect(
    expectFailure(githubDescriptor.parse(headerMap({ 'x-hub-signature-256': ['sha256=' + VECTOR_HEX, 'sha256=' + VECTOR_HEX] }), BODY)).reason,
  ).toBe('malformed-signature');
});

test('treats a missing delivery id as unsigned optional metadata', () => {
  const parsed = expectOk(githubDescriptor.parse(headerMap({ 'x-hub-signature-256': `sha256=${VECTOR_HEX}` }), BODY));
  expect(parsed.identity.deliveryId).toBeNull();
  expect(parsed.identity.authenticatedFields).toEqual([]);
});

test('preserves exact binary body bytes as the signed content', () => {
  const body = new Uint8Array([0x00, 0xff, 0x80, 0x41, 0xc3, 0xa9]);
  const parsed = expectOk(
    githubDescriptor.parse(headerMap({ 'x-hub-signature-256': `sha256=${hmacHex(SECRET, body)}` }), body),
  );
  expect(parsed.signedContent).toEqual(body);
});
