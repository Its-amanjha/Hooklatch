import { createHmac } from 'node:crypto';
import { decodeHex, utf8 } from '../../src/internal/bytes.js';
import { verifyHmac } from '../../src/internal/crypto.js';
import type { ParseResult } from '../../src/internal/provider.js';
import { dopplerDescriptor } from '../../src/providers/doppler.js';
import { expectFailure, expectOk, headerMap, ternErrorCode } from './helpers.js';

const SECRET = 'synthetic.doppler.signing_secret';
const RETIRING_SECRET = 'synthetic.doppler.retiring_secret';
const ACTIVE_SECRET = 'synthetic.doppler.active_secret';
const OTHER_SECRET = 'synthetic.doppler.other_secret';

const SIGNATURE_HEADER = 'x-doppler-signature';
const SHA256_PREFIX = 'sha256=';

/** LOCAL SYNTHETIC ANCHOR generated with node:crypto for this repository. */
const ANCHOR_DIGEST = 'b839a94435ce1301ca883f0c49a7ff54384498b4f0c3a28f77ddb980fc1ca3ac';

const BODY = utf8('{"type":"config.updated","config":"staging","project":"synthetic"}');

/** Independent test-only HMAC anchor; never labeled as a Doppler-published vector. */
const sign = (secret: string, body: Uint8Array): string =>
  createHmac('sha256', Buffer.from(secret, 'utf8')).update(body).digest('hex');

const signedValue = (secret: string, body: Uint8Array = BODY): string =>
  `${SHA256_PREFIX}${sign(secret, body)}`;

const parse = (value: string | undefined, body: Uint8Array = BODY): ParseResult =>
  dopplerDescriptor.parse(headerMap(value === undefined ? {} : { [SIGNATURE_HEADER]: value }), body);

test('matches a fixed synthetic anchor and preserves the raw body', async () => {
  expect(sign(SECRET, BODY)).toBe(ANCHOR_DIGEST);

  const parsed = expectOk(parse(`${SHA256_PREFIX}${ANCHOR_DIGEST}`));

  expect(parsed.signatures).toEqual([decodeHex(ANCHOR_DIGEST)]);
  expect(parsed.signedContent).toEqual(BODY);

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('reports absent and whitespace-only signatures as missing', () => {
  for (const headers of [
    {},
    { [SIGNATURE_HEADER]: '' },
    { [SIGNATURE_HEADER]: '   ' },
    { [SIGNATURE_HEADER]: '\t ' },
    { authorization: `Bearer ${SECRET}` },
    { authorization: `Basic ${Buffer.from(`synthetic:${SECRET}`, 'utf8').toString('base64')}` },
  ]) {
    expect(expectFailure(dopplerDescriptor.parse(headerMap(headers), BODY)).reason).toBe('missing-signature');
  }
});

test('reports a well-formed digest under any other scheme as unsupported', () => {
  const digest = sign(SECRET, BODY);

  // The scheme decides, not the digest: `SHA256=` is a different token.
  for (const value of [`sha1=${digest}`, `SHA256=${digest}`, `v1=${digest}`, `sha-256=${digest}`]) {
    expect(expectFailure(parse(value)).reason).toBe('unsupported-scheme');
  }
});

test('reports wrong-length or non-hex digests as malformed, not unsupported', () => {
  for (const value of [
    `sha1=${'a'.repeat(40)}`,
    `sha256=${'a'.repeat(40)}`,
    `sha1=${'a'.repeat(65)}`,
  ]) {
    expect(expectFailure(parse(value)).reason).toBe('malformed-signature');
  }
});

test('rejects every nonconforming signature shape as malformed', () => {
  const digest = sign(SECRET, BODY);

  for (const value of [
    digest,
    'sha256',
    '=',
    'sha256=',
    'sha256==',
    `${SHA256_PREFIX}${digest}=${digest}`,
    `${SHA256_PREFIX}${digest},sha1=${digest}`,
    `${SHA256_PREFIX}${digest} `,
    ` ${SHA256_PREFIX}${digest}`,
    `${SHA256_PREFIX}${digest.slice(0, 63)}`,
    `${SHA256_PREFIX}${digest}0`,
    `${SHA256_PREFIX}${digest.slice(0, 63)}g`,
    `${SHA256_PREFIX}${'z'.repeat(64)}`,
    'not-a-signature',
    `sha.256=${digest}`,
    `sha+256=${digest}`,
  ]) {
    expect(expectFailure(parse(value)).reason).toBe('malformed-signature');
  }
});

test('rejects duplicate digests instead of treating them as a rotation list', () => {
  const digest = sign(SECRET, BODY);

  for (const headers of [
    { [SIGNATURE_HEADER]: `${digest},${digest}` },
    { [SIGNATURE_HEADER]: `${digest}, ${digest}` },
    { [SIGNATURE_HEADER]: [digest, digest] },
    { [SIGNATURE_HEADER]: [digest, digest.toUpperCase()] },
    { [SIGNATURE_HEADER]: [signedValue(SECRET), signedValue(SECRET)] },
    { 'X-Doppler-Signature': signedValue(SECRET), [SIGNATURE_HEADER]: signedValue(SECRET) },
  ]) {
    expect(expectFailure(dopplerDescriptor.parse(headerMap(headers), BODY)).reason).toBe('malformed-signature');
  }
});

test('accepts either digest case and treats the secret as literal UTF-8', async () => {
  const lower = expectOk(parse(`${SHA256_PREFIX}${ANCHOR_DIGEST}`));
  const upper = expectOk(parse(`${SHA256_PREFIX}${ANCHOR_DIGEST.toUpperCase()}`));

  expect(upper.signatures).toEqual(lower.signatures);

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(SECRET)], lower.signatures, lower.signedContent),
  ).toBe(true);

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(SECRET)], upper.signatures, upper.signedContent),
  ).toBe(true);

  expect(dopplerDescriptor.decodeSecret(SECRET)).toEqual(utf8(SECRET));
  expect(dopplerDescriptor.decodeSecret('whsec_literal')).toEqual(utf8('whsec_literal'));

  expect(ternErrorCode(() => dopplerDescriptor.decodeSecret(''))).toBe('invalid-secret');
});

test('uses whitespace and unicode secrets literally without normalization', async () => {
  const padded = '  synthetic doppler secret  ';
  const unicode = 'clé-秘密-🔐';

  expect(dopplerDescriptor.decodeSecret(padded)).toEqual(utf8(padded));
  expect(dopplerDescriptor.decodeSecret(unicode)).toEqual(utf8(unicode));

  const paddedParsed = expectOk(parse(signedValue(padded)));
  const unicodeParsed = expectOk(parse(signedValue(unicode)));

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(padded)], paddedParsed.signatures, paddedParsed.signedContent),
  ).toBe(true);

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(padded.trim())], paddedParsed.signatures, paddedParsed.signedContent),
  ).toBe(false);

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(unicode)], unicodeParsed.signatures, unicodeParsed.signedContent),
  ).toBe(true);

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(padded)], unicodeParsed.signatures, unicodeParsed.signedContent),
  ).toBe(false);
});

test('exposes no signed identity or freshness and ignores unsigned headers', async () => {
  const parsed = expectOk(
    dopplerDescriptor.parse(
      headerMap({
        [SIGNATURE_HEADER]: signedValue(SECRET),
        'x-doppler-timestamp': '1700000000',
        'x-doppler-delivery-id': 'dlv_synthetic_1',
        'doppler-config': 'staging',
        'user-agent': 'Doppler',
      }),
      BODY,
    ),
  );

  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: null,
    authenticatedFields: [],
  });

  expect(parsed.identity.timestamp).toBeNull();
  expect(parsed.identity.eventId).toBeNull();
  expect(parsed.identity.authenticatedFields).toEqual([]);
  expect(parsed.signatures).toHaveLength(1);
  expect(parsed.signedContent).toEqual(BODY);

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('changing unsigned headers never changes signed content or authenticity', async () => {
  const value = signedValue(SECRET);

  const first = expectOk(parse(value));

  const second = expectOk(
    dopplerDescriptor.parse(
      headerMap({ [SIGNATURE_HEADER]: value, 'x-doppler-timestamp': '1700000001', 'user-agent': 'other' }),
      BODY,
    ),
  );

  expect(first.identity).toEqual(second.identity);
  expect(first.signatures).toEqual(second.signatures);
  expect(first.signedContent).toEqual(second.signedContent);

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(SECRET)], second.signatures, second.signedContent),
  ).toBe(true);
});

test('signs the exact raw bytes, not an equivalent re-serialization', async () => {
  const parsed = expectOk(parse(signedValue(SECRET)));

  const reSerialized = utf8('{"type": "config.updated","config":"staging","project":"synthetic"}');
  const timestampPrefixed = Buffer.concat([Buffer.from('1700000000.', 'utf8'), BODY]);

  expect(parsed.signedContent).toEqual(BODY);

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(SECRET)], parsed.signatures, reSerialized),
  ).toBe(false);

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(SECRET)], parsed.signatures, timestampPrefixed),
  ).toBe(false);
});

test('verifies empty, binary, invalid UTF-8 and non-JSON bodies byte-exactly', async () => {
  for (const body of [
    new Uint8Array(),
    utf8('plain text, not JSON'),
    utf8('   \n\t '),
    new Uint8Array([0x00, 0xff, 0xfe, 0x80, 0xc3, 0x28]),
  ]) {
    const parsed = expectOk(parse(signedValue(SECRET, body), body));

    expect(parsed.signedContent).toEqual(body);

    expect(
      await verifyHmac([dopplerDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
    ).toBe(true);

    const withExtraByte = new Uint8Array(body.byteLength + 1);

    withExtraByte.set(body);

    expect(
      await verifyHmac([dopplerDescriptor.decodeSecret(SECRET)], parsed.signatures, withExtraByte),
    ).toBe(false);
  }
});

test('signs only the visible bytes of an offset body view', async () => {
  const buffer = new Uint8Array([0xde, 0xad, 0xbe, 0xef, ...utf8('{"offset":true}')]);
  const view = buffer.subarray(4);

  expect(view.byteOffset).toBe(4);
  expect(view.byteLength).toBe(buffer.byteLength - 4);

  const parsed = expectOk(parse(signedValue(SECRET, view), view));

  expect(parsed.signedContent).toEqual(view);
  expect(parsed.signedContent).not.toEqual(buffer);

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);

  // A digest over the whole buffer is not valid for the visible slice.
  const wrongRange = expectOk(parse(`${SHA256_PREFIX}${sign(SECRET, buffer)}`, view));

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(SECRET)], wrongRange.signatures, wrongRange.signedContent),
  ).toBe(false);
});

test('rejects a tampered body', async () => {
  const parsed = expectOk(parse(signedValue(SECRET)));

  const tampered = new Uint8Array(parsed.signedContent);

  tampered[10] = (tampered[10] ?? 0) ^ 0x01;

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(SECRET)], parsed.signatures, tampered),
  ).toBe(false);
});

test('rejects a signature computed with a different secret', async () => {
  const parsed = expectOk(parse(signedValue(SECRET)));

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(OTHER_SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(false);
});

test('accepts retiring and active secrets together during rotation overlap', async () => {
  const parsed = expectOk(parse(signedValue(RETIRING_SECRET)));

  expect(
    await verifyHmac([dopplerDescriptor.decodeSecret(ACTIVE_SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(false);

  expect(
    await verifyHmac(
      [dopplerDescriptor.decodeSecret(ACTIVE_SECRET), dopplerDescriptor.decodeSecret(RETIRING_SECRET)],
      parsed.signatures,
      parsed.signedContent,
    ),
  ).toBe(true);
});

test('exposes the literal doppler descriptor identity without a registry change', () => {
  expect(dopplerDescriptor.provider).toBe('doppler');
});
