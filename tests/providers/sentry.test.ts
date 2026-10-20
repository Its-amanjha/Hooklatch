import { createHmac } from 'node:crypto';
import { decodeHex, utf8 } from '../../src/internal/bytes.js';
import { verifyHmac } from '../../src/internal/crypto.js';
import { sentryDescriptor } from '../../src/providers/sentry.js';
import { expectFailure, expectOk, headerMap, ternErrorCode } from './helpers.js';

const SECRET = 'synthetic.sentry.7d1f0c2a';
const OLD_SECRET = 'synthetic.sentry.old.5b21';
const ACTIVE_SECRET = 'synthetic.sentry.active.9c43';

/**
 * Synthetic JSON body with explicit spaces and a trailing newline.
 * These are local test bytes, not claimed output of Sentry's serializer.
 */
const BODY = utf8(
  '{"action": "created", "installation": {"uuid": "00000000-0000-4000-8000-000000000001"}, "data": {"issue": {"id": "1001"}}}\n',
);

const UNSIGNED_HEADERS = {
  'request-id': 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
  'sentry-hook-resource': 'issue',
  'sentry-hook-timestamp': '1792450000',
};

/** Independent test-only HMAC anchor; never labeled as a Sentry-published vector. */
const sign = (secret: string, body: Uint8Array): string =>
  createHmac('sha256', Buffer.from(secret, 'utf8')).update(body).digest('hex');

const signatureHeader = (signature: string) => ({ 'sentry-hook-signature': signature });

test('verifies a locally derived signature over the exact raw body', async () => {
  const signature = sign(SECRET, BODY);

  const parsed = expectOk(
    sentryDescriptor.parse(
      headerMap({ 'Sentry-Hook-Signature': signature, ...UNSIGNED_HEADERS }),
      BODY,
    ),
  );

  expect(parsed.signatures).toHaveLength(1);
  expect(parsed.signatures[0]).toEqual(decodeHex(signature));
  expect(parsed.signedContent).toEqual(BODY);
  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: null,
    authenticatedFields: [],
  });
  expect(
    await verifyHmac([sentryDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('matches a fixed synthetic anchor without claiming official provenance', async () => {
  // LOCAL SYNTHETIC ANCHOR: computed with node:crypto from the fixed bytes above.
  // Sentry publishes no complete signature tuple; this is not an official vector.
  const signature = '91c86d49b76d59bfe2541883902d32887c8003309c140e0a0f3f590d7b957917';

  expect(sign(SECRET, BODY)).toBe(signature);

  const parsed = expectOk(sentryDescriptor.parse(headerMap(signatureHeader(signature)), BODY));

  expect(
    await verifyHmac([sentryDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('accepts either hex case and keys the HMAC with the literal secret', async () => {
  const signature = sign(SECRET, BODY).toUpperCase();

  const parsed = expectOk(sentryDescriptor.parse(headerMap(signatureHeader(signature)), BODY));

  expect(sentryDescriptor.decodeSecret('synthetic.prefix.literal')).toEqual(
    utf8('synthetic.prefix.literal'),
  );
  expect(ternErrorCode(() => sentryDescriptor.decodeSecret(''))).toBe('invalid-secret');
  expect(
    await verifyHmac([sentryDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('rejects a tampered body and a wrong secret separately', async () => {
  const signature = sign(SECRET, BODY);

  const tampered = expectOk(
    sentryDescriptor.parse(
      headerMap(signatureHeader(signature)),
      utf8('{"tampered":true}'),
    ),
  );

  expect(
    await verifyHmac([sentryDescriptor.decodeSecret(SECRET)], tampered.signatures, tampered.signedContent),
  ).toBe(false);

  const original = expectOk(sentryDescriptor.parse(headerMap(signatureHeader(signature)), BODY));

  expect(
    await verifyHmac(
      [sentryDescriptor.decodeSecret('synthetic.sentry.wrong')],
      original.signatures,
      original.signedContent,
    ),
  ).toBe(false);
});

test('preserves empty, non-JSON, invalid UTF-8 and view bodies byte-exactly', async () => {
  const backing = new Uint8Array([0xaa, 0xff, 0xfe, 0x80, 0x00, 0xc3, 0xbb]);
  const view = backing.subarray(2, 6);

  const bodies = [
    new Uint8Array(),
    utf8('plain text, not JSON'),
    new Uint8Array([0xff, 0xfe, 0x80, 0x00, 0xc3]),
    view,
  ];

  for (const body of bodies) {
    const parsed = expectOk(
      sentryDescriptor.parse(headerMap(signatureHeader(sign(SECRET, body))), body),
    );

    expect(parsed.signedContent).toEqual(body);
    expect(
      await verifyHmac([sentryDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
    ).toBe(true);
  }

  const parsedView = expectOk(
    sentryDescriptor.parse(headerMap(signatureHeader(sign(SECRET, view))), view),
  );

  expect(parsedView.signedContent).toBe(view);
  expect(parsedView.signedContent.byteOffset).toBe(view.byteOffset);
});

test('accepts old and new secrets together for retry-overlap rotation', async () => {
  const retrySignature = sign(OLD_SECRET, BODY);

  const parsed = expectOk(
    sentryDescriptor.parse(headerMap(signatureHeader(retrySignature)), BODY),
  );

  expect(
    await verifyHmac([sentryDescriptor.decodeSecret(ACTIVE_SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(false);
  expect(
    await verifyHmac(
      [sentryDescriptor.decodeSecret(ACTIVE_SECRET), sentryDescriptor.decodeSecret(OLD_SECRET)],
      parsed.signatures,
      parsed.signedContent,
    ),
  ).toBe(true);
});

test('uses whitespace and unicode secrets literally without normalization', async () => {
  const padded = '  synthetic sentry secret with spaces  ';
  const unicode = 'clé-秘密-🔐';

  expect(sentryDescriptor.decodeSecret(padded)).toEqual(utf8(padded));
  expect(sentryDescriptor.decodeSecret(unicode)).toEqual(utf8(unicode));

  const paddedInput = expectOk(
    sentryDescriptor.parse(headerMap(signatureHeader(sign(padded, BODY))), BODY),
  );

  expect(
    await verifyHmac([sentryDescriptor.decodeSecret(padded)], paddedInput.signatures, paddedInput.signedContent),
  ).toBe(true);
  expect(
    await verifyHmac(
      [sentryDescriptor.decodeSecret(padded.trim())],
      paddedInput.signatures,
      paddedInput.signedContent,
    ),
  ).toBe(false);

  const unicodeInput = expectOk(
    sentryDescriptor.parse(headerMap(signatureHeader(sign(unicode, BODY))), BODY),
  );

  expect(
    await verifyHmac([sentryDescriptor.decodeSecret(unicode)], unicodeInput.signatures, unicodeInput.signedContent),
  ).toBe(true);
  expect(
    await verifyHmac([sentryDescriptor.decodeSecret(padded)], unicodeInput.signatures, unicodeInput.signedContent),
  ).toBe(false);
});

test('reports absent and whitespace-only signatures as missing', () => {
  for (const headers of [
    {},
    { 'sentry-hook-signature': '' },
    { 'sentry-hook-signature': '   ' },
    { 'sentry-hook-signature': '\t ' },
    { ...UNSIGNED_HEADERS },
  ]) {
    expect(expectFailure(sentryDescriptor.parse(headerMap(headers), BODY)).reason).toBe('missing-signature');
  }
});

test('rejects prefixed, non-hex, wrong-length, whitespace and duplicate values as malformed', () => {
  const signature = sign(SECRET, BODY);

  for (const header of [
    `sha256=${signature}`,
    `v1=${signature}`,
    'zz'.repeat(32),
    signature.slice(0, 62),
    `${signature}00`,
    'not-a-signature',
    ` ${signature}`,
    `${signature} `,
    ` ${signature} `,
    `${signature.slice(0, 32)} ${signature.slice(32)}`,
    `${signature}\t`,
  ]) {
    expect(
      expectFailure(sentryDescriptor.parse(headerMap({ 'sentry-hook-signature': header }), BODY)).reason,
    ).toBe('malformed-signature');
  }

  for (const value of [
    [signature, signature],
    [signature, signature.toUpperCase()],
    [`${signature},${signature}`],
    [`${signature}, ${signature}`],
  ]) {
    expect(
      expectFailure(sentryDescriptor.parse(headerMap({ 'sentry-hook-signature': value }), BODY)).reason,
    ).toBe('malformed-signature');
  }
});

test('ignores unsigned timestamp, resource and request-id headers', async () => {
  const signature = sign(SECRET, BODY);
  const baseline = expectOk(sentryDescriptor.parse(headerMap(signatureHeader(signature)), BODY));

  const mutations = [
    { 'sentry-hook-timestamp': '0' },
    { 'sentry-hook-timestamp': '9999999999' },
    { 'sentry-hook-resource': 'installation' },
    { 'request-id': 'ffffffffffffffffffffffffffffffff' },
    {
      'request-id': '00000000000000000000000000000000',
      'sentry-hook-resource': 'event',
      'sentry-hook-timestamp': '1',
    },
  ];

  for (const mutation of mutations) {
    const parsed = expectOk(
      sentryDescriptor.parse(
        headerMap({ 'sentry-hook-signature': signature, ...mutation }),
        BODY,
      ),
    );

    expect(parsed.signedContent).toEqual(baseline.signedContent);
    expect(parsed.identity).toEqual({
      deliveryId: null,
      eventId: null,
      timestamp: null,
      authenticatedFields: [],
    });
    expect(
      await verifyHmac([sentryDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
    ).toBe(true);
  }
});

test('binds the signature to raw bytes rather than an equivalent JSON value', async () => {
  const signature = sign(SECRET, BODY);

  const compact = utf8(
    '{"action":"created","installation":{"uuid":"00000000-0000-4000-8000-000000000001"},"data":{"issue":{"id":"1001"}}}\n',
  );

  expect(compact).not.toEqual(BODY);

  const parsed = expectOk(sentryDescriptor.parse(headerMap(signatureHeader(signature)), compact));

  expect(
    await verifyHmac([sentryDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(false);
});

test('exposes the literal sentry descriptor identity without a registry change', () => {
  expect(sentryDescriptor.provider).toBe('sentry');
});
