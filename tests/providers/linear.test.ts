import { createHmac } from 'node:crypto';
import { decodeHex, utf8 } from '../../src/internal/bytes.js';
import { verifyHmac } from '../../src/internal/crypto.js';
import { linearDescriptor } from '../../src/providers/linear.js';
import { expectFailure, expectOk, headerMap, ternErrorCode } from './helpers.js';

const SECRET = 'synthetic.linear.secret.4f8c';
const OLD_SECRET = 'synthetic.linear.old.8a21';
const ACTIVE_SECRET = 'synthetic.linear.active.6c73';

/**
 * Synthetic JSON with explicit spaces and a trailing newline. This is local test
 * data, not a claimed Linear serializer output.
 */
const BODY = utf8(
  '{"action":"create","type":"Issue","data":{"id":"issue_123","identifier":"SYN-1"}}\n',
);

const UNSIGNED_HEADERS = {
  'linear-delivery': 'delivery_00000000000000000000000000000001',
  'linear-event': 'Issue.create',
  'linear-timestamp': '1792450000',
};

/** Independent test-only HMAC anchor; never labeled as a Linear-published vector. */
const sign = (secret: string, body: Uint8Array): string =>
  createHmac('sha256', Buffer.from(secret, 'utf8')).update(body).digest('hex');

const signatureHeader = (signature: string) => ({ 'linear-signature': signature });

test('verifies a locally derived signature over the exact raw body', async () => {
  const signature = sign(SECRET, BODY);

  const parsed = expectOk(
    linearDescriptor.parse(
      headerMap({ 'Linear-Signature': signature, ...UNSIGNED_HEADERS }),
      BODY,
    ),
  );

  expect(parsed.signatures).toHaveLength(1);
  expect(parsed.signatures[0]).toEqual(decodeHex(signature));
  expect(parsed.signedContent).toBe(BODY);
  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: null,
    authenticatedFields: [],
  });
  expect(
    await verifyHmac([linearDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('matches a fixed synthetic anchor without claiming official provenance', async () => {
  // LOCAL SYNTHETIC ANCHOR: computed with node:crypto from the fixed bytes above.
  // Linear publishes no complete signature tuple; this is not an official vector.
  const signature = '3dc878180f7c67ef9bc00cdaba0ea2f8765fcacf503cbb068f39d7db792bf9b4';

  expect(sign(SECRET, BODY)).toBe(signature);

  const parsed = expectOk(linearDescriptor.parse(headerMap(signatureHeader(signature)), BODY));

  expect(
    await verifyHmac([linearDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('accepts either hex case and uses the literal secret as the HMAC key', async () => {
  const signature = sign(SECRET, BODY);

  const parsed = expectOk(
    linearDescriptor.parse(headerMap(signatureHeader(signature.toUpperCase())), BODY),
  );

  expect(parsed.signatures[0]).toEqual(decodeHex(signature));
  expect(linearDescriptor.decodeSecret('synthetic.linear.literal')).toEqual(
    utf8('synthetic.linear.literal'),
  );
  expect(ternErrorCode(() => linearDescriptor.decodeSecret(''))).toBe('invalid-secret');
  expect(
    await verifyHmac([linearDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(true);
});

test('preserves empty, binary, invalid UTF-8 and view bodies byte-exactly', async () => {
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
      linearDescriptor.parse(headerMap(signatureHeader(sign(SECRET, body))), body),
    );

    expect(parsed.signedContent).toEqual(body);
    expect(
      await verifyHmac([linearDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
    ).toBe(true);
  }

  const parsedView = expectOk(
    linearDescriptor.parse(headerMap(signatureHeader(sign(SECRET, view))), view),
  );

  expect(parsedView.signedContent).toBe(view);
  expect(parsedView.signedContent.byteOffset).toBe(view.byteOffset);
});

test('rejects a tampered body and a wrong secret separately', async () => {
  const signature = sign(SECRET, BODY);

  const tampered = expectOk(
    linearDescriptor.parse(
      headerMap(signatureHeader(signature)),
      utf8('{"tampered":true}'),
    ),
  );

  expect(
    await verifyHmac([linearDescriptor.decodeSecret(SECRET)], tampered.signatures, tampered.signedContent),
  ).toBe(false);

  const original = expectOk(linearDescriptor.parse(headerMap(signatureHeader(signature)), BODY));

  expect(
    await verifyHmac(
      [linearDescriptor.decodeSecret('synthetic.linear.wrong')],
      original.signatures,
      original.signedContent,
    ),
  ).toBe(false);
});

test('accepts old and new secrets together for retry-overlap rotation', async () => {
  const retrySignature = sign(OLD_SECRET, BODY);

  const parsed = expectOk(
    linearDescriptor.parse(headerMap(signatureHeader(retrySignature)), BODY),
  );

  expect(
    await verifyHmac([linearDescriptor.decodeSecret(ACTIVE_SECRET)], parsed.signatures, parsed.signedContent),
  ).toBe(false);
  expect(
    await verifyHmac(
      [linearDescriptor.decodeSecret(ACTIVE_SECRET), linearDescriptor.decodeSecret(OLD_SECRET)],
      parsed.signatures,
      parsed.signedContent,
    ),
  ).toBe(true);
});

test('uses whitespace-only, padded and unicode secrets literally without normalization', async () => {
  const whitespace = '   ';
  const padded = '  synthetic linear secret with spaces  ';
  const unicode = 'clé-秘密-🔐';

  expect(linearDescriptor.decodeSecret(whitespace)).toEqual(utf8(whitespace));
  expect(linearDescriptor.decodeSecret(padded)).toEqual(utf8(padded));
  expect(linearDescriptor.decodeSecret(unicode)).toEqual(utf8(unicode));

  const paddedInput = expectOk(
    linearDescriptor.parse(headerMap(signatureHeader(sign(padded, BODY))), BODY),
  );

  expect(
    await verifyHmac([linearDescriptor.decodeSecret(padded)], paddedInput.signatures, paddedInput.signedContent),
  ).toBe(true);
  expect(
    await verifyHmac(
      [linearDescriptor.decodeSecret(padded.trim())],
      paddedInput.signatures,
      paddedInput.signedContent,
    ),
  ).toBe(false);

  const whitespaceInput = expectOk(
    linearDescriptor.parse(headerMap(signatureHeader(sign(whitespace, BODY))), BODY),
  );

  expect(
    await verifyHmac(
      [linearDescriptor.decodeSecret(whitespace)],
      whitespaceInput.signatures,
      whitespaceInput.signedContent,
    ),
  ).toBe(true);

  const unicodeInput = expectOk(
    linearDescriptor.parse(headerMap(signatureHeader(sign(unicode, BODY))), BODY),
  );

  expect(
    await verifyHmac([linearDescriptor.decodeSecret(unicode)], unicodeInput.signatures, unicodeInput.signedContent),
  ).toBe(true);
});

test('reports absent and whitespace-only signatures as missing', () => {
  for (const headers of [
    {},
    { 'linear-signature': '' },
    { 'linear-signature': '   ' },
    { 'linear-signature': '\t ' },
    { ...UNSIGNED_HEADERS },
  ]) {
    expect(expectFailure(linearDescriptor.parse(headerMap(headers), BODY))).toMatchObject({
      reason: 'missing-signature',
      message: 'No Linear signature header was provided.',
    });
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
    'é'.repeat(64),
  ]) {
    expect(expectFailure(linearDescriptor.parse(headerMap({ 'linear-signature': header }), BODY)))
      .toMatchObject({
        reason: 'malformed-signature',
        message: 'The Linear signature header is malformed.',
      });
  }

  for (const value of [
    [signature, signature],
    [signature, signature.toUpperCase()],
    [`${signature},${signature}`],
    [`${signature}, ${signature}`],
  ]) {
    expect(expectFailure(linearDescriptor.parse(headerMap({ 'linear-signature': value }), BODY)).reason)
      .toBe('malformed-signature');
  }
});

test('ignores unsigned timestamp, delivery, event and alien authentication headers', async () => {
  const signature = sign(SECRET, BODY);
  const baseline = expectOk(linearDescriptor.parse(headerMap(signatureHeader(signature)), BODY));

  const mutations = [
    { 'linear-delivery': '0' },
    { 'linear-delivery': 'ffffffffffffffffffffffffffffffff' },
    { 'linear-event': 'Issue.update' },
    { 'linear-timestamp': '0' },
    { 'linear-timestamp': '9999999999' },
    { 'x-hub-signature-256': `sha256=${signature}` },
    { 'stripe-signature': `t=1,v1=${signature}` },
    { 'svix-signature': `v1,${signature}` },
    { 'x-linear-signature': signature },
    {
      'linear-delivery': '00000000000000000000000000000000',
      'linear-event': 'Comment.create',
      'linear-timestamp': '1',
    },
  ];

  for (const mutation of mutations) {
    const parsed = expectOk(
      linearDescriptor.parse(
        headerMap({ 'linear-signature': signature, ...mutation }),
        BODY,
      ),
    );

    expect(parsed.signedContent).toBe(baseline.signedContent);
    expect(parsed.identity).toEqual({
      deliveryId: null,
      eventId: null,
      timestamp: null,
      authenticatedFields: [],
    });
    expect(
      await verifyHmac([linearDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent),
    ).toBe(true);
  }

  expect(
    expectFailure(
      linearDescriptor.parse(
        headerMap({
          'linear-delivery': 'delivery_00000000000000000000000000000001',
          'linear-event': 'Issue.create',
          'linear-timestamp': '1792450000',
          'x-hub-signature-256': `sha256=${signature}`,
          'stripe-signature': `t=1,v1=${signature}`,
          'svix-signature': `v1,${signature}`,
          'x-linear-signature': signature,
        }),
        BODY,
      ),
    ).reason,
  ).toBe('missing-signature');
});

test('does not extract identity from body fields and binds raw bytes rather than JSON value', async () => {
  const bodyWithIds = utf8(
    '{"deliveryId":"body-delivery","eventId":"body-event","timestamp":1792450000}\n',
  );

  const signature = sign(SECRET, bodyWithIds);

  const parsed = expectOk(
    linearDescriptor.parse(headerMap(signatureHeader(signature)), bodyWithIds),
  );

  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: null,
    authenticatedFields: [],
  });

  const compact = utf8('{"deliveryId":"body-delivery","eventId":"body-event","timestamp":1792450000}');

  expect(compact).not.toEqual(bodyWithIds);

  const compactParsed = expectOk(
    linearDescriptor.parse(headerMap(signatureHeader(signature)), compact),
  );

  expect(
    await verifyHmac(
      [linearDescriptor.decodeSecret(SECRET)],
      compactParsed.signatures,
      compactParsed.signedContent,
    ),
  ).toBe(false);
});

test('exposes the literal linear descriptor identity without a registry change', () => {
  expect(linearDescriptor.provider).toBe('linear');
});
