import { createHmac } from 'node:crypto';

import { verifyHmac } from '../../src/internal/crypto.js';
import { normalizeHeaders } from '../../src/internal/headers.js';
import { sanityDescriptor as descriptor } from '../../src/providers/sanity.js';
import type { HeaderInput, VerificationFailureReason } from '../../src/types.js';
import { expectFailure, expectOk, headerMap } from './helpers.js';

// Published tuples below are copied from the official Sanity webhook toolkit
// test file, pinned to commit e0c211ed6cd80465a70829e335c9e219f37839ba:
// https://github.com/sanity-io/webhook-toolkit/blob/e0c211ed6cd80465a70829e335c9e219f37839ba/test/signature.test.ts
// The upstream fixtures use the public literal secret "test" and "try-me"; they
// are repository test data, not credentials. Every other vector in this file is
// a locally generated synthetic anchor.
const PUBLISHED_SECRET = 'test';
const PUBLISHED_TIMESTAMP = '1633519811129';
const PUBLISHED_BODY = Buffer.from(JSON.stringify({ _id: 'resume' }), 'utf8');
const PUBLISHED_DIGEST = 'tLa470fx7qkLLEcMOcEUFuBbRSkGujyskxrNXcoh0N0';
const PUBLISHED_HEADER = `t=${PUBLISHED_TIMESTAMP},v1=${PUBLISHED_DIGEST}`;

const PUBLISHED_ENCODE_SECRET = 'try-me';
const PUBLISHED_ENCODE_TIMESTAMP = '1633518820676';
const PUBLISHED_ENCODE_BODY = Buffer.from(JSON.stringify({ title: 'GROQ-Hooks are neat' }), 'utf8');
const PUBLISHED_ENCODE_DIGEST = 'e7C9h2sfbFfc4V7TEz7PSOp4IoNzl0UdVsBV-1wgdeA';

// The upstream `decodeSignatureHeader` fixture publishes the header value only.
// Its body and secret pairing is not published, so it is used for grammar
// assertions and never for a cryptographic claim.
const PUBLISHED_DECODE_HEADER = 't=1633470609222,v1=7kTYPaw6SmCoN2VJzFL24oEjV-ac7lRwbljOkh7d13A';

const SECRET = 'sanity phase5 synthetic secret';
const OTHER_SECRET = 'sanity phase5 other synthetic secret';
const T = '1792368000123';

const BODY = Buffer.from('{"_id":"synthetic-doc","_type":"groq-hook"}', 'utf8');

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Independent anchor bytes: the original timestamp text, a dot, then the exact body. */
const signedBytes = (timestampText: string, body: Uint8Array): Buffer =>
  Buffer.concat([Buffer.from(`${timestampText}.`, 'utf8'), Buffer.from(body)]);

/** Independent anchor digest: node:crypto HMAC-SHA256 rendered as unpadded Base64url. */
const signDigest = (secret: string, timestampText: string, body: Uint8Array): string =>
  createHmac('sha256', Buffer.from(secret, 'utf8'))
    .update(signedBytes(timestampText, body))
    .digest('base64url');

const header = (value: string): ReturnType<typeof headerMap> => headerMap({ 'sanity-webhook-signature': value });

const valueFor = (timestampText: string = T, digest: string = signDigest(SECRET, T, BODY)): string =>
  `t=${timestampText},v1=${digest}`;

test('verifies the published Sanity toolkit tuple over its exact published bytes', async () => {
  const parsed = expectOk(descriptor.parse(header(PUBLISHED_HEADER), PUBLISHED_BODY));

  expect(parsed.signatures).toHaveLength(1);
  expect(Buffer.from(parsed.signedContent).equals(signedBytes(PUBLISHED_TIMESTAMP, PUBLISHED_BODY)))
    .toBe(true);
  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: 1633519811.129,
    authenticatedFields: ['timestamp'],
  });
  expect(await verifyHmac([descriptor.decodeSecret(PUBLISHED_SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('verifies the published Sanity toolkit encoding tuple', async () => {
  const value = `t=${PUBLISHED_ENCODE_TIMESTAMP},v1=${PUBLISHED_ENCODE_DIGEST}`;
  const parsed = expectOk(descriptor.parse(header(value), PUBLISHED_ENCODE_BODY));

  expect(Buffer.from(parsed.signedContent).equals(signedBytes(PUBLISHED_ENCODE_TIMESTAMP, PUBLISHED_ENCODE_BODY)))
    .toBe(true);
  expect(await verifyHmac(
    [descriptor.decodeSecret(PUBLISHED_ENCODE_SECRET)],
    parsed.signatures,
    parsed.signedContent,
  )).toBe(true);
});

test('binds a published signature to the published body only', async () => {
  const otherBody = Buffer.from(JSON.stringify({ _id: 'structure' }), 'utf8');
  const parsed = expectOk(descriptor.parse(header(PUBLISHED_HEADER), otherBody));

  expect(await verifyHmac([descriptor.decodeSecret(PUBLISHED_SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(false);

  // The control: the same body signed correctly does verify, so the failure
  // above comes from the body binding and not from a broken anchor.
  const control = expectOk(descriptor.parse(
    header(`t=${PUBLISHED_TIMESTAMP},v1=${signDigest(PUBLISHED_SECRET, PUBLISHED_TIMESTAMP, otherBody)}`),
    otherBody,
  ));

  expect(await verifyHmac(
    [descriptor.decodeSecret(PUBLISHED_SECRET)],
    control.signatures,
    control.signedContent,
  )).toBe(true);
});

test('rejects the published alternate version header and the published space separator', () => {
  const cases: readonly (readonly [string, VerificationFailureReason])[] = [
    [`t=${PUBLISHED_TIMESTAMP},v5=${PUBLISHED_DIGEST}`, 'malformed-signature'],
    [`t=${PUBLISHED_TIMESTAMP}, v1=${PUBLISHED_DIGEST}`, 'malformed-signature'],
    [`t=${PUBLISHED_TIMESTAMP} ,v1=${PUBLISHED_DIGEST}`, 'malformed-signature'],
    [`t=${PUBLISHED_TIMESTAMP},v1=${PUBLISHED_DIGEST} `, 'malformed-signature'],
  ];

  for (const [value, reason] of cases) {
    expect(expectFailure(descriptor.parse(header(value), PUBLISHED_BODY)).reason).toBe(reason);
  }

  // The published decode fixture is a well-formed header, so it parses here.
  const parsed = expectOk(descriptor.parse(header(PUBLISHED_DECODE_HEADER), PUBLISHED_BODY));

  expect(parsed.signatures).toHaveLength(1);
  expect(parsed.identity.timestamp).toBe(1633470609.222);
});

test('treats the secret as literal untrimmed UTF-8 with no prefix or Base64 rule', async () => {
  const secrets = [
    'sanity phase5 synthetic secret',
    '  padded sanity secret  ',
    '\tTAB sanity secret\t',
    'sänity-秘密 secret',
    '0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d',
    'dHNhbnl0aWMuc2FuaXR5LnNlY3JldA==',
  ];

  for (const secret of secrets) {
    expect(Buffer.from(descriptor.decodeSecret(secret)).equals(Buffer.from(secret, 'utf8'))).toBe(true);

    const parsed = expectOk(descriptor.parse(header(valueFor(T, signDigest(secret, T, BODY))), BODY));

    expect(await verifyHmac([descriptor.decodeSecret(secret)], parsed.signatures, parsed.signedContent))
      .toBe(true);
  }

  // A Base64-shaped secret is used as text; its decoded bytes are not the key.
  const base64Looking = 'dHNhbnl0aWMuc2FuaXR5LnNlY3JldA==';
  const literalKey = Buffer.from(base64Looking, 'utf8');
  const decodedKey = Buffer.from(base64Looking, 'base64');
  const parsed = expectOk(descriptor.parse(header(valueFor(T, signDigest(base64Looking, T, BODY))), BODY));

  expect(await verifyHmac([literalKey], parsed.signatures, parsed.signedContent)).toBe(true);
  expect(await verifyHmac([decodedKey], parsed.signatures, parsed.signedContent)).toBe(false);
});

test('requires a 32-byte digest and rejects other digest lengths', () => {
  const digest = signDigest(SECRET, T, BODY);
  const short = Buffer.alloc(31, 7).toString('base64url');
  const long = Buffer.alloc(33, 7).toString('base64url');

  expect(digest).toHaveLength(43);
  expect(short).toHaveLength(42);
  expect(long).toHaveLength(44);

  for (const candidate of [short, long, digest.slice(0, 42), `${digest}A`]) {
    expect(expectFailure(descriptor.parse(header(valueFor(T, candidate)), BODY)).reason)
      .toBe('malformed-signature');
  }
});

test('accepts only canonical Base64url pad bits in the final digest character', () => {
  const digest = signDigest(SECRET, T, BODY);
  let accepted = 0;

  for (const character of BASE64URL_ALPHABET) {
    const candidate = digest.slice(0, -1) + character;
    const parsed = descriptor.parse(header(valueFor(T, candidate)), BODY);

    // The 43 characters carry 258 bits; the two unused low bits of the last
    // character are the pad bits and must be zero for a canonical encoding.
    const isCanonical = (BASE64URL_ALPHABET.indexOf(character) & 0b11) === 0;

    if (isCanonical) {
      expect(expectOk(parsed).signatures).toHaveLength(1);
      accepted += 1;
    } else {
      expect(expectFailure(parsed).reason).toBe('malformed-signature');
    }
  }

  // Exactly 16 of the 64 Base64url values carry zero pad bits.
  expect(accepted).toBe(16);
});

test('rejects standard Base64 characters and Base64 padding in the digest', () => {
  const digest = signDigest(SECRET, T, BODY);
  const withPlus = `+${digest.slice(1)}`;
  const withSlash = `${digest.slice(0, -1)}/`;
  const padded = `${digest}=`;

  for (const candidate of [withPlus, withSlash, padded, `${digest.slice(0, 42)}==`]) {
    expect(expectFailure(descriptor.parse(header(valueFor(T, candidate)), BODY)).reason)
      .toBe('malformed-signature');
  }
});

test('accepts only the exact ordered single-field header grammar', () => {
  const digest = signDigest(SECRET, T, BODY);

  const cases: readonly string[] = [
    `t=${T}`,
    `v1=${digest}`,
    `v2=${digest}`,
    `t=${T},v2=${digest}`,
    `t=${T},v5=${digest}`,
    `v1=${digest},t=${T}`,
    `t=${T},t=${T},v1=${digest}`,
    `t=${T},v1=${digest},v1=${digest}`,
    `t=${T},v1=${digest},extra=1`,
    `extra=1,t=${T},v1=${digest}`,
    `t=${T};v1=${digest}`,
    `t=${T},v1=${digest};`,
    `t=${T}, v1=${digest}`,
    `t=${T},v1 =${digest}`,
    `t=${T},v1= ${digest}`,
    ` t=${T},v1=${digest}`,
    `t=${T},v1=${digest} `,
    `t=${T},v1=${digest}\t`,
    `T=${T},V1=${digest}`,
    `t=${T},V1=${digest}`,
    `t=${T},v1=${digest},`,
    `,t=${T},v1=${digest}`,
    `t=${T},,v1=${digest}`,
    `t=${T},v1=${digest},v1`,
  ];

  for (const value of cases) {
    expect(expectFailure(descriptor.parse(header(value), BODY)).reason).toBe('malformed-signature');
  }

  expect(expectOk(descriptor.parse(header(valueFor()), BODY)).signatures).toHaveLength(1);
});

test('rejects repeated and combined signature headers', () => {
  const digest = signDigest(SECRET, T, BODY);

  const repeated = headerMap({
    'sanity-webhook-signature': [`t=${T},v1=${digest}`, `t=${T},v1=${digest}`],
  });

  const mixed = headerMap({
    'sanity-webhook-signature': [`t=${T},v1=${digest}`, `t=${T},v1=${signDigest(OTHER_SECRET, T, BODY)}`],
  });

  for (const headers of [repeated, mixed]) {
    expect(expectFailure(descriptor.parse(headers, BODY)).reason).toBe('malformed-signature');
  }
});

test('matches the header name case-insensitively and the field names case-sensitively', () => {
  const digest = signDigest(SECRET, T, BODY);
  const tuple: [string, string][] = [['Sanity-Webhook-Signature', valueFor(T, digest)]];
  const record: HeaderInput = { 'SANITY-WEBHOOK-SIGNATURE': valueFor(T, digest) };

  for (const headers of [
    normalizeHeaders(tuple),
    normalizeHeaders(new Headers(tuple)),
    normalizeHeaders(record),
  ]) {
    expect(expectOk(descriptor.parse(headers, BODY)).signatures).toHaveLength(1);
  }

  expect(expectFailure(descriptor.parse(header(`T=${T},v1=${digest}`), BODY)).reason)
    .toBe('malformed-signature');
});

test('enforces the canonical millisecond timestamp policy', () => {
  // A canonical, safe, above-minimum millisecond value is accepted even when
  // it is far in the future: freshness belongs to core, not to the descriptor.
  const accepted = ['1609459200000', '1633519811129', '1792368000123', '16094592000000', '9007199254740991'];

  for (const timestamp of accepted) {
    const parsed = expectOk(
      descriptor.parse(header(valueFor(timestamp, signDigest(SECRET, timestamp, BODY))), BODY),
    );

    expect(parsed.identity.timestamp).toBe(Number(timestamp) / 1000);
  }

  const rejected = [
    '0',
    '1609459199999',
    '01609459200000',
    '1609459200000.0',
    '-1609459200000',
    '+1609459200000',
    ' 1609459200000',
    '1609459200000 ',
    '1_609459200000',
    '9007199254740992',
    '99999999999999999999',
    '1e12',
    '16094592000a',
    '0x5f5e1000',
    '',
  ];

  for (const timestamp of rejected) {
    expect(expectFailure(descriptor.parse(header(valueFor(timestamp)), BODY)).reason)
      .toBe('malformed-signature');
  }
});

test('reports missing and blank headers as missing signatures', () => {
  for (const headers of [headerMap({}), header(''), header('   '), header('\t\t')]) {
    expect(expectFailure(descriptor.parse(headers, BODY)).reason).toBe('missing-signature');
  }

  // A whitespace-only value that header normalization rejects is still a
  // missing signature for the descriptor itself.

  const control = new Map([['sanity-webhook-signature', '\n']]);

  expect(expectFailure(descriptor.parse(control, BODY)).reason).toBe('missing-signature');
});

test('preserves empty, NUL, BOM, invalid UTF-8, non-JSON, and Unicode bodies exactly', async () => {
  const bodies: readonly Uint8Array[] = [
    new Uint8Array(),
    Buffer.from('not json {', 'utf8'),
    new Uint8Array([0x00]),
    new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
    new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28]),
    Buffer.from('{"unicode":"héllo-秘密"}', 'utf8'),
  ];

  for (const body of bodies) {
    const parsed = expectOk(descriptor.parse(header(valueFor(T, signDigest(SECRET, T, body))), body));

    expect(Buffer.from(parsed.signedContent).equals(signedBytes(T, body))).toBe(true);
    expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
      .toBe(true);
  }
});

test('signs the exact bytes of a non-zero-offset body view', async () => {
  const backing = new Uint8Array(BODY.byteLength + 8);

  backing.set(BODY, 3);

  const view = backing.subarray(3, 3 + BODY.byteLength);
  const parsed = expectOk(descriptor.parse(header(valueFor(T, signDigest(SECRET, T, view))), view));

  expect(view.byteOffset).toBe(3);
  expect(Buffer.from(parsed.signedContent).equals(signedBytes(T, view))).toBe(true);
  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('fails cryptographic verification on body tamper and on a wrong key', async () => {
  const digest = signDigest(SECRET, T, BODY);
  const parsed = expectOk(descriptor.parse(header(valueFor(T, digest)), BODY));

  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
  expect(await verifyHmac([descriptor.decodeSecret(OTHER_SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(false);

  const tampered = new Uint8Array(BODY);

  tampered[0] = (tampered[0] ?? 0) ^ 0x01;

  const tamperedParsed = expectOk(descriptor.parse(header(valueFor(T, digest)), tampered));

  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], tamperedParsed.signatures, tamperedParsed.signedContent))
    .toBe(false);
});

test('exposes only an authenticated timestamp identity', () => {
  const parsed = expectOk(descriptor.parse(header(valueFor()), BODY));

  expect(descriptor.provider).toBe('sanity');
  expect(parsed.identity.deliveryId).toBeNull();
  expect(parsed.identity.eventId).toBeNull();
  expect(parsed.identity.authenticatedFields).toEqual(['timestamp']);
  expect(parsed.identity.timestamp).toBe(1792368000.123);
});

test('does not enforce freshness in the descriptor', () => {
  const ancient = '1609459200000';
  const value = valueFor(ancient, signDigest(SECRET, ancient, BODY));
  const parsed = expectOk(descriptor.parse(header(value), BODY));

  expect(parsed.identity.timestamp).toBe(1609459200);
});
