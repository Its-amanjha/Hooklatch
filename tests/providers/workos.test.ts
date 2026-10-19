import { verifyHmac } from '../../src/internal/crypto.js';
import { normalizeHeaders } from '../../src/internal/headers.js';
import { workosDescriptor as descriptor } from '../../src/providers/workos.js';
import type { HeaderInput, VerificationFailureReason } from '../../src/types.js';
import { expectFailure, expectOk, headerMap, hmacHex, ternErrorCode } from './helpers.js';

// Synthetic phase-4 anchors only. No WorkOS-published signature vector is
// claimed and no live endpoint was called. The signing secret is fake and is
// built with test-only node:crypto from the documented recipe.
const SECRET = 'workos/phase4 synthetic secret';
const OTHER_SECRET = 'workos/phase4 other synthetic secret';
const T = '1792368000500';

const BODY = Buffer.from(
  '{"event":"dsync.user.created","data":{"id":"user_synthetic"},"nul":"\\u0000"}',
  'utf8',
);

const signed = (timestamp: string, body: Uint8Array): Buffer =>
  Buffer.concat([Buffer.from(`${timestamp}.`, 'utf8'), Buffer.from(body)]);

const sign = (timestamp: string, body: Uint8Array, secret: string = SECRET): string =>
  hmacHex(secret, signed(timestamp, body));

const header = (value: string): ReturnType<typeof headerMap> => headerMap({ 'workos-signature': value });

const valueFor = (
  timestamp: string = T,
  signature: string = sign(T, BODY),
  order: 'timestamp-first' | 'signature-first' = 'timestamp-first',
): string => order === 'timestamp-first'
  ? `t=${timestamp},v1=${signature}`
  : `v1=${signature},t=${timestamp}`;

test('verifies an independently signed millisecond payload over exact raw bytes', async () => {
  const backing = new Uint8Array(BODY.byteLength + 4);

  backing.set(BODY, 2);
  const body = backing.subarray(2, 2 + BODY.byteLength);
  const expected = signed(T, body);
  const parsed = expectOk(descriptor.parse(header(valueFor(T, sign(T, body))), body));

  expect(parsed.signatures).toHaveLength(1);
  expect(Buffer.from(parsed.signedContent).equals(expected)).toBe(true);
  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: 1792368000.5,
    authenticatedFields: ['timestamp'],
  });
  // The millisecond fraction survives identity formatting; it is not floored.
  expect(parsed.identity.timestamp).not.toBe(1792368000);
  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
    .toBe(true);
});

test('preserves empty, binary, NUL, BOM, invalid UTF-8, unicode and long bodies exactly', async () => {
  const backing = new Uint8Array(600);

  for (let index = 0; index < backing.byteLength; index += 1) {
    backing[index] = (index * 37) % 256;
  }

  const bodies: readonly Uint8Array[] = [
    new Uint8Array(),
    Buffer.from('not json {', 'utf8'),
    new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28]),
    new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
    new Uint8Array([0x00]),
    Buffer.from('{"unicode":"héllo-秘密"}', 'utf8'),
    backing.subarray(7, 507),
  ];

  for (const body of bodies) {
    const parsed = expectOk(descriptor.parse(header(valueFor(T, sign(T, body))), body));

    expect(Buffer.from(parsed.signedContent).equals(signed(T, body))).toBe(true);
    expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
      .toBe(true);
  }
});

test('fails cryptographic verification on body, timestamp, or digest tamper and on a wrong key', async () => {
  const tampered = new Uint8Array(BODY);

  tampered[0] = (tampered[0] ?? 0) ^ 0x01;
  const bodyParsed = expectOk(descriptor.parse(header(valueFor()), tampered));

  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], bodyParsed.signatures, bodyParsed.signedContent))
    .toBe(false);

  // `t` participates in the signed bytes, so a shifted timestamp parses but fails the MAC.
  const timestampParsed = expectOk(descriptor.parse(header(valueFor('1792368000501')), BODY));

  expect(timestampParsed.identity.timestamp).toBe(1792368000.501);
  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], timestampParsed.signatures, timestampParsed.signedContent))
    .toBe(false);

  const digest = Buffer.from(sign(T, BODY), 'hex');

  digest[0] = (digest[0] ?? 0) ^ 0x01;
  const digestParsed = expectOk(descriptor.parse(header(valueFor(T, digest.toString('hex'))), BODY));

  expect(await verifyHmac([descriptor.decodeSecret(SECRET)], digestParsed.signatures, digestParsed.signedContent))
    .toBe(false);

  expect(await verifyHmac([descriptor.decodeSecret(OTHER_SECRET)], bodyParsed.signatures, bodyParsed.signedContent))
    .toBe(false);
});

test('treats the secret as literal untrimmed UTF-8, never Base64 or a prefix rule', async () => {
  expect(Buffer.from(descriptor.decodeSecret(SECRET)).equals(Buffer.from(SECRET, 'utf8'))).toBe(true);

  for (const secret of [
    '  padded workos secret  ',
    '\tTAB secret\t',
    'wörkos-秘密 secret',
    'd29ya29zLXNlY3JldA==',
    ' ',
  ]) {
    expect(Buffer.from(descriptor.decodeSecret(secret)).equals(Buffer.from(secret, 'utf8'))).toBe(true);

    const parsed = expectOk(descriptor.parse(header(valueFor(T, sign(T, BODY, secret))), BODY));

    expect(await verifyHmac([descriptor.decodeSecret(secret)], parsed.signatures, parsed.signedContent))
      .toBe(true);
  }

  // A Base64-shaped literal secret is used as text; its decoded bytes are not the key.
  const base64Looking = 'd29ya29zLXNlY3JldA==';
  const literalKey = Buffer.from(base64Looking, 'utf8');
  const decodedKey = Buffer.from(base64Looking, 'base64');
  const parsed = expectOk(descriptor.parse(header(valueFor(T, sign(T, BODY, base64Looking))), BODY));

  expect(await verifyHmac([descriptor.decodeSecret(base64Looking)], parsed.signatures, parsed.signedContent))
    .toBe(true);
  expect(await verifyHmac([decodedKey], parsed.signatures, parsed.signedContent)).toBe(false);
  expect(Buffer.from(descriptor.decodeSecret(base64Looking)).equals(literalKey)).toBe(true);
  expect(Buffer.from(descriptor.decodeSecret(base64Looking)).equals(decodedKey)).toBe(false);

  // No whsec_ prefix is stripped from a WorkOS literal secret.
  const prefixed = `whsec_${SECRET}`;

  expect(Buffer.from(descriptor.decodeSecret(prefixed)).equals(Buffer.from(prefixed, 'utf8'))).toBe(true);
  expect(ternErrorCode(() => descriptor.decodeSecret(''))).toBe('invalid-secret');
});

test('accepts either field order and trims only outer segment whitespace', () => {
  const signature = sign(T, BODY);
  const first = expectOk(descriptor.parse(header(valueFor()), BODY));
  const second = expectOk(descriptor.parse(header(valueFor(T, signature, 'signature-first')), BODY));
  const spaced = expectOk(descriptor.parse(header(`  t=${T} ,  v1=${signature}  `), BODY));
  const tabbed = expectOk(descriptor.parse(header(`\tt=${T}\t,\tv1=${signature}\t`), BODY));

  for (const parsed of [second, spaced, tabbed]) {
    expect(Buffer.from(parsed.signedContent).equals(Buffer.from(first.signedContent))).toBe(true);
    expect(parsed.identity).toEqual(first.identity);
  }
});

test('reports missing and blank headers as missing signatures', () => {
  for (const headers of [headerMap({}), header(''), header('   '), header('\t\t')]) {
    expect(expectFailure(descriptor.parse(headers, BODY)).reason).toBe('missing-signature');
  }
});

test('rejects malformed structure, canonical defects, and unsupported-only schemes by table', () => {
  const signature = sign(T, BODY);

  const cases: readonly (readonly [string, VerificationFailureReason])[] = [
    // Required-field checks run only after the whole structure validates.
    [`t=${T}`, 'missing-signature'],
    [`v1=${signature}`, 'missing-timestamp'],
    ['v1a=abc123', 'unsupported-scheme'],
    ['v2=abc123', 'unsupported-scheme'],
    [`t=${T},v1a=abc123`, 'unsupported-scheme'],
    [`t=${T},v2=abc123`, 'unsupported-scheme'],
    // Repeated timestamps fail even when the values agree.
    [`t=${T},t=${T},v1=${signature}`, 'malformed-signature'],
    [`t=${T},t=1792368000501,v1=${signature}`, 'malformed-signature'],
    // Canonical nonnegative safe-decimal millisecond `t`.
    ['t=,v1=' + signature, 'malformed-signature'],
    [`t=01,v1=${signature}`, 'malformed-signature'],
    [`t=0${T},v1=${signature}`, 'malformed-signature'],
    [`t=+${T},v1=${signature}`, 'malformed-signature'],
    [`t=-1,v1=${signature}`, 'malformed-signature'],
    [`t=1.5,v1=${signature}`, 'malformed-signature'],
    [`t=1e3,v1=${signature}`, 'malformed-signature'],
    [`t= 1,v1=${signature}`, 'malformed-signature'],
    ['t=9007199254740992,v1=' + signature, 'malformed-signature'],
    [`t=99999999999999999999,v1=${signature}`, 'malformed-signature'],
    // One malformed recognized `v1` poisons the accept-set.
    [`t=${T},v1=zz`, 'malformed-signature'],
    [`t=${T},v1=@@@`, 'malformed-signature'],
    [`t=${T},v1=${signature.slice(1)}`, 'malformed-signature'],
    [`t=${T},v1=${signature}00`, 'malformed-signature'],
    [`t=${T},v1=${signature},v1=`, 'malformed-signature'],
    [`t=${T},v1=,v1=${signature}`, 'malformed-signature'],
    [`t=${T},v1=${signature},v1=@@@`, 'malformed-signature'],
    [`t=${T},v1=@@@,v1=${signature}`, 'malformed-signature'],
    // Empty segments, missing `=`, extra `=`, and empty values fail structurally.
    [`t=${T},v1=${signature},`, 'malformed-signature'],
    [`t=${T},v1=${signature},,`, 'malformed-signature'],
    [`t=${T},v1=${signature},v1a`, 'malformed-signature'],
    [`t=${T},v1=${signature},v1a=`, 'malformed-signature'],
    [`t=${T},v1=${signature},v1a=a=b`, 'malformed-signature'],
    [`t=${T},v1=${signature},bad key=value`, 'malformed-signature'],
    [`t=${T},v1=${signature},=value`, 'malformed-signature'],
    // Whitespace around `=` is rejected; only whole segments are trimmed.
    [`t =${T},v1=${signature}`, 'malformed-signature'],
    [`t=${T},v1 =${signature}`, 'malformed-signature'],
    [`t=${T},v1= ${signature}`, 'malformed-signature'],
    // Field names are case-sensitive.
    [`T=${T},V1=${signature}`, 'unsupported-scheme'],
    [`T=${T},v1=${signature}`, 'missing-timestamp'],
    [`t=${T},V1=${signature}`, 'unsupported-scheme'],
    // Poisoned unknown syntax fails even though unknown names are otherwise ignored.
    [`t=${T},v1=${signature},v1a=a b`, 'malformed-signature'],
    [`t=${T},v1=${signature},v1a=a,b`, 'malformed-signature'],
    [`t=${T},v1=${signature},v1a=a',b`, 'malformed-signature'],
    [`t=${T},v1=${signature},v1a=a\tb`, 'malformed-signature'],
  ];

  for (const [value, reason] of cases) {
    expect(expectFailure(descriptor.parse(header(value), BODY)).reason).toBe(reason);
  }

  // Structurally valid opaque unknown schemes are ignored beside a valid `v1`.
  for (const value of [
    `t=${T},v1=${signature},v1a=abc-123_XYZ`,
    `v1a=abc-123,v1=${signature},t=${T}`,
    `  t=${T} , v1=${signature} , future_TOKEN=abc-123  `,
  ]) {
    expect(expectOk(descriptor.parse(header(value), BODY)).signatures).toHaveLength(1);
  }
});

test('formats identity timestamp as t/1000 using exactly representable fractions', () => {
  for (const timestamp of ['0', '1700000000250', '1700000000500', '1700000000750', T]) {
    const parsed = expectOk(
      descriptor.parse(header(valueFor(timestamp, sign(timestamp, BODY))), BODY),
    );

    expect(parsed.identity.timestamp).toBe(Number(timestamp) / 1000);
    expect(Buffer.from(parsed.signedContent).equals(signed(timestamp, BODY))).toBe(true);
  }

  expect(expectOk(descriptor.parse(header(valueFor('0', sign('0', BODY))), BODY)).identity.timestamp)
    .toBe(0);
});

test('accepts valid repeated v1 tokens as an accept-set for distinct keys', async () => {
  const firstKey = 'workos accept-set first key';
  const secondKey = 'workos accept-set second key';
  const firstSignature = sign(T, BODY, firstKey);
  const secondSignature = sign(T, BODY, secondKey);

  for (const value of [
    `t=${T},v1=${firstSignature},v1=${secondSignature}`,
    `v1=${secondSignature},t=${T},v1=${firstSignature}`,
  ]) {
    const parsed = expectOk(descriptor.parse(header(value), BODY));

    expect(parsed.signatures).toHaveLength(2);
    expect(await verifyHmac([descriptor.decodeSecret(firstKey)], parsed.signatures, parsed.signedContent))
      .toBe(true);
    expect(await verifyHmac([descriptor.decodeSecret(secondKey)], parsed.signatures, parsed.signedContent))
      .toBe(true);
    expect(await verifyHmac([descriptor.decodeSecret(OTHER_SECRET)], parsed.signatures, parsed.signedContent))
      .toBe(false);
  }
});

test('accepts either hex case for a 32-byte v1 signature', async () => {
  const signature = sign(T, BODY);

  const mixed = [...signature]
    .map((char, index) => (index % 2 === 0 ? char.toUpperCase() : char))
    .join('');

  for (const value of [signature.toUpperCase(), mixed]) {
    const parsed = expectOk(descriptor.parse(header(valueFor(T, value)), BODY));

    expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
      .toBe(true);
  }
});

test('does not perform freshness checks; the descriptor only formats identity', () => {
  for (const timestamp of ['0', '1', '9999999999999']) {
    const parsed = expectOk(descriptor.parse(header(valueFor(timestamp, sign(timestamp, BODY))), BODY));

    expect(parsed.identity.timestamp).toBe(Number(timestamp) / 1000);
  }

  expect(descriptor.provider).toBe('workos');
});

test('normalizes header name case across record, tuple, and Headers inputs', () => {
  const signature = sign(T, BODY);

  const tuple: [string, string][] = [
    ['WorkOS-Signature', valueFor(T, signature)],
  ];

  const record: HeaderInput = { 'WORKOS-SIGNATURE': valueFor(T, signature, 'signature-first') };
  const expected = signed(T, BODY);

  for (const headers of [
    normalizeHeaders(tuple),
    normalizeHeaders(new Headers(tuple)),
    normalizeHeaders(record),
  ]) {
    const parsed = expectOk(descriptor.parse(headers, BODY));

    expect(Buffer.from(parsed.signedContent).equals(expected)).toBe(true);
  }
});
