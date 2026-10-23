import { createHmac } from 'node:crypto';
import { utf8 } from '../../src/internal/bytes.js';
import { vercelDescriptor } from '../../src/providers/vercel.js';
import { expectFailure, expectOk, headerMap, ternErrorCode } from './helpers.js';

const signature = 'aB'.repeat(20);
const parse = (value: string) => vercelDescriptor.parse(headerMap({ 'X-Vercel-Signature': value }), utf8('body'));

test('declares a fixed SHA1 policy and preserves literal keys and exact visible body bytes', () => {
  expect(vercelDescriptor.crypto).toEqual({ kind: 'hmac', hash: 'SHA-1', signatureBytes: 20 });

  for (const secret of [' ', '  clé🔐  ', 'base64:not-decoded']) {
    expect(vercelDescriptor.decodeSecret(secret)).toEqual(utf8(secret));

    for (const body of [new Uint8Array(), new Uint8Array([0, 255, 128]), new Uint8Array([9, 1, 2, 9]).subarray(1, 3)]) {
      const hex = createHmac('sha1', secret).update(body).digest('hex');
      const parsed = expectOk(vercelDescriptor.parse(headerMap({ 'X-Vercel-Signature': hex }), body));
      expect(parsed.signedContent).toBe(body);
      expect(parsed.signatures).toEqual([new Uint8Array(Buffer.from(hex, 'hex'))]);
      expect(parsed.identity).toEqual({ deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] });
    }
  }

  expect(ternErrorCode(() => vercelDescriptor.decodeSecret(''))).toBe('invalid-secret');
});

test('accepts either hex case and all-zero grammar without authenticating it', () => {
  expect(expectOk(parse(signature)).signatures[0]).toEqual(new Uint8Array(20).fill(171));
  expect(expectOk(parse('0'.repeat(40))).signatures[0]).toEqual(new Uint8Array(20));
});

test('matches the independent GLM synthetic baseline, with no vendor-vector claim', () => {
  const bytes = utf8('{"hooklatchStage":9,"case":"vercel-positive-baseline"}');
  const expected = 'b0e82367fa2acfe019550eff3ce268154a2c6faa';
  const parsed = expectOk(vercelDescriptor.parse(headerMap({ 'x-vercel-signature': expected }), bytes));

  expect(createHmac('sha1', 'hooklatch_stage_9b_vercel_secret').update(parsed.signedContent).digest('hex')).toBe(expected);
});

test.each(['', ' ', '\t'])('classifies blank signature %j as missing', value => {
  expect(expectFailure(parse(value)).reason).toBe('missing-signature');
});

test.each(['a'.repeat(38), 'a'.repeat(42), 'a'.repeat(64), 'g'.repeat(40), ` ${signature}`, `${signature} `, `sha1=${signature}`, `${signature},${signature}`, `${signature}=`, 'é'.repeat(40)])('rejects malformed signature %j', value => {
  expect(expectFailure(parse(value)).reason).toBe('malformed-signature');
});

test('ignores all alien header families and cannot rescue a missing selected header', () => {
  const alien = { 'x-hub-signature': `sha1=${signature}`, 'vercel-signature': signature, 'x-fal-webhook-signature': signature, 'x-vercel-timestamp': '0' };
  expect(expectFailure(vercelDescriptor.parse(headerMap(alien), utf8('x'))).reason).toBe('missing-signature');
  expect(expectOk(vercelDescriptor.parse(headerMap({ ...alien, 'x-vercel-signature': signature }), utf8('x'))).identity.timestamp).toBeNull();
  expect(expectFailure(vercelDescriptor.parse(headerMap({ 'x-vercel-signature': [signature, signature] }), utf8('x'))).reason).toBe('malformed-signature');
});
