import { jest } from '@jest/globals';
import { Buffer } from 'node:buffer';
import { verifyHmac, verifyEd25519 } from '../../src/internal/crypto.js';
import { HooklatchError } from '../../src/index.js';
import { normalizeOptions } from '../../src/internal/options.js';

afterEach(() => jest.restoreAllMocks());

test.each([NaN, 1.5])('fal rejects a key-array proxy reporting length %s during synchronous setup', (length) => {
  const publicKeys = new Proxy([new Uint8Array(32), new Uint8Array(32)], {
    get(_target, property) {
      if (property === 'length') return length;

      throw new Error('Unexpected array property read');
    },
  });

  expect(() => normalizeOptions({ provider: 'fal', publicKeys, expectedUserId: 'synthetic-user' }))
    .toThrow(new HooklatchError('invalid-options', 'Invalid verification options.'));
});

test.each([0, 31, 33])('fal validates copied key bytes despite a shadowed byteLength on a %s-byte key', (length) => {
  const key = new Uint8Array(length);
  Object.defineProperty(key, 'byteLength', { value: 32 });

  expect(() => normalizeOptions({ provider: 'fal', publicKeys: [key], expectedUserId: 'synthetic-user' }))
    .toThrow(new HooklatchError('invalid-options', 'Invalid verification options.'));
});

test('fal rejects a typed-array proxy offering replacement iterable key bytes', () => {
  const key = new Proxy(new Uint8Array(31), {
    get(_target, property) {
      if (property === 'byteLength') return 32;

      if (property === Symbol.iterator) return new Uint8Array(32)[Symbol.iterator].bind(new Uint8Array(32));

      return undefined;
    },
  });

  expect(() => normalizeOptions({ provider: 'fal', publicKeys: [key], expectedUserId: 'synthetic-user' }))
    .toThrow(new HooklatchError('invalid-options', 'Invalid verification options.'));
});

test('fal snapshots actual visible key bytes without consulting shadowed metadata or iterators', () => {
  const backing = new Uint8Array(40).fill(7);
  const key = backing.subarray(4, 36);
  Object.defineProperty(key, 'byteLength', { value: 999 });
  Object.defineProperty(key, Symbol.iterator, { value: () => { throw new Error('unused iterator'); } });
  const normalized = normalizeOptions({ provider: 'fal', publicKeys: [key], expectedUserId: 'synthetic-user' });
  key.fill(9);

  expect(normalized.provider).toBe('fal');

  if (normalized.provider !== 'fal') throw new Error('Expected fal credentials');

  expect(normalized.publicKeys).toEqual([new Uint8Array(32).fill(7)]);
});

test('fal contains detached key views as a generic setup error', () => {
  const key = new Uint8Array(32);
  structuredClone(key.buffer, { transfer: [key.buffer] });

  expect(() => normalizeOptions({ provider: 'fal', publicKeys: [key], expectedUserId: 'synthetic-user' }))
    .toThrow(new HooklatchError('invalid-options', 'Invalid verification options.'));
});

test('unsupported cryptographic operations remain capability errors', async () => {
  jest.spyOn(crypto.subtle, 'importKey').mockRejectedValue(new DOMException('synthetic', 'NotSupportedError'));
  await expect(verifyHmac([new Uint8Array(32)], [new Uint8Array(32)], new Uint8Array()))
    .rejects.toMatchObject({ code: 'crypto-unavailable' });
});

test('wrong signature lengths are rejected before runtime verification', async () => {
  const verification = jest.spyOn(crypto.subtle, 'verify').mockResolvedValue(true);
  expect(await verifyHmac([new Uint8Array(32)], [new Uint8Array(20)], new Uint8Array())).toBe(false);
  expect(verification).not.toHaveBeenCalled();
});

test('unexpected cryptographic failures retain the generic internal code', async () => {
  jest.spyOn(crypto.subtle, 'importKey').mockRejectedValue(new DOMException('synthetic', 'OperationError'));
  await expect(verifyHmac([new Uint8Array(32)], [new Uint8Array(32)], new Uint8Array()))
    .rejects.toMatchObject({ code: 'internal', message: 'Cryptographic verification failed.' });
});

test('SHA1 policy verifies the RFC 2202 vector without changing the SHA256 default', async () => {
  const key = new Uint8Array(20).fill(0x0b);
  const signature = Buffer.from('b617318655057264e28bc0b6fb378c8ef146be00', 'hex');
  const content = new TextEncoder().encode('Hi There');

  expect(await verifyHmac([key], [signature], content, { kind: 'hmac', hash: 'SHA-1', signatureBytes: 20 })).toBe(true);

  expect(await verifyHmac([key], [signature], content)).toBe(false);
});

test('raw Ed25519 keys verify RFC 8032 test vector 1 and reject changed content', async () => {
  const key = Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex');

  const signature = Buffer.from('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f'
    + 'b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b', 'hex');

  expect(await verifyEd25519([key], [signature], new Uint8Array())).toBe(true);
  expect(await verifyEd25519([key], [signature], new Uint8Array([1]))).toBe(false);
});

test('Ed25519 rejects wrong signature lengths before runtime verification', async () => {
  const verification = jest.spyOn(crypto.subtle, 'verify').mockResolvedValue(true);
  expect(await verifyEd25519([new Uint8Array(32)], [new Uint8Array(32)], new Uint8Array())).toBe(false);
  expect(verification).not.toHaveBeenCalled();
});

test.each([
  ['NotSupportedError', 'crypto-unavailable'],
  ['OperationError', 'internal'],
])('Ed25519 import %s becomes %s', async (name, code) => {
  jest.spyOn(crypto.subtle, 'importKey').mockRejectedValue(new DOMException('synthetic', name));
  await expect(verifyEd25519([new Uint8Array(32)], [new Uint8Array(64)], new Uint8Array()))
    .rejects.toMatchObject({ code });
});

test('Ed25519 verification exceptions never become an invalid signature result', async () => {
  jest.spyOn(crypto.subtle, 'verify').mockRejectedValue(new DOMException('synthetic', 'OperationError'));
  await expect(verifyEd25519([new Uint8Array(32)], [new Uint8Array(64)], new Uint8Array()))
    .rejects.toMatchObject({ code: 'internal' });
});
