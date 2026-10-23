import { jest } from '@jest/globals';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { utf8 } from '../../src/internal/bytes.js';
import { falDescriptor } from '../../src/providers/fal.js';
import { expectFailure, headerMap } from './helpers.js';

const SIG = 'aB'.repeat(64);
const HEADERS = { 'x-fal-webhook-signature': SIG, 'x-fal-webhook-request-id': 'request:1', 'x-fal-webhook-user-id': 'user:1', 'x-fal-webhook-timestamp': '0' };
const body = new Uint8Array([0, 255, 128, 1]);
const message = (bytes: Uint8Array, request = 'request:1', user = 'user:1', timestamp = '0') => utf8(`${request}\n${user}\n${timestamp}\n${createHash('sha256').update(bytes).digest('hex')}`);
const parse = (changes: Record<string, string> = {}) => falDescriptor.parse(headerMap({ ...HEADERS, ...changes }), body);

afterEach(() => { jest.restoreAllMocks(); });

test('formats independent synthetic Ed25519 signatures over exact bytes, with no ID relabelling', async () => {
  // RFC 8032 test-1 seed is used only as a primitive key anchor, not a fal vector.
  const seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
  const key = createPrivateKey({ key: Buffer.from(`302e020100300506032b657004220420${seed}`, 'hex'), type: 'pkcs8', format: 'der' });
  const publicKey = createPublicKey(key);
  expect(sign(null, new Uint8Array(), key).toString('hex')).toBe('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
  expect(falDescriptor.crypto).toEqual({ kind: 'ed25519', signatureBytes: 64 });
  expect('decodeSecret' in falDescriptor).toBe(false);

  for (const bytes of [new Uint8Array(), body, new Uint8Array([9, 255, 0, 9]).subarray(1, 3)]) {
    const signed = sign(null, message(bytes), key);
    const parsed = await falDescriptor.parse(headerMap({ ...HEADERS, 'X-Fal-Webhook-Signature': signed.toString('hex').toUpperCase(), 'x-fal-webhook-signature': signed.toString('hex').toUpperCase() }), bytes);
    // Avoid duplicate selected headers in normalization.
    const clean = await falDescriptor.parse(headerMap({ ...HEADERS, 'x-fal-webhook-signature': signed.toString('hex').toUpperCase() }), bytes);
    expect(expectFailure(parsed).reason).toBe('malformed-signature');

    if (!clean.ok) throw new Error(clean.reason);
    const detached = clean.signatures[0];

    if (detached === undefined) throw new Error('Expected one detached signature.');
    expect(clean.signedContent).toEqual(message(bytes));
    expect(clean.signatures).toEqual([new Uint8Array(signed)]);
    expect(verify(null, clean.signedContent, publicKey, detached)).toBe(true);
    expect(verify(null, message(utf8('tampered')), publicKey, detached)).toBe(false);
    expect(clean.recipient).toBe('user:1');
    expect(clean.identity).toEqual({ deliveryId: null, eventId: null, timestamp: 0, authenticatedFields: ['timestamp'] });
  }
});

test('checks both ID presences before either grammar and then timestamps', async () => {
  const cases: [Record<string, string>, string][] = [
    [{ 'x-fal-webhook-signature': '' }, 'missing-signature'],
    [{ 'x-fal-webhook-signature': 'x', 'x-fal-webhook-user-id': '' }, 'malformed-signature'],
    [{ 'x-fal-webhook-request-id': 'bad id', 'x-fal-webhook-user-id': '' }, 'missing-identity'],
    [{ 'x-fal-webhook-request-id': '', 'x-fal-webhook-user-id': 'bad id' }, 'missing-identity'],
    [{ 'x-fal-webhook-request-id': 'bad id', 'x-fal-webhook-timestamp': '' }, 'malformed-signature'],
    [{ 'x-fal-webhook-timestamp': '' }, 'missing-timestamp'],
  ];

  for (const [headers, reason] of cases) expect(expectFailure(await parse(headers)).reason).toBe(reason);

  for (const name of ['x-fal-webhook-request-id', 'x-fal-webhook-user-id']) {
    for (const invalid of ['bad id', 'a,b', 'é', '\u007f', 'a'.repeat(1025), '\tbad']) {
      expect(expectFailure(await parse({ [name]: invalid })).reason).toBe('malformed-signature');
    }

    expect((await parse({ [name]: '!'.repeat(1024) })).ok).toBe(true);
  }
});

test.each(['01', '+1', '-1', '1.0', ' 1', '1 ', '9007199254740992', '1e3'])('rejects noncanonical timestamp %j', async value => {
  expect(expectFailure(await parse({ 'x-fal-webhook-timestamp': value })).reason).toBe('malformed-signature');
});

test.each(['0', '1', '9007199254740991'])('accepts canonical safe timestamp %j without doing freshness checks', async value => {
  const parsed = await parse({ 'x-fal-webhook-timestamp': value });

  if (!parsed.ok) throw new Error(parsed.reason);
  expect(parsed.identity.timestamp).toBe(Number(value));
});

test.each(['0'.repeat(126), '0'.repeat(130), 'z'.repeat(128), ` ${SIG}`, `${SIG} `, `ed25519=${SIG}`, `${SIG},${SIG}`])('rejects malformed detached signature %j', async value => {
  expect(expectFailure(await parse({ 'x-fal-webhook-signature': value })).reason).toBe('malformed-signature');
});

test('reads only selected headers and snapshots headers and visible body before a paused digest', async () => {
  const subtle = globalThis.crypto.subtle;
  const digest = subtle.digest.bind(subtle);
  let release: (() => void) | undefined;
  const pause = new Promise<void>(resolve => { release = resolve; });
  jest.spyOn(subtle, 'digest').mockImplementation(async (algorithm, data) => {
    await pause;

    return digest(algorithm, data);
  });
  const bytes = new Uint8Array(body);
  const headers = new Map(Object.entries(HEADERS));
  headers.set('unrelated', '\n');
  const result = falDescriptor.parse(headers, bytes);
  bytes.fill(9);

  for (const name of Object.keys(HEADERS)) headers.set(name, 'changed');

  if (!release) throw new Error('Digest pause not initialized.');
  release();
  const parsed = await result;

  if (!parsed.ok) throw new Error(parsed.reason);
  expect(parsed.signedContent).toEqual(message(body));
  expect(parsed.recipient).toBe('user:1');
});

test('does not rescue missing selected headers with aliases', async () => {
  expect(expectFailure(await falDescriptor.parse(headerMap({ 'fal-signature': SIG, 'x-vercel-signature': SIG }), body)).reason).toBe('missing-signature');
});

test('checks absent identity headers and timestamp in deterministic order', async () => {
  for (const name of ['x-fal-webhook-request-id', 'x-fal-webhook-user-id', 'x-fal-webhook-timestamp']) {
    const headers = new Map(Object.entries(HEADERS));

    headers.delete(name);
    expect(expectFailure(await falDescriptor.parse(headers, body)).reason).toBe(name.endsWith('timestamp') ? 'missing-timestamp' : 'missing-identity');
  }
});

test('matches the independent GLM synthetic baseline public key and detached signature', async () => {
  const bytes = utf8('{"hooklatchStage":9,"case":"fal-positive-baseline"}');
  const hex = 'b8cf0e44028977db5c252828ffbfbef2f8df113d3c2b9c3d5cc640620ab1394ec9c064f601ad0941dc7b16930654569a17e8f73745b4a472358ee3c4bc307c02';
  const publicBytes = Buffer.from('tAc4RHy5UZnJXTUzlKhkLUKAZ-dl3COi0F1Kc3xx4bo', 'base64url');
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), publicBytes]), format: 'der', type: 'spki' });
  const parsed = await parse({ 'x-fal-webhook-signature': hex, 'x-fal-webhook-request-id': '9f8e7d6c-5b4a-4c98-b493-a9ba4e6f4373', 'x-fal-webhook-user-id': 'usr_hooklatch_stage9', 'x-fal-webhook-timestamp': '1792742400' });
  const actual = await falDescriptor.parse(headerMap({ ...HEADERS, 'x-fal-webhook-signature': hex, 'x-fal-webhook-request-id': '9f8e7d6c-5b4a-4c98-b493-a9ba4e6f4373', 'x-fal-webhook-user-id': 'usr_hooklatch_stage9', 'x-fal-webhook-timestamp': '1792742400' }), bytes);

  if (!actual.ok || !parsed.ok) throw new Error('Baseline headers must parse.');
  const actualSignature = actual.signatures[0];
  const parsedSignature = parsed.signatures[0];

  if (actualSignature === undefined || parsedSignature === undefined) throw new Error('Expected detached signatures.');
  expect(verify(null, actual.signedContent, key, actualSignature)).toBe(true);
  expect(verify(null, parsed.signedContent, key, parsedSignature)).toBe(false);
});

test('classifies absent crypto, unsupported digest, and unexpected digest errors without echoing details', async () => {
  const original = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });

  try { await expect(parse()).rejects.toMatchObject({ name: 'HooklatchError', code: 'crypto-unavailable' }); }
  finally { Object.defineProperty(globalThis, 'crypto', { configurable: true, value: original }); }

  const spy = jest.spyOn(original.subtle, 'digest');

  for (const [error, code] of [[new DOMException('sensitive', 'NotSupportedError'), 'crypto-unavailable'], [new Error('sensitive'), 'internal']]) {
    spy.mockRejectedValueOnce(error);
    await expect(parse()).rejects.toMatchObject({ name: 'HooklatchError', code, message: expect.not.stringContaining('sensitive') });
  }
});
