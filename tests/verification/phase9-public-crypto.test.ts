import { createHash, createHmac, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { createVerifier, verify, verifyRequest } from '../../src/index.js';
import type {
  VerificationFailureReason,
  VerificationResult,
  VerifyOptions,
  WebhookRequest,
} from '../../src/index.js';

const NOW = 1_792_454_000;
const VERCEL_SECRET = '  vercel synthetic literal secret 秘密  ';
const VERCEL_BODY = new TextEncoder().encode('{"type":"vercel.synthetic","event":"deploy"}');
const VERCEL_SIGNATURE_HEADER = 'X-Vercel-Signature';

const FAL_REQUEST_ID = 'req_phase9_public_001';
const FAL_USER_ID = 'fal_user_phase9_public_001';
const FAL_BODY = new TextEncoder().encode('{"type":"fal.synthetic","request_id":"req_phase9_public_001"}');
const FAL_SIGNATURE_HEADER = 'X-Fal-Webhook-Signature';
const FAL_REQUEST_ID_HEADER = 'X-Fal-Webhook-Request-Id';
const FAL_USER_ID_HEADER = 'X-Fal-Webhook-User-Id';
const FAL_TIMESTAMP_HEADER = 'X-Fal-Webhook-Timestamp';

const LINEAR_SECRET = 'linear-phase9-source-compat-synthetic-secret';
const LINEAR_BODY = new TextEncoder().encode('{"action":"create","type":"Issue"}');

interface FalKeyPair {
  readonly privateKey: KeyObject;
  readonly publicKey: Uint8Array;
}

/** Synthetic Ed25519 keys from fixed seeds; never real provider material. */
function falKeyPair(seedByte: number): FalKeyPair {
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const seed = Buffer.alloc(32, seedByte);

  const privateKey = createPrivateKey({
    key: Buffer.concat([prefix, seed]),
    format: 'der',
    type: 'pkcs8',
  });

  const jwk = createPublicKey(privateKey).export({ format: 'jwk' });

  if (jwk.x === undefined) throw new Error('Synthetic Ed25519 key has no public x coordinate');
  const publicKey = new Uint8Array(Buffer.from(jwk.x, 'base64url'));

  if (publicKey.byteLength !== 32) throw new Error('Synthetic Ed25519 public key is not 32 bytes');

  return { privateKey, publicKey };
}

const FAL_KEYS: readonly FalKeyPair[] = Array.from(
  { length: 16 },
  (_unused, index) => falKeyPair(index + 1),
);

const FAL_KEY = FAL_KEYS[0]!;

function signVercel(body: Uint8Array, secret: string = VERCEL_SECRET): string {
  return createHmac('sha1', Buffer.from(secret, 'utf8'))
    .update(body)
    .digest('hex');
}

function signLinear(body: Uint8Array): string {
  return createHmac('sha256', Buffer.from(LINEAR_SECRET, 'utf8'))
    .update(body)
    .digest('hex');
}

function falSignedContent(
  requestId: string,
  userId: string,
  timestamp: string,
  body: Uint8Array,
): string {
  const digest = createHash('sha256').update(body).digest('hex');

  return `${requestId}\n${userId}\n${timestamp}\n${digest}`;
}

function signFal(
  body: Uint8Array,
  privateKey: KeyObject,
  requestId: string = FAL_REQUEST_ID,
  userId: string = FAL_USER_ID,
  timestamp: string = String(NOW),
): string {
  return sign(
    null,
    Buffer.from(falSignedContent(requestId, userId, timestamp, body), 'utf8'),
    privateKey,
  ).toString('hex');
}

function falHeaders(
  signature: string,
  requestId: string = FAL_REQUEST_ID,
  userId: string = FAL_USER_ID,
  timestamp: string = String(NOW),
) {
  return {
    [FAL_SIGNATURE_HEADER]: signature,
    [FAL_REQUEST_ID_HEADER]: requestId,
    [FAL_USER_ID_HEADER]: userId,
    [FAL_TIMESTAMP_HEADER]: timestamp,
  };
}

function validFalHeaders(
  body: Uint8Array,
  key: FalKeyPair = FAL_KEY,
  requestId: string = FAL_REQUEST_ID,
  userId: string = FAL_USER_ID,
  timestamp: string = String(NOW),
): Record<string, string> {
  return falHeaders(signFal(body, key.privateKey, requestId, userId, timestamp), requestId, userId, timestamp);
}

function withoutHeader(headers: Record<string, string>, name: string) {
  const copy = { ...headers };
  Reflect.deleteProperty(copy, name);

  return copy;
}

function vercelOptions(secret: string = VERCEL_SECRET, now: number = NOW): VerifyOptions {
  return { provider: 'vercel', secrets: [secret], now: () => now };
}

function falOptions(
  publicKeys: readonly Uint8Array[],
  expectedUserId: string = FAL_USER_ID,
  now: number = NOW,
): VerifyOptions {
  return { provider: 'fal', publicKeys, expectedUserId, now: () => now };
}

function falOptionsWithTolerance(
  publicKeys: readonly Uint8Array[],
  toleranceSeconds: number,
  expectedUserId: string = FAL_USER_ID,
  now: number = NOW,
): VerifyOptions {
  return { provider: 'fal', publicKeys, expectedUserId, toleranceSeconds, now: () => now };
}

function vercelOptionsWithLimit(
  secret: string,
  maxBodyBytes: number,
): VerifyOptions {
  return { provider: 'vercel', secrets: [secret], maxBodyBytes, now: () => NOW };
}

function expectOkAll(
  results: readonly VerificationResult[],
  provider: string,
  rawBody: Uint8Array,
  timestamp: number | null,
  authenticatedFields: readonly string[],
): void {
  expect(results).toHaveLength(3);

  for (const result of results) {
    expect(result.ok).toBe(true);

    if (!result.ok) continue;
    expect(result.provider).toBe(provider);
    expect(result.rawBody).toEqual(rawBody);
    expect(result.identity.deliveryId).toBeNull();
    expect(result.identity.eventId).toBeNull();
    expect(result.identity.timestamp).toBe(timestamp);
    expect([...result.identity.authenticatedFields]).toEqual([...authenticatedFields]);
  }
}

function expectFailureAll(
  results: readonly VerificationResult[],
  provider: string,
  reason: VerificationFailureReason,
): void {
  expect(results).toHaveLength(3);

  for (const result of results) {
    expect(result.ok).toBe(false);

    if (result.ok) continue;
    expect(result.provider).toBe(provider);
    expect(result.reason).toBe(reason);
    expect(result.message.length).toBeGreaterThan(0);
  }
}

async function runAll(
  rawBody: Uint8Array,
  headers: Record<string, string>,
  options: VerifyOptions,
): Promise<readonly VerificationResult[]> {
  const request: WebhookRequest = { rawBody, headers };

  const webRequest = new Request('https://fixture.internal/hook', {
    method: 'POST',
    headers,
    body: new Uint8Array(rawBody),
  });

  const preconfigured = createVerifier(options);
  const viaVerify = await verify(request, options);
  const viaRequest = await verifyRequest(webRequest, options);
  const viaCreated = await preconfigured(request);

  return [viaVerify, viaRequest, viaCreated];
}

async function expectReason(
  rawBody: Uint8Array,
  headers: Record<string, string>,
  options: VerifyOptions,
  provider: string,
  reason: VerificationFailureReason,
): Promise<void> {
  const result = await verify({ rawBody, headers }, options);
  expect(result.ok).toBe(false);

  if (result.ok) return;
  expect(result.provider).toBe(provider);
  expect(result.reason).toBe(reason);
  expect(result.message.length).toBeGreaterThan(0);
}

describe('Phase 9 public-root Vercel HMAC-SHA1', () => {
  test('verifies exact bytes through verify, verifyRequest and createVerifier', async () => {
    const results = await runAll(
      VERCEL_BODY,
      { [VERCEL_SIGNATURE_HEADER]: signVercel(VERCEL_BODY) },
      vercelOptions(),
    );

    expectOkAll(results, 'vercel', VERCEL_BODY, null, []);
  });

  test('uses the literal UTF-8 secret and HMAC-SHA1, not a SHA-256 truncation', async () => {
    const results = await runAll(
      VERCEL_BODY,
      { [VERCEL_SIGNATURE_HEADER]: signVercel(VERCEL_BODY, VERCEL_SECRET) },
      vercelOptions(VERCEL_SECRET),
    );

    expectOkAll(results, 'vercel', VERCEL_BODY, null, []);

    const sha256Truncated = createHmac('sha256', Buffer.from(VERCEL_SECRET, 'utf8'))
      .update(VERCEL_BODY)
      .digest()
      .subarray(0, 20)
      .toString('hex');

    await expectReason(
      VERCEL_BODY,
      { [VERCEL_SIGNATURE_HEADER]: sha256Truncated },
      vercelOptions(VERCEL_SECRET),
      'vercel',
      'invalid-signature',
    );

    await expectReason(
      VERCEL_BODY,
      { [VERCEL_SIGNATURE_HEADER]: signVercel(VERCEL_BODY, VERCEL_SECRET) },
      vercelOptions(VERCEL_SECRET.trim()),
      'vercel',
      'invalid-signature',
    );
  });

  test('enforces exactly 40 ASCII hex characters and a 20-byte signature', async () => {
    const valid = signVercel(VERCEL_BODY);

    const mixed = valid.split('').map((character, index) =>
      index % 2 === 0 ? character.toUpperCase() : character).join('');

    for (const signature of [valid.toUpperCase(), mixed]) {
      const result = await verify(
        { rawBody: VERCEL_BODY, headers: { [VERCEL_SIGNATURE_HEADER]: signature } },
        vercelOptions(),
      );

      expect(result.ok).toBe(true);
    }

    const malformed = [
      valid.slice(0, 39),
      `${valid}0`,
      valid.slice(0, 38),
      `${valid}00`,
      `sha1=${valid}`,
      `${valid},${valid}`,
      valid.replace(/[0-9a-f]/, 'g'),
      ` ${valid}`,
      `${valid} `,
    ];

    for (const signature of malformed) {
      await expectReason(
        VERCEL_BODY,
        { [VERCEL_SIGNATURE_HEADER]: signature },
        vercelOptions(),
        'vercel',
        'malformed-signature',
      );
    }

    await expectReason(
      VERCEL_BODY,
      { [VERCEL_SIGNATURE_HEADER]: '0'.repeat(40) },
      vercelOptions(),
      'vercel',
      'invalid-signature',
    );
  });

  test('maps absent and trim-blank signatures to missing-signature', async () => {
    for (const headers of [
      {},
      { [VERCEL_SIGNATURE_HEADER]: '' },
      { [VERCEL_SIGNATURE_HEADER]: ' \t ' },
    ]) {
      await expectReason(VERCEL_BODY, headers, vercelOptions(), 'vercel', 'missing-signature');
    }
  });

  test('records the WHATWG outer-trim view separately from raw header records', async () => {
    const signature = signVercel(VERCEL_BODY);
    await expectReason(
      VERCEL_BODY,
      { [VERCEL_SIGNATURE_HEADER]: ` ${signature} ` },
      vercelOptions(),
      'vercel',
      'malformed-signature',
    );

    const headers = new Headers();
    headers.set('x-vercel-signature', ` ${signature} `);

    const request = new Request('https://fixture.internal/hook', {
      method: 'POST',
      headers,
      body: new Uint8Array(VERCEL_BODY),
    });

    const result = await verifyRequest(request, vercelOptions());
    expect(result.ok).toBe(true);
  });

  test('rotates literal secrets and rejects removal', async () => {
    const oldSecret = 'vercel-old-synthetic-secret';
    const newSecret = 'vercel-new-synthetic-secret';

    const options: VerifyOptions = {
      provider: 'vercel',
      secrets: [oldSecret, newSecret],
      now: () => NOW,
    };

    for (const secret of [oldSecret, newSecret]) {
      const results = await runAll(
        VERCEL_BODY,
        { [VERCEL_SIGNATURE_HEADER]: signVercel(VERCEL_BODY, secret) },
        options,
      );

      expectOkAll(results, 'vercel', VERCEL_BODY, null, []);
    }

    await expectReason(
      VERCEL_BODY,
      { [VERCEL_SIGNATURE_HEADER]: signVercel(VERCEL_BODY, oldSecret) },
      vercelOptions(newSecret),
      'vercel',
      'invalid-signature',
    );
  });

  test('does not apply freshness or read foreign signature headers', async () => {
    const headers = {
      [VERCEL_SIGNATURE_HEADER]: signVercel(VERCEL_BODY),
      'X-Vercel-Timestamp': '1',
      [FAL_SIGNATURE_HEADER]: '0'.repeat(128),
      [FAL_REQUEST_ID_HEADER]: FAL_REQUEST_ID,
      [FAL_USER_ID_HEADER]: FAL_USER_ID,
      [FAL_TIMESTAMP_HEADER]: '1',
    };

    const results = await runAll(VERCEL_BODY, headers, vercelOptions());
    expectOkAll(results, 'vercel', VERCEL_BODY, null, []);

    await expectReason(
      VERCEL_BODY,
      { [FAL_SIGNATURE_HEADER]: '0'.repeat(128) },
      vercelOptions(),
      'vercel',
      'missing-signature',
    );
  });

  test('preserves visible offsets, binary bodies and empty bodies', async () => {
    const backing = new Uint8Array(VERCEL_BODY.byteLength + 12);
    backing.fill(0xaa);
    backing.set(VERCEL_BODY, 5);
    const bodyView = backing.subarray(5, 5 + VERCEL_BODY.byteLength);

    const offsetResults = await runAll(
      bodyView,
      { [VERCEL_SIGNATURE_HEADER]: signVercel(bodyView) },
      vercelOptions(),
    );

    expectOkAll(offsetResults, 'vercel', bodyView, null, []);

    const binary = new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0x7f, 0x01]);

    const binaryResults = await runAll(
      binary,
      { [VERCEL_SIGNATURE_HEADER]: signVercel(binary) },
      vercelOptions(),
    );

    expectOkAll(binaryResults, 'vercel', binary, null, []);

    const empty = new Uint8Array(0);

    const emptyResults = await runAll(
      empty,
      { [VERCEL_SIGNATURE_HEADER]: signVercel(empty) },
      vercelOptions(),
    );

    expectOkAll(emptyResults, 'vercel', empty, null, []);
  });

  test('applies maxBodyBytes before signature verification', async () => {
    const body = new Uint8Array([1, 2, 3, 4]);
    const signature = signVercel(body);

    const exactResults = await runAll(
      body,
      { [VERCEL_SIGNATURE_HEADER]: signature },
      vercelOptionsWithLimit(VERCEL_SECRET, 4),
    );

    expectOkAll(exactResults, 'vercel', body, null, []);

    const tooSmallResults = await runAll(
      body,
      { [VERCEL_SIGNATURE_HEADER]: signature },
      vercelOptionsWithLimit(VERCEL_SECRET, 3),
    );

    expectFailureAll(tooSmallResults, 'vercel', 'body-too-large');
  });

  test('snapshots the Vercel secret array before awaits', async () => {
    const secrets = [VERCEL_SECRET];

    const options: VerifyOptions = {
      provider: 'vercel',
      secrets,
      now: () => NOW,
    };

    const headers = { [VERCEL_SIGNATURE_HEADER]: signVercel(VERCEL_BODY) };
    const pending = verify({ rawBody: VERCEL_BODY, headers }, options);
    secrets[0] = 'mutated-after-call';
    const result = await pending;
    expect(result.ok).toBe(true);

    const createdSecrets = [VERCEL_SECRET];

    const createdOptions: VerifyOptions = {
      provider: 'vercel',
      secrets: createdSecrets,
      now: () => NOW,
    };

    const verifier = createVerifier(createdOptions);
    createdSecrets[0] = 'mutated-after-setup';
    const created = await verifier({ rawBody: VERCEL_BODY, headers });
    expect(created.ok).toBe(true);
  });

  test('createVerifier returns a promise from asynchronous verification', async () => {
    const verifier = createVerifier(vercelOptions());

    const request: WebhookRequest = {
      rawBody: VERCEL_BODY,
      headers: { [VERCEL_SIGNATURE_HEADER]: '0'.repeat(40) },
    };

    const pending = verifier(request);
    expect(pending).toBeInstanceOf(Promise);
    const result = await pending;
    expect(result.ok).toBe(false);

    if (!result.ok) expect(result.reason).toBe('invalid-signature');
  });
});

describe('Phase 9 public-root fal Ed25519', () => {
  test('verifies canonical signed content through verify, verifyRequest and createVerifier', async () => {
    const results = await runAll(
      FAL_BODY,
      validFalHeaders(FAL_BODY),
      falOptions([FAL_KEY.publicKey]),
    );

    expectOkAll(results, 'fal', FAL_BODY, NOW, ['timestamp']);
  });

  test('accepts one through sixteen keys, duplicates, rotation and removal', async () => {
    const oneKeyResults = await runAll(
      FAL_BODY,
      validFalHeaders(FAL_BODY),
      falOptions([new Uint8Array(FAL_KEY.publicKey)]),
    );

    expectOkAll(oneKeyResults, 'fal', FAL_BODY, NOW, ['timestamp']);

    const sixteen = Array.from(
      { length: 16 },
      (_unused, index) => new Uint8Array(FAL_KEYS[index]!.publicKey),
    );

    const lastKey = FAL_KEYS[15]!;

    const sixteenResults = await runAll(
      FAL_BODY,
      validFalHeaders(FAL_BODY, lastKey),
      falOptions(sixteen),
    );

    expectOkAll(sixteenResults, 'fal', FAL_BODY, NOW, ['timestamp']);

    const duplicateResults = await runAll(
      FAL_BODY,
      validFalHeaders(FAL_BODY),
      falOptions([
        new Uint8Array(FAL_KEY.publicKey),
        new Uint8Array(FAL_KEY.publicKey),
      ]),
    );

    expectOkAll(duplicateResults, 'fal', FAL_BODY, NOW, ['timestamp']);

    const rotatedResults = await runAll(
      FAL_BODY,
      validFalHeaders(FAL_BODY),
      falOptions([FAL_KEYS[1]!.publicKey, FAL_KEY.publicKey]),
    );

    expectOkAll(rotatedResults, 'fal', FAL_BODY, NOW, ['timestamp']);

    await expectReason(
      FAL_BODY,
      validFalHeaders(FAL_BODY),
      falOptions([FAL_KEYS[1]!.publicKey]),
      'fal',
      'invalid-signature',
    );
  });

  test('accepts visible-offset body and key views', async () => {
    const keyBacking = new Uint8Array(96);
    keyBacking.fill(0xaa);
    keyBacking.set(FAL_KEY.publicKey, 17);
    const keyView = keyBacking.subarray(17, 49);

    const bodyBacking = new Uint8Array(FAL_BODY.byteLength + 19);
    bodyBacking.fill(0xbb);
    bodyBacking.set(FAL_BODY, 7);
    const bodyView = bodyBacking.subarray(7, 7 + FAL_BODY.byteLength);

    const results = await runAll(
      bodyView,
      validFalHeaders(bodyView),
      falOptions([keyView]),
    );

    expectOkAll(results, 'fal', bodyView, NOW, ['timestamp']);
  });

  test('preserves binary and empty bodies through all three APIs', async () => {
    const binary = new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0x7f, 0x01]);

    const binaryResults = await runAll(
      binary,
      validFalHeaders(binary),
      falOptions([FAL_KEY.publicKey]),
    );

    expectOkAll(binaryResults, 'fal', binary, NOW, ['timestamp']);

    const empty = new Uint8Array(0);

    const emptyResults = await runAll(
      empty,
      validFalHeaders(empty),
      falOptions([FAL_KEY.publicKey]),
    );

    expectOkAll(emptyResults, 'fal', empty, NOW, ['timestamp']);
  });

  test('enforces 128 hex characters and malformed-before-identity ordering', async () => {
    const valid = signFal(FAL_BODY, FAL_KEY.privateKey);

    const upperResult = await verify(
      { rawBody: FAL_BODY, headers: falHeaders(valid.toUpperCase()) },
      falOptions([FAL_KEY.publicKey]),
    );

    expect(upperResult.ok).toBe(true);

    await expectReason(
      FAL_BODY,
      withoutHeader(falHeaders(valid), FAL_SIGNATURE_HEADER),
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'missing-signature',
    );

    for (const signature of ['', ' \t ']) {
      await expectReason(
        FAL_BODY,
        falHeaders(signature),
        falOptions([FAL_KEY.publicKey]),
        'fal',
        'missing-signature',
      );
    }

    for (const signature of [
      valid.slice(0, 127),
      `${valid}0`,
      valid.replace(/[0-9a-f]/, 'g'),
      `0x${valid}`,
      `${valid},${valid}`,
      ` ${valid}`,
      `${valid} `,
    ]) {
      await expectReason(
        FAL_BODY,
        falHeaders(signature),
        falOptions([FAL_KEY.publicKey]),
        'fal',
        'malformed-signature',
      );
    }

    const headers = new Headers();
    headers.set(FAL_SIGNATURE_HEADER, ` ${valid} `);
    headers.set(FAL_REQUEST_ID_HEADER, FAL_REQUEST_ID);
    headers.set(FAL_USER_ID_HEADER, FAL_USER_ID);
    headers.set(FAL_TIMESTAMP_HEADER, String(NOW));

    const request = new Request('https://fixture.internal/hook', {
      method: 'POST',
      headers,
      body: new Uint8Array(FAL_BODY),
    });

    const trimmedView = await verifyRequest(request, falOptions([FAL_KEY.publicKey]));
    expect(trimmedView.ok).toBe(true);

    await expectReason(
      FAL_BODY,
      falHeaders('0'.repeat(128)),
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'invalid-signature',
    );
  });

  test('checks both identity headers before either identity grammar', async () => {
    const signature = '0'.repeat(128);
    const baseHeaders = falHeaders(signature);

    for (const header of [FAL_REQUEST_ID_HEADER, FAL_USER_ID_HEADER]) {
      await expectReason(
        FAL_BODY,
        withoutHeader(baseHeaders, header),
        falOptions([FAL_KEY.publicKey]),
        'fal',
        'missing-identity',
      );
    }

    for (const value of ['', ' \t ']) {
      for (const header of [FAL_REQUEST_ID_HEADER, FAL_USER_ID_HEADER]) {
        await expectReason(
          FAL_BODY,
          { ...baseHeaders, [header]: value },
          falOptions([FAL_KEY.publicKey]),
          'fal',
          'missing-identity',
        );
      }
    }

    await expectReason(
      FAL_BODY,
      { ...withoutHeader(baseHeaders, FAL_USER_ID_HEADER), [FAL_REQUEST_ID_HEADER]: 'bad id' },
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'missing-identity',
    );

    for (const invalidId of ['bad id', 'bad,id', 'bad\tid', 'bad\u007fid', 'caf\u00e9']) {
      await expectReason(
        FAL_BODY,
        falHeaders(signature, invalidId, FAL_USER_ID, String(NOW)),
        falOptions([FAL_KEY.publicKey]),
        'fal',
        'malformed-signature',
      );
      await expectReason(
        FAL_BODY,
        falHeaders(signature, FAL_REQUEST_ID, invalidId, String(NOW)),
        falOptions([FAL_KEY.publicKey]),
        'fal',
        'malformed-signature',
      );
    }

    const tooLong = 'a'.repeat(1025);
    await expectReason(
      FAL_BODY,
      falHeaders(signature, tooLong, FAL_USER_ID, String(NOW)),
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'malformed-signature',
    );
  });

  test('accepts one and 1024 visible ASCII identity characters', async () => {
    for (const id of ['a', 'a'.repeat(1024)]) {
      const results = await runAll(
        FAL_BODY,
        validFalHeaders(FAL_BODY, FAL_KEY, id, id),
        falOptions([FAL_KEY.publicKey], id),
      );

      expectOkAll(results, 'fal', FAL_BODY, NOW, ['timestamp']);
    }
  });

  test('enforces timestamp grammar and inclusive freshness boundaries', async () => {
    const signature = '0'.repeat(128);
    await expectReason(
      FAL_BODY,
      withoutHeader(falHeaders(signature), FAL_TIMESTAMP_HEADER),
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'missing-timestamp',
    );

    for (const timestamp of ['', ' \t ']) {
      await expectReason(
        FAL_BODY,
        falHeaders(signature, FAL_REQUEST_ID, FAL_USER_ID, timestamp),
        falOptions([FAL_KEY.publicKey]),
        'fal',
        'missing-timestamp',
      );
    }

    for (const timestamp of [
      '+1',
      '-1',
      '01',
      '1.0',
      ' 1',
      '1 ',
      '1e3',
      '0x10',
      '9007199254740992',
      '999999999999999999999',
    ]) {
      await expectReason(
        FAL_BODY,
        falHeaders(signature, FAL_REQUEST_ID, FAL_USER_ID, timestamp),
        falOptions([FAL_KEY.publicKey]),
        'fal',
        'malformed-signature',
      );
    }

    const zeroHeaders = falHeaders(
      signFal(FAL_BODY, FAL_KEY.privateKey, FAL_REQUEST_ID, FAL_USER_ID, '0'),
      FAL_REQUEST_ID,
      FAL_USER_ID,
      '0',
    );

    const zeroResults = await runAll(FAL_BODY, zeroHeaders, falOptions([FAL_KEY.publicKey], FAL_USER_ID, 0));
    expectOkAll(zeroResults, 'fal', FAL_BODY, 0, ['timestamp']);

    const boundaries: readonly (readonly [number, VerificationFailureReason | 'ok'])[] = [
      [NOW - 300, 'ok'],
      [NOW - 301, 'timestamp-expired'],
      [NOW + 300, 'ok'],
      [NOW + 301, 'timestamp-future'],
    ];

    for (const [timestamp, expected] of boundaries) {
      const headers = validFalHeaders(FAL_BODY, FAL_KEY, FAL_REQUEST_ID, FAL_USER_ID, String(timestamp));

      if (expected === 'ok') {
        const result = await verify({ rawBody: FAL_BODY, headers }, falOptions([FAL_KEY.publicKey]));
        expect(result.ok).toBe(true);
      } else {
        await expectReason(FAL_BODY, headers, falOptions([FAL_KEY.publicKey]), 'fal', expected);
      }
    }

    for (const [timestamp, expected] of [
      [NOW, 'ok'],
      [NOW - 1, 'timestamp-expired'],
      [NOW + 1, 'timestamp-future'],
    ] as const) {
      const headers = validFalHeaders(FAL_BODY, FAL_KEY, FAL_REQUEST_ID, FAL_USER_ID, String(timestamp));

      if (expected === 'ok') {
        const result = await verify(
          { rawBody: FAL_BODY, headers },
          falOptionsWithTolerance([FAL_KEY.publicKey], 0),
        );

        expect(result.ok).toBe(true);
      } else {
        await expectReason(
          FAL_BODY,
          headers,
          falOptionsWithTolerance([FAL_KEY.publicKey], 0),
          'fal',
          expected,
        );
      }
    }

    const safeInteger = String(Number.MAX_SAFE_INTEGER);
    await expectReason(
      FAL_BODY,
      validFalHeaders(FAL_BODY, FAL_KEY, FAL_REQUEST_ID, FAL_USER_ID, safeInteger),
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'timestamp-future',
    );

    const milliseconds = String(NOW * 1000);
    await expectReason(
      FAL_BODY,
      validFalHeaders(FAL_BODY, FAL_KEY, FAL_REQUEST_ID, FAL_USER_ID, milliseconds),
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'timestamp-future',
    );
  });

  test('orders bad MAC before account binding and account binding before freshness', async () => {
    const stale = String(NOW - 1000);

    const wrongMacSignature = signFal(
      FAL_BODY,
      FAL_KEYS[1]!.privateKey,
      FAL_REQUEST_ID,
      'different_user',
      stale,
    );

    await expectReason(
      FAL_BODY,
      falHeaders(wrongMacSignature, FAL_REQUEST_ID, 'different_user', stale),
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'invalid-signature',
    );

    const mismatchSignature = signFal(
      FAL_BODY,
      FAL_KEY.privateKey,
      FAL_REQUEST_ID,
      'different_user',
      stale,
    );

    await expectReason(
      FAL_BODY,
      falHeaders(mismatchSignature, FAL_REQUEST_ID, 'different_user', stale),
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'invalid-signature',
    );

    const staleSignature = signFal(
      FAL_BODY,
      FAL_KEY.privateKey,
      FAL_REQUEST_ID,
      FAL_USER_ID,
      stale,
    );

    await expectReason(
      FAL_BODY,
      falHeaders(staleSignature, FAL_REQUEST_ID, FAL_USER_ID, stale),
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'timestamp-expired',
    );
  });

  test('signs the exact canonical content without a trailing newline or digest case rescue', async () => {
    const digest = createHash('sha256').update(FAL_BODY).digest('hex');
    const canonical = `${FAL_REQUEST_ID}\n${FAL_USER_ID}\n${String(NOW)}\n${digest}`;
    const trailingNewline = `${canonical}\n`;

    const trailingSignature = sign(
      null,
      Buffer.from(trailingNewline, 'utf8'),
      FAL_KEY.privateKey,
    ).toString('hex');

    await expectReason(
      FAL_BODY,
      falHeaders(trailingSignature),
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'invalid-signature',
    );

    const uppercaseDigest = digest.toUpperCase();
    const uppercaseContent = `${FAL_REQUEST_ID}\n${FAL_USER_ID}\n${String(NOW)}\n${uppercaseDigest}`;

    const uppercaseSignature = sign(
      null,
      Buffer.from(uppercaseContent, 'utf8'),
      FAL_KEY.privateKey,
    ).toString('hex');

    await expectReason(
      FAL_BODY,
      falHeaders(uppercaseSignature),
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'invalid-signature',
    );
  });

  test('isolates header families and rejects equal duplicate signatures', async () => {
    const validHeaders = validFalHeaders(FAL_BODY);
    await expectReason(
      FAL_BODY,
      withoutHeader(validHeaders, FAL_SIGNATURE_HEADER),
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'missing-signature',
    );

    await expectReason(
      FAL_BODY,
      { [VERCEL_SIGNATURE_HEADER]: signVercel(FAL_BODY) },
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'missing-signature',
    );

    await expectReason(
      FAL_BODY,
      { 'X-Fal-Signature': validHeaders[FAL_SIGNATURE_HEADER] ?? '' },
      falOptions([FAL_KEY.publicKey]),
      'fal',
      'missing-signature',
    );

    const duplicate = validHeaders[FAL_SIGNATURE_HEADER];

    if (duplicate === undefined) throw new Error('Synthetic fal signature header missing');

    const result = await verify(
      {
        rawBody: FAL_BODY,
        headers: { ...validHeaders, [FAL_SIGNATURE_HEADER]: [duplicate, duplicate] },
      },
      falOptions([FAL_KEY.publicKey]),
    );

    expect(result.ok).toBe(false);

    if (!result.ok) expect(result.reason).toBe('malformed-signature');
  });

  test('snapshots request body bytes before asynchronous verification', async () => {
    const body = new Uint8Array(FAL_BODY);
    const headers = validFalHeaders(body);
    const pending = verify({ rawBody: body, headers }, falOptions([FAL_KEY.publicKey]));
    body.fill(0);
    const result = await pending;
    expect(result.ok).toBe(true);

    if (result.ok) expect(result.rawBody).toEqual(FAL_BODY);
  });

  test('snapshots the public-key array and key bytes before awaits', async () => {
    const keyCopy = new Uint8Array(FAL_KEY.publicKey);
    const keys = [keyCopy];
    const options = falOptions(keys);
    const headers = validFalHeaders(FAL_BODY);
    const pending = verify({ rawBody: FAL_BODY, headers }, options);
    keyCopy.fill(0);
    keys[0] = new Uint8Array(32);
    const result = await pending;
    expect(result.ok).toBe(true);

    const createdKeyCopy = new Uint8Array(FAL_KEY.publicKey);
    const verifier = createVerifier(falOptions([createdKeyCopy]));
    createdKeyCopy.fill(0);
    const created = await verifier({ rawBody: FAL_BODY, headers });
    expect(created.ok).toBe(true);
  });

  test('never echoes secrets, body content, identity values or signatures in failures', async () => {
    const bodyMarker = 'phase9-body-marker-3f7a';
    const requestMarker = 'phase9-request-marker-9c21';
    const userMarker = 'phase9-user-marker-6b04';
    const expectedMarker = 'phase9-expected-marker-1d88';
    const body = new TextEncoder().encode(`{"marker":"${bodyMarker}"}`);

    const signature = signFal(
      body,
      FAL_KEY.privateKey,
      `req_${requestMarker}`,
      `user_${userMarker}`,
    );

    const headers = falHeaders(
      signature,
      `req_${requestMarker}`,
      `user_${userMarker}`,
    );

    const result = await verify(
      { rawBody: body, headers },
      falOptions([FAL_KEY.publicKey], `expected_${expectedMarker}`),
    );

    expect(result.ok).toBe(false);

    if (result.ok) return;
    expect(result.reason).toBe('invalid-signature');

    for (const marker of [bodyMarker, requestMarker, userMarker, expectedMarker, signature]) {
      expect(result.message).not.toContain(marker);
    }

    const vercelMarker = 'phase9-vercel-marker-54e2';
    const vercelBody = new TextEncoder().encode(`{"marker":"${vercelMarker}"}`);

    const vercelResult = await verify(
      {
        rawBody: vercelBody,
        headers: {
          [VERCEL_SIGNATURE_HEADER]: '0'.repeat(40),
          'X-Vercel-Timestamp': vercelMarker,
        },
      },
      vercelOptions(`secret_${vercelMarker}`),
    );

    expect(vercelResult.ok).toBe(false);

    if (!vercelResult.ok) {
      expect(vercelResult.reason).toBe('invalid-signature');
      expect(vercelResult.message).not.toContain(vercelMarker);
    }
  });
});

const LINEAR_OPTIONS = {
  provider: 'linear',
  secrets: [LINEAR_SECRET],
  now: () => NOW,
} satisfies VerifyOptions;

describe('Phase 9 public source compatibility', () => {
  test('existing secret-based VerifyOptions callers remain valid through all three APIs', async () => {
    const results = await runAll(
      LINEAR_BODY,
      { 'Linear-Signature': signLinear(LINEAR_BODY) },
      LINEAR_OPTIONS,
    );

    expectOkAll(results, 'linear', LINEAR_BODY, null, []);
  });
});
