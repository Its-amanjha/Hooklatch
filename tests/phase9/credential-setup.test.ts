import { createHash, createHmac, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { createVerifier, HooklatchError, verify, verifyRequest } from '../../src/index.js';
import type { VerificationResult, VerifyOptions, WebhookRequest } from '../../src/index.js';

const NOW = 1_792_454_000;
const VERCEL_SECRET = 'vercel-setup-synthetic-secret';
const VERCEL_BODY = new TextEncoder().encode('{"type":"vercel.setup"}');
const FAL_USER_ID = 'fal_user_phase9_setup_001';
const FAL_REQUEST_ID = 'req_phase9_setup_001';
const FAL_BODY = new TextEncoder().encode('{"type":"fal.setup"}');
const STREAM_BODY = new TextEncoder().encode('{"stream":true}');

const FAL_SIGNATURE_HEADER = 'X-Fal-Webhook-Signature';
const FAL_REQUEST_ID_HEADER = 'X-Fal-Webhook-Request-Id';
const FAL_USER_ID_HEADER = 'X-Fal-Webhook-User-Id';
const FAL_TIMESTAMP_HEADER = 'X-Fal-Webhook-Timestamp';
const VERCEL_SIGNATURE_HEADER = 'X-Vercel-Signature';

type OptionValue = string | number | boolean | null | undefined
  | readonly string[] | readonly Uint8Array[] | (() => number);

interface FalKeyPair {
  readonly privateKey: KeyObject;
  readonly publicKey: Uint8Array;
}

interface InstrumentedStream {
  readonly stream: ReadableStream<Uint8Array>;
  readonly wasPulled: () => boolean;
  readonly markStarted: () => void;
}

interface StreamRequestInit extends RequestInit {
  duplex: 'half';
}

const STREAM_MODE: StreamRequestInit = { duplex: 'half' };

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

function signVercel(body: Uint8Array): string {
  return createHmac('sha1', Buffer.from(VERCEL_SECRET, 'utf8'))
    .update(body)
    .digest('hex');
}

function signFal(
  body: Uint8Array,
  privateKey: KeyObject,
  requestId: string = FAL_REQUEST_ID,
  userId: string = FAL_USER_ID,
  timestamp: string = String(NOW),
): string {
  const digest = createHash('sha256').update(body).digest('hex');
  const content = `${requestId}\n${userId}\n${timestamp}\n${digest}`;

  return sign(null, Buffer.from(content, 'utf8'), privateKey).toString('hex');
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

function validFalHeaders(body: Uint8Array): Record<string, string> {
  return falHeaders(signFal(body, FAL_KEY.privateKey));
}

function setOption(
  options: VerifyOptions,
  key: string,
  value: OptionValue,
  enumerable = true,
): void {
  Object.defineProperty(options, key, {
    value,
    enumerable,
    configurable: true,
    writable: true,
  });
}

function setGetter(options: VerifyOptions, key: string, getter: () => OptionValue): void {
  Object.defineProperty(options, key, {
    get: getter,
    enumerable: true,
    configurable: true,
  });
}

function deleteOption(options: VerifyOptions, key: string): void {
  Reflect.deleteProperty(options, key);
}

function vercelOptions(secret: string = VERCEL_SECRET): VerifyOptions {
  return { provider: 'vercel', secrets: [secret], now: () => NOW };
}

function falOptions(
  publicKeys: readonly Uint8Array[],
  expectedUserId: string = FAL_USER_ID,
): VerifyOptions {
  return { provider: 'fal', publicKeys, expectedUserId, now: () => NOW };
}

function expectSetupCodeSync(run: () => void, code: string): HooklatchError {
  let thrown: unknown;

  try {
    run();
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(HooklatchError);

  if (!(thrown instanceof HooklatchError)) throw new Error('Expected HooklatchError');
  expect(thrown.code).toBe(code);

  return thrown;
}

async function expectSetupCodeAsync(
  run: () => Promise<VerificationResult | void>,
  code: string,
): Promise<HooklatchError> {
  let thrown: unknown;

  try {
    await run();
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(HooklatchError);

  if (!(thrown instanceof HooklatchError)) throw new Error('Expected HooklatchError');
  expect(thrown.code).toBe(code);

  return thrown;
}

function expectNoLeak(error: HooklatchError, markers: readonly string[]): void {
  for (const marker of markers) expect(error.message).not.toContain(marker);
}

function instrumentedStream(): InstrumentedStream {
  let started = false;
  let pulled = false;

  const stream = new ReadableStream<Uint8Array>({
    start() {},
    pull(controller) {
      if (started) pulled = true;
      controller.enqueue(STREAM_BODY);
      controller.close();
    },
  }, { highWaterMark: 0 });

  return {
    stream,
    wasPulled: () => pulled,
    markStarted: () => {
      started = true;
    },
  };
}

function streamRequest(
  headers: Record<string, string>,
  stream: ReadableStream<Uint8Array>,
): Request {
  return new Request('https://fixture.internal/hook', {
    method: 'POST',
    headers,
    body: stream,
    ...STREAM_MODE,
  });
}

function falPublicKeys(count: number): readonly Uint8Array[] {
  return Array.from(
    { length: count },
    (_unused, index) => new Uint8Array(FAL_KEYS[index % FAL_KEYS.length]!.publicKey),
  );
}

function inheritedFalOptions(inherit: 'publicKeys' | 'expectedUserId'): VerifyOptions {
  class FalOptionsWithPrototypeCredentials {
    readonly provider = 'fal' as const;
    readonly now = (): number => NOW;

    get publicKeys(): readonly Uint8Array[] {
      return [FAL_KEY.publicKey];
    }

    get expectedUserId(): string {
      return FAL_USER_ID;
    }
  }

  const options = new FalOptionsWithPrototypeCredentials();

  if (inherit === 'publicKeys') {
    Object.defineProperty(options, 'expectedUserId', {
      value: FAL_USER_ID,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  } else {
    Object.defineProperty(options, 'publicKeys', {
      value: [FAL_KEY.publicKey],
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }

  return options;
}

describe('Phase 9 Vercel credential setup', () => {
  test('accepts literal nonempty secrets synchronously', () => {
    expect(createVerifier(vercelOptions(VERCEL_SECRET))).toBeDefined();
    expect(createVerifier(vercelOptions('   '))).toBeDefined();
  });

  test('rejects missing, malformed and invalid secret lists', () => {
    const missing = vercelOptions();
    deleteOption(missing, 'secrets');
    expectSetupCodeSync(() => createVerifier(missing), 'missing-secrets');

    const empty = vercelOptions();
    setOption(empty, 'secrets', []);
    expectSetupCodeSync(() => createVerifier(empty), 'missing-secrets');

    const nullList = vercelOptions();
    setOption(nullList, 'secrets', null);
    expectSetupCodeSync(() => createVerifier(nullList), 'missing-secrets');

    const nonArray = vercelOptions();
    setOption(nonArray, 'secrets', 'not-an-array');
    expectSetupCodeSync(() => createVerifier(nonArray), 'missing-secrets');

    const emptyElement = vercelOptions();
    setOption(emptyElement, 'secrets', [VERCEL_SECRET, '']);
    expectSetupCodeSync(() => createVerifier(emptyElement), 'invalid-secret');

    const nonStringElement = vercelOptions();
    const withNumber: readonly string[] = [VERCEL_SECRET];
    Object.defineProperty(withNumber, 0, { value: 42 });
    setOption(nonStringElement, 'secrets', withNumber);
    expectSetupCodeSync(() => createVerifier(nonStringElement), 'invalid-secret');

    const nullElement = vercelOptions();
    const withNull: readonly string[] = [VERCEL_SECRET];
    Object.defineProperty(withNull, 0, { value: null });
    setOption(nullElement, 'secrets', withNull);
    expectSetupCodeSync(() => createVerifier(nullElement), 'invalid-secret');
  });

  test('rejects every forbidden Vercel credential field, including own undefined', () => {
    const publicKeys = vercelOptions();
    setOption(publicKeys, 'publicKeys', [FAL_KEY.publicKey]);
    expectSetupCodeSync(() => createVerifier(publicKeys), 'invalid-options');

    const publicKeysUndefined = vercelOptions();
    setOption(publicKeysUndefined, 'publicKeys', undefined);
    expectSetupCodeSync(() => createVerifier(publicKeysUndefined), 'invalid-options');

    const expectedUserId = vercelOptions();
    setOption(expectedUserId, 'expectedUserId', FAL_USER_ID);
    expectSetupCodeSync(() => createVerifier(expectedUserId), 'invalid-options');

    const expectedUserIdUndefined = vercelOptions();
    setOption(expectedUserIdUndefined, 'expectedUserId', undefined);
    expectSetupCodeSync(() => createVerifier(expectedUserIdUndefined), 'invalid-options');

    const providerOptions = vercelOptions();
    setOption(providerOptions, 'providerOptions', null);
    expectSetupCodeSync(() => createVerifier(providerOptions), 'invalid-options');

    const providerOptionsUndefined = vercelOptions();
    setOption(providerOptionsUndefined, 'providerOptions', undefined);
    expectSetupCodeSync(() => createVerifier(providerOptionsUndefined), 'invalid-options');
  });

  test('validates common bounds even without freshness', () => {
    const negativeTolerance = vercelOptions();
    setOption(negativeTolerance, 'toleranceSeconds', -1);
    expectSetupCodeSync(() => createVerifier(negativeTolerance), 'invalid-options');

    const zeroLimit = vercelOptions();
    setOption(zeroLimit, 'maxBodyBytes', 0);
    expectSetupCodeSync(() => createVerifier(zeroLimit), 'invalid-options');

    const nonFunctionClock = vercelOptions();
    setOption(nonFunctionClock, 'now', 42);
    expectSetupCodeSync(() => createVerifier(nonFunctionClock), 'invalid-options');
  });

  test('verify rejects setup errors asynchronously', async () => {
    const options = vercelOptions();
    setOption(options, 'expectedUserId', FAL_USER_ID);
    const request: WebhookRequest = { rawBody: VERCEL_BODY, headers: {} };
    const pending = verify(request, options);
    expect(pending).toBeInstanceOf(Promise);
    await expectSetupCodeAsync(() => pending, 'invalid-options');
  });
});

describe('Phase 9 fal credential setup', () => {
  test('accepts one through sixteen raw 32-byte keys and snapshots the key array', async () => {
    expect(createVerifier(falOptions(falPublicKeys(1)))).toBeDefined();
    expect(createVerifier(falOptions(falPublicKeys(16)))).toBeDefined();
    expect(createVerifier(falOptions([
      new Uint8Array(FAL_KEY.publicKey),
      new Uint8Array(FAL_KEY.publicKey),
    ]))).toBeDefined();

    const keys = [new Uint8Array(FAL_KEY.publicKey)];
    const verifier = createVerifier(falOptions(keys));
    keys[0]!.fill(0);

    const result = await verifier({
      rawBody: FAL_BODY,
      headers: validFalHeaders(FAL_BODY),
    });

    expect(result.ok).toBe(true);
  });

  test('rejects missing, non-array, empty, oversized and wrong-length key collections', () => {
    expectSetupCodeSync(() => createVerifier(falOptions([])), 'invalid-options');
    expectSetupCodeSync(() => createVerifier(falOptions(falPublicKeys(17))), 'invalid-options');
    expectSetupCodeSync(() => createVerifier(falOptions([new Uint8Array(0)])), 'invalid-options');
    expectSetupCodeSync(() => createVerifier(falOptions([new Uint8Array(31)])), 'invalid-options');
    expectSetupCodeSync(() => createVerifier(falOptions([new Uint8Array(33)])), 'invalid-options');

    const missing = falOptions([FAL_KEY.publicKey]);
    deleteOption(missing, 'publicKeys');
    expectSetupCodeSync(() => createVerifier(missing), 'invalid-options');

    const ownUndefined = falOptions([FAL_KEY.publicKey]);
    setOption(ownUndefined, 'publicKeys', undefined);
    expectSetupCodeSync(() => createVerifier(ownUndefined), 'invalid-options');

    const nonArray = falOptions([FAL_KEY.publicKey]);
    setOption(nonArray, 'publicKeys', 'not-an-array');
    expectSetupCodeSync(() => createVerifier(nonArray), 'invalid-options');

    const nullKeys = falOptions([FAL_KEY.publicKey]);
    setOption(nullKeys, 'publicKeys', null);
    expectSetupCodeSync(() => createVerifier(nullKeys), 'invalid-options');

    const nonByteEntry = [new Uint8Array(FAL_KEY.publicKey)];
    Object.defineProperty(nonByteEntry, 0, { value: 'not-a-key' });
    expectSetupCodeSync(() => createVerifier(falOptions(nonByteEntry)), 'invalid-options');

    const hole: Uint8Array[] = [];
    hole.length = 2;
    hole[1] = new Uint8Array(FAL_KEY.publicKey);
    expectSetupCodeSync(() => createVerifier(falOptions(hole)), 'invalid-options');

    const detached = new Uint8Array(new ArrayBuffer(32));
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    expectSetupCodeSync(() => createVerifier(falOptions([detached])), 'invalid-options');
  });

  test('requires an own, visible-ASCII expectedUserId', () => {
    const missing = falOptions([FAL_KEY.publicKey]);
    deleteOption(missing, 'expectedUserId');
    expectSetupCodeSync(() => createVerifier(missing), 'invalid-options');

    const ownUndefined = falOptions([FAL_KEY.publicKey]);
    setOption(ownUndefined, 'expectedUserId', undefined);
    expectSetupCodeSync(() => createVerifier(ownUndefined), 'invalid-options');

    for (const expectedUserId of ['', 'bad id', 'bad,id', 'a'.repeat(1025)]) {
      const options = falOptions([FAL_KEY.publicKey]);
      setOption(options, 'expectedUserId', expectedUserId);
      expectSetupCodeSync(() => createVerifier(options), 'invalid-options');
    }

    const nonString = falOptions([FAL_KEY.publicKey]);
    setOption(nonString, 'expectedUserId', 42);
    expectSetupCodeSync(() => createVerifier(nonString), 'invalid-options');

    const nonEnumerableBadKeys = falOptions([FAL_KEY.publicKey]);
    setOption(nonEnumerableBadKeys, 'publicKeys', [new Uint8Array(31)], false);
    expectSetupCodeSync(() => createVerifier(nonEnumerableBadKeys), 'invalid-options');

    const nonEnumerableBadUser = falOptions([FAL_KEY.publicKey]);
    setOption(nonEnumerableBadUser, 'expectedUserId', 'bad id', false);
    expectSetupCodeSync(() => createVerifier(nonEnumerableBadUser), 'invalid-options');

    expect(createVerifier(falOptions([FAL_KEY.publicKey], 'a'))).toBeDefined();
    expect(createVerifier(falOptions([FAL_KEY.publicKey], 'a'.repeat(1024)))).toBeDefined();
  });

  test('rejects every forbidden fal credential field, including own undefined', () => {
    const secrets = falOptions([FAL_KEY.publicKey]);
    setOption(secrets, 'secrets', [VERCEL_SECRET]);
    expectSetupCodeSync(() => createVerifier(secrets), 'invalid-options');

    const secretsUndefined = falOptions([FAL_KEY.publicKey]);
    setOption(secretsUndefined, 'secrets', undefined);
    expectSetupCodeSync(() => createVerifier(secretsUndefined), 'invalid-options');

    const singularSecret = falOptions([FAL_KEY.publicKey]);
    setOption(singularSecret, 'secret', VERCEL_SECRET);
    expectSetupCodeSync(() => createVerifier(singularSecret), 'invalid-options');

    const providerOptions = falOptions([FAL_KEY.publicKey]);
    setOption(providerOptions, 'providerOptions', null);
    expectSetupCodeSync(() => createVerifier(providerOptions), 'invalid-options');

    const providerOptionsUndefined = falOptions([FAL_KEY.publicKey]);
    setOption(providerOptionsUndefined, 'providerOptions', undefined);
    expectSetupCodeSync(() => createVerifier(providerOptionsUndefined), 'invalid-options');
  });

  test('accepts non-enumerable valid own credentials and preserves them through createVerifier', async () => {
    const options = falOptions([new Uint8Array(FAL_KEY.publicKey)]);
    setOption(options, 'publicKeys', [new Uint8Array(FAL_KEY.publicKey)], false);
    setOption(options, 'expectedUserId', FAL_USER_ID, false);

    const verifier = createVerifier(options);

    const result = await verifier({
      rawBody: FAL_BODY,
      headers: validFalHeaders(FAL_BODY),
    });

    expect(result.ok).toBe(true);
  });

  test('rejects inherited, accessor and proxy credential reads', () => {
    expectSetupCodeSync(
      () => createVerifier(inheritedFalOptions('publicKeys')),
      'invalid-options',
    );
    expectSetupCodeSync(
      () => createVerifier(inheritedFalOptions('expectedUserId')),
      'invalid-options',
    );

    const publicKeysAccessor = falOptions([FAL_KEY.publicKey]);
    setGetter(publicKeysAccessor, 'publicKeys', () => [FAL_KEY.publicKey]);
    expectSetupCodeSync(() => createVerifier(publicKeysAccessor), 'invalid-options');

    const expectedUserAccessor = falOptions([FAL_KEY.publicKey]);
    setGetter(expectedUserAccessor, 'expectedUserId', () => FAL_USER_ID);
    expectSetupCodeSync(() => createVerifier(expectedUserAccessor), 'invalid-options');

    const marker = 'phase9-accessor-marker-71c3';
    const throwingPublicKeys = falOptions([FAL_KEY.publicKey]);
    setGetter(throwingPublicKeys, 'publicKeys', () => {
      throw new Error(marker);
    });

    const accessorError = expectSetupCodeSync(
      () => createVerifier(throwingPublicKeys),
      'invalid-options',
    );

    expectNoLeak(accessorError, [marker]);

    const proxy = new Proxy(falOptions([FAL_KEY.publicKey]), {
      get(_target, property) {
        throw new Error(`${marker}:${String(property)}`);
      },
      getOwnPropertyDescriptor(_target, property) {
        throw new Error(`${marker}:${String(property)}`);
      },
    });

    const proxyError = expectSetupCodeSync(() => createVerifier(proxy), 'invalid-options');
    expectNoLeak(proxyError, [marker]);

    const revocable = Proxy.revocable(falOptions([FAL_KEY.publicKey]), {});
    revocable.revoke();
    expectSetupCodeSync(() => createVerifier(revocable.proxy), 'invalid-options');
  });

  test('honors common bounds and defers clock invocation to verification', async () => {
    const negativeTolerance = falOptions([FAL_KEY.publicKey]);
    setOption(negativeTolerance, 'toleranceSeconds', -1);
    expectSetupCodeSync(() => createVerifier(negativeTolerance), 'invalid-options');

    const zeroLimit = falOptions([FAL_KEY.publicKey]);
    setOption(zeroLimit, 'maxBodyBytes', 0);
    expectSetupCodeSync(() => createVerifier(zeroLimit), 'invalid-options');

    const nonFunctionClock = falOptions([FAL_KEY.publicKey]);
    setOption(nonFunctionClock, 'now', 42);
    expectSetupCodeSync(() => createVerifier(nonFunctionClock), 'invalid-options');

    let clockCalls = 0;
    const options = falOptions([FAL_KEY.publicKey]);
    setOption(options, 'now', () => {
      clockCalls += 1;

      return NOW;
    });
    const verifier = createVerifier(options);
    expect(clockCalls).toBe(0);

    const result = await verifier({
      rawBody: FAL_BODY,
      headers: validFalHeaders(FAL_BODY),
    });

    expect(result.ok).toBe(true);
    expect(clockCalls).toBe(1);

    const throwingClock = falOptions([FAL_KEY.publicKey]);
    setOption(throwingClock, 'now', () => {
      throw new Error('phase9-clock-marker');
    });
    const throwingClockVerifier = createVerifier(throwingClock);
    await expectSetupCodeAsync(
      () => throwingClockVerifier({
        rawBody: FAL_BODY,
        headers: validFalHeaders(FAL_BODY),
      }),
      'invalid-options',
    );
  });

  test('verify rejects setup errors asynchronously', async () => {
    const options = falOptions([]);
    const pending = verify({ rawBody: FAL_BODY, headers: validFalHeaders(FAL_BODY) }, options);
    expect(pending).toBeInstanceOf(Promise);
    await expectSetupCodeAsync(() => pending, 'invalid-options');
  });
});

describe('Phase 9 setup-before-body ordering', () => {
  test('invalid fal setup does not read the clock or pull the body', async () => {
    let clockRead = false;
    const options = falOptions([]);
    setOption(options, 'now', () => {
      clockRead = true;

      return NOW;
    });
    const instrumented = instrumentedStream();
    const request = streamRequest({}, instrumented.stream);
    instrumented.markStarted();

    await expectSetupCodeAsync(() => verifyRequest(request, options), 'invalid-options');
    expect(clockRead).toBe(false);
    expect(instrumented.wasPulled()).toBe(false);
  });

  test('invalid Vercel setup does not pull the body', async () => {
    const options = vercelOptions();
    setOption(options, 'publicKeys', [FAL_KEY.publicKey]);
    const instrumented = instrumentedStream();
    const request = streamRequest({}, instrumented.stream);
    instrumented.markStarted();

    await expectSetupCodeAsync(() => verifyRequest(request, options), 'invalid-options');
    expect(instrumented.wasPulled()).toBe(false);
  });

  test('captures the fal clock before pulling the body', async () => {
    let clockRead = false;
    let pulledAfterClock = false;
    const options = falOptions([FAL_KEY.publicKey]);
    setOption(options, 'now', () => {
      clockRead = true;

      return NOW;
    });

    const stream = new ReadableStream<Uint8Array>({
      start() {},
      pull(controller) {
        pulledAfterClock = clockRead;
        controller.enqueue(STREAM_BODY);
        controller.close();
      },
    }, { highWaterMark: 0 });

    const request = streamRequest(validFalHeaders(STREAM_BODY), stream);

    const result = await verifyRequest(request, options);
    expect(result.ok).toBe(true);
    expect(clockRead).toBe(true);
    expect(pulledAfterClock).toBe(true);
  });

  test('captures the Vercel clock before pulling the body', async () => {
    let clockRead = false;
    let pulledAfterClock = false;
    const options = vercelOptions();
    setOption(options, 'now', () => {
      clockRead = true;

      return NOW;
    });

    const stream = new ReadableStream<Uint8Array>({
      start() {},
      pull(controller) {
        pulledAfterClock = clockRead;
        controller.enqueue(STREAM_BODY);
        controller.close();
      },
    }, { highWaterMark: 0 });

    const request = streamRequest({ [VERCEL_SIGNATURE_HEADER]: signVercel(STREAM_BODY) }, stream);

    const result = await verifyRequest(request, options);
    expect(result.ok).toBe(true);
    expect(clockRead).toBe(true);
    expect(pulledAfterClock).toBe(true);
  });
});

describe('Phase 9 setup failure message containment', () => {
  test('generic setup failures never echo credential markers', () => {
    const marker = 'phase9-setup-marker-92d1';
    const invalidUser = falOptions([FAL_KEY.publicKey], `${marker} bad`);

    const userError = expectSetupCodeSync(
      () => createVerifier(invalidUser),
      'invalid-options',
    );

    expectNoLeak(userError, [marker]);

    const throwingGetter = falOptions([FAL_KEY.publicKey]);
    setGetter(throwingGetter, 'expectedUserId', () => {
      throw new Error(marker);
    });

    const getterError = expectSetupCodeSync(
      () => createVerifier(throwingGetter),
      'invalid-options',
    );

    expectNoLeak(getterError, [marker]);
  });
});
