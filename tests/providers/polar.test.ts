import { createHmac } from 'node:crypto';
import { HooklatchError } from '../../src/errors.js';
import { concatBytes, decodeBase64, utf8 } from '../../src/internal/bytes.js';
import { createPolarDescriptor } from '../../src/providers/polar.js';
import type { PolarDescriptorOptions } from '../../src/providers/polar.js';
import { base64Of, expectFailure, expectOk, headerMap, ternErrorCode } from './helpers.js';

const CURRENT_SECRET = `whsec_${base64Of(new Uint8Array(32).fill(0x41))}`;
const CURRENT_SECRET_ALT = `whsec_${base64Of(new Uint8Array(32).fill(0x42))}`;
const LEGACY_SECRET_A = 'polar-legacy-synthetic-secret-alpha-2026';
const LEGACY_SECRET_B = 'polar-legacy-synthetic-secret-beta-2026';
const EVENT_ID = 'msg_phase7_polar_synthetic_0001';
const TIMESTAMP = '1792450000';
const BODY = utf8('{"type":"order.created","data":{"id":"synthetic-order-1"}}');
const CANARY = 'phase7-polar-config-canary-6d2b9f';

type PolarHeaderRecord = {
  'webhook-id'?: string;
  'webhook-timestamp'?: string;
  'webhook-signature': string;
};

type MutablePolarOptions = { secretMode?: 'current' | 'legacy' };

function polarHeaders(
  signature: string,
  id: string | null = EVENT_ID,
  timestamp: string | null = TIMESTAMP,
): PolarHeaderRecord {
  const record: PolarHeaderRecord = { 'webhook-signature': signature };

  if (id !== null) record['webhook-id'] = id;

  if (timestamp !== null) record['webhook-timestamp'] = timestamp;

  return record;
}

function contentFor(id: string, timestamp: string, body: Uint8Array): Uint8Array {
  return concatBytes(utf8(`${id}.${timestamp}.`), body);
}

/** Independent test-only HMAC anchor. No official Polar vector is claimed. */
function sign(
  key: string | Uint8Array,
  id: string = EVENT_ID,
  timestamp: string = TIMESTAMP,
  body: Uint8Array = BODY,
): string {
  return createHmac('sha256', key).update(contentFor(id, timestamp, body)).digest('base64');
}

function token(signature: string): string {
  return `v1,${signature}`;
}

function macMatches(
  key: string | Uint8Array,
  content: Uint8Array,
  signatures: readonly Uint8Array[],
): boolean {
  const expected = createHmac('sha256', key).update(content).digest();

  return signatures.some((signature) => Buffer.from(signature).equals(expected));
}

function polarError(options: PolarDescriptorOptions): HooklatchError {
  try {
    createPolarDescriptor(options);
  } catch (error) {
    if (error instanceof HooklatchError) return error;

    throw error;
  }

  throw new Error('Expected invalid Polar provider options.');
}

test('defaults to current mode and derives the canonical Base64 key', () => {
  const descriptor = createPolarDescriptor();
  const explicit = createPolarDescriptor({ secretMode: 'current' });
  const expectedKey = decodeBase64(CURRENT_SECRET.slice('whsec_'.length));

  if (expectedKey === null) throw new Error('The synthetic current secret must decode.');

  expect(descriptor.provider).toBe('polar');
  expect(descriptor.decodeSecret(CURRENT_SECRET)).toEqual(expectedKey);
  expect(explicit.decodeSecret(CURRENT_SECRET)).toEqual(expectedKey);
  expect(descriptor.decodeSecret(CURRENT_SECRET)).not.toEqual(utf8(CURRENT_SECRET));
});

test('current mode keeps strict canonical Base64 and 24..64 decoded-byte bounds', () => {
  const descriptor = createPolarDescriptor();
  const withoutPrefix = base64Of(new Uint8Array(24).fill(0x11));

  expect(descriptor.decodeSecret(`whsec_${withoutPrefix}`)).toEqual(descriptor.decodeSecret(withoutPrefix));

  for (const size of [24, 64]) {
    const secret = base64Of(new Uint8Array(size).fill(0x11));

    expect(descriptor.decodeSecret(secret).byteLength).toBe(size);
  }

  const invalidSecrets = [
    '',
    'whsec_',
    'not base64!',
    ` ${withoutPrefix}`,
    `${withoutPrefix}=`,
    base64Of(new Uint8Array(23)),
    base64Of(new Uint8Array(65)),
  ];

  for (const secret of invalidSecrets) {
    expect(ternErrorCode(() => descriptor.decodeSecret(secret))).toBe('invalid-secret');
  }
});

test('legacy mode uses the complete literal UTF-8 secret with no bounds or prefix policy', () => {
  const descriptor = createPolarDescriptor({ secretMode: 'legacy' });
  const currentKey = decodeBase64(CURRENT_SECRET.slice('whsec_'.length));

  if (currentKey === null) throw new Error('The synthetic current secret must decode.');

  expect(descriptor.decodeSecret(CURRENT_SECRET)).toEqual(utf8(CURRENT_SECRET));
  expect(descriptor.decodeSecret(CURRENT_SECRET)).not.toEqual(currentKey);
  expect(descriptor.decodeSecret('plain-legacy-secret')).toEqual(utf8('plain-legacy-secret'));
  expect(descriptor.decodeSecret('whsec_')).toEqual(utf8('whsec_'));
  expect(descriptor.decodeSecret('A')).toEqual(utf8('A'));
  expect(descriptor.decodeSecret('A'.repeat(300))).toEqual(utf8('A'.repeat(300)));
  expect(descriptor.decodeSecret('  padded literal secret  ')).toEqual(utf8('  padded literal secret  '));
  expect(ternErrorCode(() => descriptor.decodeSecret(''))).toBe('invalid-secret');
});

test('the same whsec_ string produces different keys and is not interchangeable by mode', () => {
  const current = createPolarDescriptor({ secretMode: 'current' });
  const legacy = createPolarDescriptor({ secretMode: 'legacy' });
  const currentKey = current.decodeSecret(CURRENT_SECRET);
  const legacyKey = legacy.decodeSecret(CURRENT_SECRET);

  expect(currentKey).not.toEqual(legacyKey);

  const currentParsed = expectOk(
    current.parse(headerMap(polarHeaders(token(sign(currentKey)))), BODY),
  );

  const legacyParsed = expectOk(
    legacy.parse(headerMap(polarHeaders(token(sign(legacyKey)))), BODY),
  );

  expect(macMatches(currentKey, currentParsed.signedContent, currentParsed.signatures)).toBe(true);
  expect(macMatches(legacyKey, legacyParsed.signedContent, legacyParsed.signatures)).toBe(true);
  expect(macMatches(currentKey, legacyParsed.signedContent, legacyParsed.signatures)).toBe(false);
  expect(macMatches(legacyKey, currentParsed.signedContent, currentParsed.signatures)).toBe(false);
});

test('accepts both rotation orders in current mode', () => {
  const descriptor = createPolarDescriptor();
  const keyA = descriptor.decodeSecret(CURRENT_SECRET);
  const keyB = descriptor.decodeSecret(CURRENT_SECRET_ALT);
  const signatureA = token(sign(keyA));
  const signatureB = token(sign(keyB));

  const orders: readonly (readonly [string, string])[] = [
    [signatureA, signatureB],
    [signatureB, signatureA],
  ];

  for (const [first, second] of orders) {
    const parsed = expectOk(
      descriptor.parse(headerMap(polarHeaders(`${first} ${second}`)), BODY),
    );

    expect(parsed.signatures).toHaveLength(2);
    expect(macMatches(keyA, parsed.signedContent, parsed.signatures)).toBe(true);
    expect(macMatches(keyB, parsed.signedContent, parsed.signatures)).toBe(true);
  }
});

test('accepts both rotation orders in legacy mode', () => {
  const descriptor = createPolarDescriptor({ secretMode: 'legacy' });
  const keyA = descriptor.decodeSecret(LEGACY_SECRET_A);
  const keyB = descriptor.decodeSecret(LEGACY_SECRET_B);
  const signatureA = token(sign(keyA));
  const signatureB = token(sign(keyB));

  const orders: readonly (readonly [string, string])[] = [
    [signatureA, signatureB],
    [signatureB, signatureA],
  ];

  for (const [first, second] of orders) {
    const parsed = expectOk(
      descriptor.parse(headerMap(polarHeaders(`${first} ${second}`)), BODY),
    );

    expect(parsed.signatures).toHaveLength(2);
    expect(macMatches(keyA, parsed.signedContent, parsed.signatures)).toBe(true);
    expect(macMatches(keyB, parsed.signedContent, parsed.signatures)).toBe(true);
  }
});

test('inherits canonical failure reasons, token rules and metadata ordering', () => {
  const descriptor = createPolarDescriptor();
  const signature = sign(descriptor.decodeSecret(CURRENT_SECRET));
  const valid = token(signature);

  for (const signature of ['', '   ']) {
    expect(expectFailure(descriptor.parse(headerMap(polarHeaders(signature)), BODY)).reason)
      .toBe('missing-signature');
  }

  for (const signature of ['v1', 'v1,', ',abc', 'v1,@@@', 'v1,AAAA']) {
    expect(expectFailure(descriptor.parse(headerMap(polarHeaders(signature)), BODY)).reason)
      .toBe('malformed-signature');
  }

  expect(expectFailure(descriptor.parse(headerMap(polarHeaders(`v1,@@@ ${valid}`)), BODY)).reason)
    .toBe('malformed-signature');
  expect(expectFailure(descriptor.parse(headerMap(polarHeaders(`v2,${signature}`)), BODY)).reason)
    .toBe('unsupported-scheme');

  const mixed = expectOk(
    descriptor.parse(headerMap(polarHeaders(`v2,${signature} ${valid}`)), BODY),
  );

  expect(mixed.signatures).toHaveLength(1);

  expect(expectFailure(descriptor.parse(headerMap({}), BODY)).reason).toBe('missing-signature');
  expect(expectFailure(descriptor.parse(headerMap(polarHeaders(valid, null)), BODY)).reason)
    .toBe('missing-identity');
  expect(expectFailure(descriptor.parse(headerMap(polarHeaders(valid, '')), BODY)).reason)
    .toBe('missing-identity');
  expect(expectFailure(descriptor.parse(headerMap(polarHeaders(valid, 'has.dot')), BODY)).reason)
    .toBe('malformed-signature');
  expect(expectFailure(descriptor.parse(headerMap(polarHeaders(valid, 'a,b')), BODY)).reason)
    .toBe('malformed-signature');
  expect(expectFailure(descriptor.parse(headerMap(polarHeaders(valid, EVENT_ID, null)), BODY)).reason)
    .toBe('missing-timestamp');
  expect(expectFailure(descriptor.parse(headerMap(polarHeaders(valid, EVENT_ID, '')), BODY)).reason)
    .toBe('missing-timestamp');

  const combined = headerMap({
    ...polarHeaders(valid),
    'webhook-signature': [valid, valid],
  });

  expect(expectFailure(descriptor.parse(combined, BODY)).reason).toBe('malformed-signature');
});

test('accepts only canonical nonnegative safe-integer timestamps', () => {
  const descriptor = createPolarDescriptor();
  const key = descriptor.decodeSecret(CURRENT_SECRET);

  for (const timestamp of ['0', String(Number.MAX_SAFE_INTEGER)]) {
    const signature = token(sign(key, EVENT_ID, timestamp));

    const parsed = expectOk(
      descriptor.parse(headerMap(polarHeaders(signature, EVENT_ID, timestamp)), BODY),
    );

    expect(parsed.identity.timestamp).toBe(Number(timestamp));
    expect(parsed.signedContent).toEqual(contentFor(EVENT_ID, timestamp, BODY));
    expect(macMatches(key, parsed.signedContent, parsed.signatures)).toBe(true);
  }

  const signature = token(sign(key));

  const invalidTimestamps = [
    '00',
    '01',
    '-1',
    '+1',
    '1.5',
    '1, 2',
    ' 1',
    '1 ',
    '9007199254740992',
    '99999999999999999999',
  ];

  for (const timestamp of invalidTimestamps) {
    expect(
      expectFailure(
        descriptor.parse(headerMap(polarHeaders(signature, EVENT_ID, timestamp)), BODY),
      ).reason,
    ).toBe('malformed-signature');
  }
});

test('never accepts svix-* aliases for canonical Polar fields', () => {
  const descriptor = createPolarDescriptor();
  const signature = token(sign(descriptor.decodeSecret(CURRENT_SECRET)));

  expect(
    expectFailure(
      descriptor.parse(
        headerMap({
          'svix-id': EVENT_ID,
          'svix-timestamp': TIMESTAMP,
          'svix-signature': signature,
        }),
        BODY,
      ),
    ).reason,
  ).toBe('missing-signature');

  expect(
    expectFailure(
      descriptor.parse(
        headerMap({
          'svix-id': EVENT_ID,
          'svix-timestamp': TIMESTAMP,
          'webhook-signature': signature,
        }),
        BODY,
      ),
    ).reason,
  ).toBe('missing-identity');

  expect(
    expectFailure(
      descriptor.parse(
        headerMap({
          'webhook-id': EVENT_ID,
          'webhook-timestamp': TIMESTAMP,
          'svix-signature': signature,
        }),
        BODY,
      ),
    ).reason,
  ).toBe('missing-signature');

  const accepted = expectOk(
    descriptor.parse(
      headerMap({
        ...polarHeaders(signature),
        'svix-id': 'ignored-svix-id',
        'svix-timestamp': '0',
        'svix-signature': 'v1,@@@',
      }),
      BODY,
    ),
  );

  expect(accepted.identity.eventId).toBe(EVENT_ID);
  expect(accepted.signatures).toHaveLength(1);

  expect(
    expectFailure(
      descriptor.parse(
        headerMap({
          ...polarHeaders('v1,@@@'),
          'svix-signature': signature,
        }),
        BODY,
      ),
    ).reason,
  ).toBe('malformed-signature');
});

test('authenticates the event id but leaves delivery metadata unsigned', () => {
  const descriptor = createPolarDescriptor();
  const key = descriptor.decodeSecret(CURRENT_SECRET);
  const signature = token(sign(key));

  const parsed = expectOk(
    descriptor.parse(
      headerMap({
        ...polarHeaders(signature),
        'webhook-delivery-id': 'synthetic-delivery-id',
        'x-polar-delivery-id': 'synthetic-polar-delivery',
        'webhook-event-id': 'synthetic-unsigned-event',
        'x-polar-event-id': 'synthetic-unsigned-polar-event',
      }),
      BODY,
    ),
  );

  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: EVENT_ID,
    timestamp: Number(TIMESTAMP),
    authenticatedFields: ['eventId', 'timestamp'],
  });
  expect(parsed.signedContent).toEqual(contentFor(EVENT_ID, TIMESTAMP, BODY));
  expect(macMatches(key, parsed.signedContent, parsed.signatures)).toBe(true);

  const changedId = 'msg_phase7_polar_synthetic_changed';

  const changed = expectOk(
    descriptor.parse(
      headerMap({
        ...polarHeaders(signature, changedId),
        'webhook-delivery-id': 'synthetic-delivery-id',
      }),
      BODY,
    ),
  );

  expect(changed.identity.eventId).toBe(changedId);
  expect(changed.signedContent).toEqual(contentFor(changedId, TIMESTAMP, BODY));
  expect(macMatches(key, changed.signedContent, changed.signatures)).toBe(false);
});

test('signs exact raw body bytes including empty, NUL, invalid UTF-8, non-JSON and views', () => {
  const descriptor = createPolarDescriptor();
  const key = descriptor.decodeSecret(CURRENT_SECRET);
  const backing = new Uint8Array([0xaa, 0x31, 0xff, 0xfe, 0x00, 0x80, 0xbb, 0xcc]);
  const view = backing.subarray(2, 7);

  const bodies: readonly Uint8Array[] = [
    new Uint8Array(),
    utf8('plain text, not JSON'),
    new Uint8Array([0xff, 0xfe, 0x80, 0x00, 0xc3]),
    new Uint8Array([0x00, 0x01, 0x00, 0xff]),
    view,
  ];

  for (const body of bodies) {
    const parsed = expectOk(
      descriptor.parse(headerMap(polarHeaders(token(sign(key, EVENT_ID, TIMESTAMP, body)))), body),
    );

    expect(parsed.signedContent).toEqual(contentFor(EVENT_ID, TIMESTAMP, body));
    expect(macMatches(key, parsed.signedContent, parsed.signatures)).toBe(true);
  }

  const parsedView = expectOk(
    descriptor.parse(headerMap(polarHeaders(token(sign(key, EVENT_ID, TIMESTAMP, view)))), view),
  );

  expect(parsedView.signedContent).toEqual(contentFor(EVENT_ID, TIMESTAMP, view));
  expect(parsedView.signedContent).not.toEqual(contentFor(EVENT_ID, TIMESTAMP, backing));
  expect(parsedView.signedContent.byteLength).toBe(
    contentFor(EVENT_ID, TIMESTAMP, view).byteLength,
  );
});

test('snapshots the selected mode and ignores inherited-only configuration', () => {
  let reads = 0;

  const getterOptions: PolarDescriptorOptions = {
    get secretMode(): 'current' | 'legacy' {
      reads += 1;

      return reads === 1 ? 'legacy' : 'current';
    },
  };

  const getterDescriptor = createPolarDescriptor(getterOptions);

  expect(reads).toBe(1);
  expect(getterDescriptor.decodeSecret(LEGACY_SECRET_A)).toEqual(utf8(LEGACY_SECRET_A));

  const mutable: MutablePolarOptions = { secretMode: 'legacy' };
  const mutableDescriptor = createPolarDescriptor(mutable);

  mutable.secretMode = 'current';
  expect(mutableDescriptor.decodeSecret(LEGACY_SECRET_A)).toEqual(utf8(LEGACY_SECRET_A));

  // SAFETY: The inherited property deliberately bypasses the own-field contract.
  const inherited = Object.create({ secretMode: 'legacy' }) as PolarDescriptorOptions;
  const defaultKey = createPolarDescriptor().decodeSecret(CURRENT_SECRET);

  expect(createPolarDescriptor(inherited).decodeSecret(CURRENT_SECRET)).toEqual(defaultKey);
  expect(createPolarDescriptor({}).decodeSecret(CURRENT_SECRET)).toEqual(defaultKey);
  expect(createPolarDescriptor(undefined).decodeSecret(CURRENT_SECRET)).toEqual(defaultKey);
});

test('rejects invalid configuration generically without echoing values', () => {
  // SAFETY: Deliberately invalid runtime values exercise validation beyond the typed optional argument.
  const invalidConfigs: readonly PolarDescriptorOptions[] = [
    null as never,
    [] as never,
    'legacy' as never,
    1 as never,
    (() => 'legacy') as never,
    { secretMode: undefined } as never,
    { secretMode: 'auto' } as never,
    { secretMode: null } as never,
    { secretMode: 'legacy', unexpected: CANARY } as never,
    { [CANARY]: CANARY } as never,
  ];

  for (const config of invalidConfigs) {
    const error = polarError(config);

    expect(error.code).toBe('invalid-options');
    expect(error.message).toBe('Invalid Polar provider options.');
    expect(error.message).not.toContain(CANARY);
  }

  const hostileGetter: PolarDescriptorOptions = {
    get secretMode(): 'legacy' {
      throw new Error(CANARY);
    },
  };

  const hostileOwnKeys = new Proxy<PolarDescriptorOptions>(
    { secretMode: 'legacy' },
    {
      ownKeys() {
        throw new Error(CANARY);
      },
    },
  );

  const hostileGet = new Proxy<PolarDescriptorOptions>(
    { secretMode: 'legacy' },
    {
      get() {
        throw new Error(CANARY);
      },
    },
  );

  const hostileDescriptor = new Proxy<PolarDescriptorOptions>(
    { secretMode: 'legacy' },
    {
      getOwnPropertyDescriptor() {
        throw new Error(CANARY);
      },
    },
  );

  const revocable = Proxy.revocable<PolarDescriptorOptions>({ secretMode: 'legacy' }, {});

  revocable.revoke();

  for (const config of [
    hostileGetter,
    hostileOwnKeys,
    hostileGet,
    hostileDescriptor,
    revocable.proxy,
  ]) {
    const error = polarError(config);

    expect(error.code).toBe('invalid-options');
    expect(error.message).toBe('Invalid Polar provider options.');
    expect(String(error)).not.toContain(CANARY);
    expect(error.stack ?? '').not.toContain(CANARY);
    expect(JSON.stringify(error)).not.toContain(CANARY);
    expect(error).not.toHaveProperty('cause');
  }
});
