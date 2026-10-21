import { concatBytes, utf8 } from '../../src/internal/bytes.js';
import { verifyHmac } from '../../src/internal/crypto.js';
import { HooklatchError } from '../../src/errors.js';
import { createGrafanaDescriptor } from '../../src/providers/grafana.js';
import type { GrafanaDescriptorOptions } from '../../src/providers/grafana.js';
import { expectFailure, expectOk, headerMap, hmacHex, ternErrorCode } from './helpers.js';

// Synthetic phase-7 anchors only. Grafana publishes no complete
// body/secret/header/signature vector for either layout, and no live Grafana
// endpoint was contacted. Every secret, body and header below is non-secret
// test material.
//
// Grafana source: http/hmac.go at commit
// 2acbeef29642fc3d89c7f3f0ad2f78e01c6d673e uses the default header
// `X-Grafana-Alerting-Signature`, the `:` separator and HMAC-SHA256 hex.

const SECRET = 'grafana synthetic secret';
const ROTATED_SECRET = 'grafana rotated synthetic secret';
const OUTSIDER_SECRET = 'grafana outsider synthetic secret';
const TIMESTAMP = '1792368000';
const DEFAULT_SIGNATURE_HEADER = 'x-grafana-alerting-signature';
const CUSTOM_SIGNATURE_HEADER = 'x-custom-grafana-signature';
const TIMESTAMP_HEADER = 'x-grafana-timestamp';

const BODY = Buffer.from('{"receiver":"grafana","status":"firing"}', 'utf8');

/** Independent test-only HMAC over the exact bytes Grafana signs. */
const sign = (
  body: Uint8Array,
  timestamp?: string,
  key: string | Uint8Array = SECRET,
): string => hmacHex(
  key,
  timestamp === undefined ? body : concatBytes(utf8(`${timestamp}:`), body),
);

const bodyDescriptor = createGrafanaDescriptor({ mode: 'body' });

const timestampedDescriptor = createGrafanaDescriptor({
  mode: 'timestamped',
  timestampHeader: TIMESTAMP_HEADER,
});

/** Capture the message of a call that must fail with a HooklatchError. */
function errorMessage(run: () => void): string {
  try {
    run();
  } catch (error) {
    if (!(error instanceof HooklatchError)) throw error;

    return error.message;
  }

  throw new Error('Expected the call to fail with a HooklatchError.');
}

test('verifies a body-mode signature over the exact raw body bytes', async () => {
  const parsed = expectOk(bodyDescriptor.parse(
    headerMap({ [DEFAULT_SIGNATURE_HEADER]: sign(BODY) }),
    BODY,
  ));

  expect(parsed.signatures).toHaveLength(1);
  expect(Buffer.from(parsed.signedContent).equals(Buffer.from(BODY))).toBe(true);
  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: null,
    authenticatedFields: [],
  });
  expect(await verifyHmac(
    [bodyDescriptor.decodeSecret(SECRET)],
    parsed.signatures,
    parsed.signedContent,
  )).toBe(true);
});

test('verifies a timestamped signature over the timestamp, colon and exact raw body bytes', async () => {
  const parsed = expectOk(timestampedDescriptor.parse(
    headerMap({
      [DEFAULT_SIGNATURE_HEADER]: sign(BODY, TIMESTAMP),
      [TIMESTAMP_HEADER]: TIMESTAMP,
    }),
    BODY,
  ));

  expect(Buffer.from(parsed.signedContent)
    .equals(concatBytes(utf8(`${TIMESTAMP}:`), BODY))).toBe(true);
  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: Number(TIMESTAMP),
    authenticatedFields: ['timestamp'],
  });
  expect(await verifyHmac(
    [timestampedDescriptor.decodeSecret(SECRET)],
    parsed.signatures,
    parsed.signedContent,
  )).toBe(true);
});

test('signs the received body view instead of a copy of a larger buffer', () => {
  const backing = new Uint8Array(BODY.byteLength + 4);

  backing.set(BODY, 2);
  const view = backing.subarray(2, 2 + BODY.byteLength);

  const parsed = expectOk(bodyDescriptor.parse(
    headerMap({ [DEFAULT_SIGNATURE_HEADER]: sign(view) }),
    view,
  ));

  expect(Buffer.from(parsed.signedContent).equals(Buffer.from(view))).toBe(true);
});

test('preserves empty, binary, non-JSON and unicode bodies exactly', async () => {
  const bodies: readonly Uint8Array[] = [
    new Uint8Array(),
    Buffer.from('not json {', 'utf8'),
    new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28]),
    new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
    new Uint8Array([0x00]),
    Buffer.from('{"unicode":"héllo-秘密"}', 'utf8'),
  ];

  for (const body of bodies) {
    const parsed = expectOk(bodyDescriptor.parse(
      headerMap({ [DEFAULT_SIGNATURE_HEADER]: sign(body) }),
      body,
    ));

    expect(Buffer.from(parsed.signedContent).equals(Buffer.from(body))).toBe(true);
    expect(await verifyHmac(
      [bodyDescriptor.decodeSecret(SECRET)],
      parsed.signatures,
      parsed.signedContent,
    )).toBe(true);
  }
});

test('accepts canonical timestamp seconds including zero', () => {
  for (const timestamp of ['0', '1', TIMESTAMP, String(Number.MAX_SAFE_INTEGER)]) {
    const parsed = expectOk(timestampedDescriptor.parse(
      headerMap({
        [DEFAULT_SIGNATURE_HEADER]: sign(BODY, timestamp),
        [TIMESTAMP_HEADER]: timestamp,
      }),
      BODY,
    ));

    expect(parsed.identity.timestamp).toBe(Number(timestamp));
    expect(Buffer.from(parsed.signedContent)
      .equals(concatBytes(utf8(`${timestamp}:`), BODY))).toBe(true);
  }
});

test('rejects noncanonical timestamp seconds', () => {
  for (const timestamp of [
    '00', '01', '+1', '-1', '1.0', '1e3', ' 1', '1 ', '1,2',
    '9007199254740992', '99999999999999999999',
  ]) {
    expect(expectFailure(timestampedDescriptor.parse(
      headerMap({
        [DEFAULT_SIGNATURE_HEADER]: sign(BODY, timestamp),
        [TIMESTAMP_HEADER]: timestamp,
      }),
      BODY,
    )).reason).toBe('malformed-signature');
  }
});

test('distinguishes a missing signature from a malformed one', () => {
  expect(expectFailure(bodyDescriptor.parse(headerMap({}), BODY)).reason)
    .toBe('missing-signature');
  expect(expectFailure(bodyDescriptor.parse(
    headerMap({ [DEFAULT_SIGNATURE_HEADER]: '' }),
    BODY,
  )).reason).toBe('missing-signature');
  expect(expectFailure(bodyDescriptor.parse(
    headerMap({ [DEFAULT_SIGNATURE_HEADER]: '   ' }),
    BODY,
  )).reason).toBe('missing-signature');
});

test('rejects malformed signature grammar and accepts either hex case', async () => {
  const valid = sign(BODY);

  const malformed = [
    'z'.repeat(64),
    'a'.repeat(63),
    'a'.repeat(65),
    `sha256=${valid}`,
    ` ${valid}`,
    `${valid} `,
    `${valid},${valid}`,
    `${valid} ${valid}`,
  ];

  for (const value of malformed) {
    expect(expectFailure(bodyDescriptor.parse(
      headerMap({ [DEFAULT_SIGNATURE_HEADER]: value }),
      BODY,
    )).reason).toBe('malformed-signature');
  }

  // Repeated header values are joined by the core header boundary.
  expect(expectFailure(bodyDescriptor.parse(
    headerMap({ [DEFAULT_SIGNATURE_HEADER]: [valid, valid] }),
    BODY,
  )).reason).toBe('malformed-signature');

  const uppercase = expectOk(bodyDescriptor.parse(
    headerMap({ [DEFAULT_SIGNATURE_HEADER]: valid.toUpperCase() }),
    BODY,
  ));

  expect(uppercase.signatures[0]).toHaveLength(32);
  expect(await verifyHmac(
    [bodyDescriptor.decodeSecret(SECRET)],
    uppercase.signatures,
    uppercase.signedContent,
  )).toBe(true);
});

test('reports a missing timestamp without falling back to the body layout', () => {
  const bodyMac = sign(BODY);

  expect(expectFailure(timestampedDescriptor.parse(
    headerMap({ [DEFAULT_SIGNATURE_HEADER]: bodyMac }),
    BODY,
  )).reason).toBe('missing-timestamp');
  expect(expectFailure(timestampedDescriptor.parse(
    headerMap({ [DEFAULT_SIGNATURE_HEADER]: bodyMac, [TIMESTAMP_HEADER]: '  ' }),
    BODY,
  )).reason).toBe('missing-timestamp');
});

test('never rescues a configured header from the default Grafana header', () => {
  const custom = createGrafanaDescriptor({
    mode: 'body',
    signatureHeader: CUSTOM_SIGNATURE_HEADER,
  });

  const valid = sign(BODY);

  // A valid MAC that only exists in the unselected default header is ignored.
  expect(expectFailure(custom.parse(
    headerMap({ [DEFAULT_SIGNATURE_HEADER]: valid }),
    BODY,
  )).reason).toBe('missing-signature');

  // An invalid configured header is not repaired by the default header either.
  expect(expectFailure(custom.parse(
    headerMap({ [CUSTOM_SIGNATURE_HEADER]: 'not-hex', [DEFAULT_SIGNATURE_HEADER]: valid }),
    BODY,
  )).reason).toBe('malformed-signature');
});

test('ignores unsigned metadata and reports null identity in body mode', () => {
  const parsed = expectOk(bodyDescriptor.parse(
    headerMap({
      [DEFAULT_SIGNATURE_HEADER]: sign(BODY),
      authorization: 'Basic dXNlcjpwYXNz',
      'content-type': 'application/json',
      'x-grafana-extra': 'value',
      [TIMESTAMP_HEADER]: 'not-a-timestamp',
    }),
    BODY,
  ));

  expect(parsed.identity).toEqual({
    deliveryId: null,
    eventId: null,
    timestamp: null,
    authenticatedFields: [],
  });
});

test('keeps the configured header name out of the signed bytes', async () => {
  const custom = createGrafanaDescriptor({
    mode: 'body',
    signatureHeader: CUSTOM_SIGNATURE_HEADER,
  });

  const value = sign(BODY);

  const fromDefault = expectOk(bodyDescriptor.parse(
    headerMap({ [DEFAULT_SIGNATURE_HEADER]: value }),
    BODY,
  ));

  const fromCustom = expectOk(custom.parse(
    headerMap({ [CUSTOM_SIGNATURE_HEADER]: value }),
    BODY,
  ));

  expect(Buffer.from(fromDefault.signedContent)
    .equals(Buffer.from(fromCustom.signedContent))).toBe(true);
  expect(await verifyHmac(
    [custom.decodeSecret(SECRET)],
    fromCustom.signatures,
    fromCustom.signedContent,
  )).toBe(true);
});

test('signs distinct bytes for the body and timestamped layouts of the same body', async () => {
  const bodyParsed = expectOk(bodyDescriptor.parse(
    headerMap({ [DEFAULT_SIGNATURE_HEADER]: sign(BODY) }),
    BODY,
  ));

  const timestampedParsed = expectOk(timestampedDescriptor.parse(
    headerMap({
      [DEFAULT_SIGNATURE_HEADER]: sign(BODY, TIMESTAMP),
      [TIMESTAMP_HEADER]: TIMESTAMP,
    }),
    BODY,
  ));

  expect(Buffer.from(bodyParsed.signedContent).equals(Buffer.from(BODY))).toBe(true);
  expect(Buffer.from(timestampedParsed.signedContent)
    .equals(concatBytes(utf8(`${TIMESTAMP}:`), BODY))).toBe(true);
  expect(Buffer.from(bodyParsed.signedContent)
    .equals(Buffer.from(timestampedParsed.signedContent))).toBe(false);
  expect(await verifyHmac(
    [bodyDescriptor.decodeSecret(SECRET)],
    bodyParsed.signatures,
    timestampedParsed.signedContent,
  )).toBe(false);
});

test('accepts a rotation accept set across the configured secrets', async () => {
  for (const secret of [SECRET, ROTATED_SECRET]) {
    const parsed = expectOk(bodyDescriptor.parse(
      headerMap({ [DEFAULT_SIGNATURE_HEADER]: sign(BODY, undefined, secret) }),
      BODY,
    ));

    expect(await verifyHmac(
      [bodyDescriptor.decodeSecret(SECRET), bodyDescriptor.decodeSecret(ROTATED_SECRET)],
      parsed.signatures,
      parsed.signedContent,
    )).toBe(true);
    expect(await verifyHmac(
      [bodyDescriptor.decodeSecret(OUTSIDER_SECRET)],
      parsed.signatures,
      parsed.signedContent,
    )).toBe(false);
  }
});

test('uses literal untrimmed secret bytes', () => {
  const literal = '  secret with spaces  ';
  const unicode = '秘密🔐';

  expect(Buffer.from(bodyDescriptor.decodeSecret(literal))
    .equals(Buffer.from(literal, 'utf8'))).toBe(true);
  expect(Buffer.from(bodyDescriptor.decodeSecret(unicode))
    .equals(Buffer.from(unicode, 'utf8'))).toBe(true);
  expect(ternErrorCode(() => bodyDescriptor.decodeSecret(''))).toBe('invalid-secret');
});

test('snapshots the configuration at construction time', () => {
  const options = { mode: 'body' as const, signatureHeader: CUSTOM_SIGNATURE_HEADER };
  const descriptor = createGrafanaDescriptor(options);

  options.signatureHeader = 'x-mutated-signature';

  const parsed = expectOk(descriptor.parse(
    headerMap({ [CUSTOM_SIGNATURE_HEADER]: sign(BODY) }),
    BODY,
  ));

  expect(Buffer.from(parsed.signedContent).equals(Buffer.from(BODY))).toBe(true);
  expect(expectFailure(descriptor.parse(
    headerMap({ 'x-mutated-signature': sign(BODY) }),
    BODY,
  )).reason).toBe('missing-signature');
});

test('rejects invalid configuration with one generic invalid-options error', () => {
  // SAFETY: Deliberately invalid configuration crosses the static API boundary
  // to assert its runtime rejection.
  const invalidConfigurations: readonly (readonly [string, () => ReturnType<typeof createGrafanaDescriptor>])[] = [
    ['undefined options', () => createGrafanaDescriptor(undefined as never)],
    ['a null configuration', () => createGrafanaDescriptor(null as never)],
    ['an array configuration', () => createGrafanaDescriptor([] as never)],
    ['a missing mode', () => createGrafanaDescriptor({ signatureHeader: CUSTOM_SIGNATURE_HEADER } as never)],
    ['an inherited mode', () => createGrafanaDescriptor(Object.create({ mode: 'body' }) as never)],
    ['an unknown mode', () => createGrafanaDescriptor({ mode: 'signed' } as never)],
    ['a non-string mode', () => createGrafanaDescriptor({ mode: 7 } as never)],
    ['an own undefined signature header', () => createGrafanaDescriptor({ mode: 'body', signatureHeader: undefined } as never)],
    ['a body-mode timestamp header', () => createGrafanaDescriptor({ mode: 'body', timestampHeader: TIMESTAMP_HEADER } as never)],
    ['a body-mode undefined timestamp header', () => createGrafanaDescriptor({ mode: 'body', timestampHeader: undefined } as never)],
    ['a missing timestamp header', () => createGrafanaDescriptor({ mode: 'timestamped' } as never)],
    ['an own undefined timestamp header', () => createGrafanaDescriptor({ mode: 'timestamped', timestampHeader: undefined } as never)],
    ['a null signature header', () => createGrafanaDescriptor({ mode: 'body', signatureHeader: null } as never)],
    ['an empty signature header', () => createGrafanaDescriptor({ mode: 'body', signatureHeader: '' } as never)],
    ['a padded signature header', () => createGrafanaDescriptor({ mode: 'body', signatureHeader: ' x-signature' } as never)],
    ['a padded trailing signature header', () => createGrafanaDescriptor({ mode: 'body', signatureHeader: 'x-signature ' } as never)],
    ['a non-token signature header', () => createGrafanaDescriptor({ mode: 'body', signatureHeader: 'x(signature)' } as never)],
    ['an empty timestamp header', () => createGrafanaDescriptor({ mode: 'timestamped', timestampHeader: '' } as never)],
    ['a non-token timestamp header', () => createGrafanaDescriptor({ mode: 'timestamped', timestampHeader: 'x timestamp' } as never)],
    ['a colliding timestamp header', () => createGrafanaDescriptor({
      mode: 'timestamped',
      signatureHeader: 'X-Collision',
      timestampHeader: 'x-collision',
    } as never)],
    ['an unexpected option key', () => createGrafanaDescriptor({ mode: 'body', secretMode: 'current' } as never)],
  ];

  for (const [label, build] of invalidConfigurations) {
    expect([label, ternErrorCode(build)]).toEqual([label, 'invalid-options']);
    expect([label, errorMessage(build)]).toEqual([label, 'Invalid Grafana provider options.']);
  }
});

test('rejects reserved header names in either position', () => {
  const reserved = [
    'host', 'content-length', 'transfer-encoding', 'connection', 'upgrade',
    'trailer', 'te', 'proxy-authorization', 'proxy-authenticate',
    'authorization', 'cookie', 'set-cookie',
  ];

  // SAFETY: Deliberately invalid configuration crosses the static API boundary
  // to assert its runtime rejection.
  const builders: readonly (readonly [string, (name: string) => ReturnType<typeof createGrafanaDescriptor>])[] = [
    ['body', (name) => createGrafanaDescriptor({ mode: 'body', signatureHeader: name } as never)],
    ['timestamped', (name) => createGrafanaDescriptor({ mode: 'timestamped', timestampHeader: name } as never)],
    ['uppercase body', (name) => createGrafanaDescriptor({ mode: 'body', signatureHeader: name.toUpperCase() } as never)],
  ];

  for (const name of reserved) {
    for (const [label, build] of builders) {
      expect([label, name, ternErrorCode(() => build(name))]).toEqual([label, name, 'invalid-options']);
    }
  }
});

test('never echoes a throwing getter or proxy trap', () => {
  const canary = 'grafana-canary-9f3a2b';
  const withGetter: GrafanaDescriptorOptions = { mode: 'body' };

  Object.defineProperty(withGetter, 'signatureHeader', {
    get() { throw new Error(canary); },
    enumerable: true,
    configurable: true,
  });

  const throwingGet = new Proxy({ mode: 'body' }, { get() { throw new Error(canary); } });
  const throwingKeys = new Proxy({ mode: 'body' }, { ownKeys() { throw new Error(canary); } });

  // SAFETY: Deliberately invalid configuration crosses the static API boundary
  // to assert its runtime rejection.
  const builds: readonly (() => ReturnType<typeof createGrafanaDescriptor>)[] = [
    () => createGrafanaDescriptor(withGetter),
    () => createGrafanaDescriptor(throwingGet as never),
    () => createGrafanaDescriptor(throwingKeys as never),
  ];

  for (const build of builds) {
    const message = errorMessage(build);

    expect(message).toBe('Invalid Grafana provider options.');
    expect(message).not.toContain(canary);
  }
});

test('leaves freshness and MAC verification to the core', async () => {
  // The descriptor reports the signed timestamp and applies no recency window
  // of its own; core owns the tolerance comparison.
  const stale = '1';

  const parsed = expectOk(timestampedDescriptor.parse(
    headerMap({
      [DEFAULT_SIGNATURE_HEADER]: sign(BODY, stale),
      [TIMESTAMP_HEADER]: stale,
    }),
    BODY,
  ));

  expect(parsed.identity.timestamp).toBe(1);
  expect(await verifyHmac(
    [timestampedDescriptor.decodeSecret(SECRET)],
    parsed.signatures,
    parsed.signedContent,
  )).toBe(true);

  // A structurally valid but wrong MAC still parses; core rejects it.
  const wrongMac = expectOk(bodyDescriptor.parse(
    headerMap({ [DEFAULT_SIGNATURE_HEADER]: 'a'.repeat(64) }),
    BODY,
  ));

  expect(await verifyHmac(
    [bodyDescriptor.decodeSecret(SECRET)],
    wrongMac.signatures,
    wrongMac.signedContent,
  )).toBe(false);
});
