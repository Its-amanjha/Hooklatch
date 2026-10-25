import { createHash, createHmac, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { HooklatchError } from 'hooklatch';
import { createVerifier, verify } from '../../src/index.js';
import type { WebhookRequest } from '../../src/index.js';
import {
  falOptionsFromEnv,
  createGrafanaTimestampedVerifier,
  createGrafanaCustomHeaderVerifier,
  createPolarCurrentVerifier,
  createPolarLegacyVerifier,
} from '../../examples/phase10/credential-recipes.js';

const NOW = 1_700_000_100;
const BODY = new TextEncoder().encode('{"example":"phase10"}');

function makeFalKey(seedByte: number): Uint8Array {
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = createPrivateKey({ key: Buffer.concat([prefix, seed]), format: 'der', type: 'pkcs8' });
  const jwk = createPublicKey(privateKey).export({ format: 'jwk' });

  if (jwk.x === undefined) throw new Error('missing x');

  return new Uint8Array(Buffer.from(jwk.x, 'base64url'));
}

const FAL_KEY = makeFalKey(7);
const FAL_USER = 'phase10-fal-user';
const FAL_REQUEST = 'phase10-fal-request';

function signFal(privateKeySeedByte: number, body: Uint8Array, userId = FAL_USER): string {
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const seed = Buffer.alloc(32, privateKeySeedByte);
  const privateKey = createPrivateKey({ key: Buffer.concat([prefix, seed]), format: 'der', type: 'pkcs8' });
  const hash = createHash('sha256').update(Buffer.from(body)).digest('hex');
  const signedContent = `${FAL_REQUEST}\n${userId}\n${NOW}\n${hash}`;

  return sign(null, Buffer.from(signedContent, 'utf8'), privateKey).toString('hex');
}

function base64UrlKey(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url').replace(/=+$/, '');
}

function expectInvalid(run: () => void): HooklatchError {
  let thrown: unknown;

  try {
    run();
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(HooklatchError);

  if (!(thrown instanceof HooklatchError)) throw new Error('expected HooklatchError');
  expect(thrown.code).toBe('invalid-options');

  return thrown;
}

describe('phase10 fal credential recipe', () => {
  test('builds working options from a valid environment value', async () => {
    const value = base64UrlKey(FAL_KEY);
    const options = falOptionsFromEnv(value, FAL_USER);

    expect(options.publicKeys).toHaveLength(1);
    expect(options.publicKeys[0]).toEqual(FAL_KEY);

    const verifier = createVerifier({ ...options, now: () => NOW });
    const signature = signFal(7, BODY);

    const result = await verifier({
      rawBody: BODY,
      headers: {
        'x-fal-webhook-signature': signature,
        'x-fal-webhook-request-id': FAL_REQUEST,
        'x-fal-webhook-user-id': FAL_USER,
        'x-fal-webhook-timestamp': String(NOW),
      },
    });

    expect(result.ok).toBe(true);
  });

  test('rejects a valid signature for the wrong account', async () => {
    const value = base64UrlKey(FAL_KEY);
    const options = falOptionsFromEnv(value, 'different-user');

    const verifier = createVerifier({ ...options, now: () => NOW });
    const signature = signFal(7, BODY);

    const result = await verifier({
      rawBody: BODY,
      headers: {
        'x-fal-webhook-signature': signature,
        'x-fal-webhook-request-id': FAL_REQUEST,
        'x-fal-webhook-user-id': FAL_USER,
        'x-fal-webhook-timestamp': String(NOW),
      },
    });

    expect(result.ok).toBe(false);
  });

  test('rejects a tampered body', async () => {
    const value = base64UrlKey(FAL_KEY);
    const options = falOptionsFromEnv(value, FAL_USER);

    const verifier = createVerifier({ ...options, now: () => NOW });
    const signature = signFal(7, BODY);
    const tampered = new TextEncoder().encode('{"example":"tampered"}');

    const result = await verifier({
      rawBody: tampered,
      headers: {
        'x-fal-webhook-signature': signature,
        'x-fal-webhook-request-id': FAL_REQUEST,
        'x-fal-webhook-user-id': FAL_USER,
        'x-fal-webhook-timestamp': String(NOW),
      },
    });

    expect(result.ok).toBe(false);
  });

  test('rejects noncanonical unused Base64 bits', () => {
    const value = base64UrlKey(FAL_KEY);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const invalid = value.slice(0, -1) + alphabet[alphabet.indexOf(value.slice(-1)) + 1];

    expectInvalid(() => falOptionsFromEnv(invalid, FAL_USER));
  });

  test('rejects seventeen keys', () => {
    const value = Array.from({ length: 17 }, () => base64UrlKey(FAL_KEY)).join(',');

    expectInvalid(() => falOptionsFromEnv(value, FAL_USER));
  });

  test('rejects malformed environment entries', () => {
    expectInvalid(() => falOptionsFromEnv('not-base64!', FAL_USER));
    expectInvalid(() => falOptionsFromEnv(base64UrlKey(FAL_KEY) + '=', FAL_USER));
    expectInvalid(() => falOptionsFromEnv(` ${base64UrlKey(FAL_KEY)}`, FAL_USER));
    expectInvalid(() => falOptionsFromEnv(base64UrlKey(FAL_KEY).slice(0, 42), FAL_USER));
  });

  test('rejects invalid configuration without echoing markers', () => {
    const marker = 'phase10-fal-canary-9f2a';

    const missingValueError = expectInvalid(() => falOptionsFromEnv(undefined, FAL_USER));
    expect(missingValueError.message).not.toContain(marker);

    const badUserError = expectInvalid(() => falOptionsFromEnv(base64UrlKey(FAL_KEY), `${marker} bad`));
    expect(badUserError.message).not.toContain(marker);

    const undefinedUserError = expectInvalid(() => falOptionsFromEnv(base64UrlKey(FAL_KEY), undefined));
    expect(undefinedUserError.message).not.toContain(marker);
  });

  test('accepts sixteen keys', () => {
    const value = Array.from({ length: 16 }, () => base64UrlKey(FAL_KEY)).join(',');

    expect(falOptionsFromEnv(value, FAL_USER).publicKeys).toHaveLength(16);
  });
});

describe('phase10 Grafana recipes', () => {
  const SECRET = 'phase10-grafana-secret';
  const TIMESTAMP = String(NOW);
  const TIMESTAMP_HEADER = 'x-grafana-timestamp';
  const CUSTOM_SIGNATURE_HEADER = 'x-custom-grafana-signature';
  const CUSTOM_TIMESTAMP_HEADER = 'x-custom-grafana-timestamp';

  function hmacHex(value: string): string {
    return createHmac('sha256', Buffer.from(SECRET, 'utf8')).update(Buffer.from(value, 'utf8')).digest('hex');
  }

  test('verifies a timestamped recipe through the public API', async () => {
    const verifier = createGrafanaTimestampedVerifier({
      secret: SECRET,
      timestampHeader: TIMESTAMP_HEADER,
      now: () => NOW,
    });

    const mac = hmacHex(`${TIMESTAMP}:${new TextDecoder().decode(BODY)}`);

    const result = await verifier({
      rawBody: BODY,
      headers: {
        'x-grafana-alerting-signature': mac,
        [TIMESTAMP_HEADER]: TIMESTAMP,
      },
    });

    expect(result.ok).toBe(true);
  });

  test('verifies a custom-header recipe and ignores the default header', async () => {
    const verifier = createGrafanaCustomHeaderVerifier({
      secret: SECRET,
      signatureHeader: CUSTOM_SIGNATURE_HEADER,
      timestampHeader: CUSTOM_TIMESTAMP_HEADER,
      now: () => NOW,
    });

    const mac = hmacHex(`${TIMESTAMP}:${new TextDecoder().decode(BODY)}`);
    const ignored = hmacHex('ignored');

    const result = await verifier({
      rawBody: BODY,
      headers: {
        [CUSTOM_SIGNATURE_HEADER]: mac,
        [CUSTOM_TIMESTAMP_HEADER]: TIMESTAMP,
        'x-grafana-alerting-signature': ignored,
      },
    });

    expect(result.ok).toBe(true);

    const missing = await verifier({
      rawBody: BODY,
      headers: {
        'x-grafana-alerting-signature': mac,
        [CUSTOM_TIMESTAMP_HEADER]: TIMESTAMP,
      },
    });

    expect(missing.ok).toBe(false);
  });

  test('rejects reserved headers and colliding header names', () => {
    expect(() =>
      createGrafanaTimestampedVerifier({
        secret: SECRET,
        signatureHeader: 'authorization',
        timestampHeader: TIMESTAMP_HEADER,
      }),
    ).toThrow(HooklatchError);

    expect(() =>
      createGrafanaTimestampedVerifier({
        secret: SECRET,
        signatureHeader: 'X-Collision',
        timestampHeader: 'x-collision',
      }),
    ).toThrow(HooklatchError);
  });

  test('rejects a tampered body', async () => {
    const verifier = createGrafanaTimestampedVerifier({
      secret: SECRET,
      timestampHeader: TIMESTAMP_HEADER,
      now: () => NOW,
    });

    const mac = hmacHex(`${TIMESTAMP}:${new TextDecoder().decode(BODY)}`);
    const tampered = new TextEncoder().encode('{"example":"tampered"}');

    const result = await verifier({
      rawBody: tampered,
      headers: {
        'x-grafana-alerting-signature': mac,
        [TIMESTAMP_HEADER]: TIMESTAMP,
      },
    });

    expect(result.ok).toBe(false);
  });
});

describe('phase10 Polar recipes', () => {
  const ID = 'msg_phase10';
  const TIMESTAMP = String(NOW);
  const SECRET_BYTES = Buffer.alloc(32, 9);
  const CURRENT_SECRET = `whsec_${SECRET_BYTES.toString('base64')}`;
  const LEGACY_SECRET = 'phase10-legacy-polar-secret';

  function signCurrent(body: Uint8Array): string {
    const hmac = createHmac('sha256', SECRET_BYTES)
      .update(Buffer.concat([Buffer.from(`${ID}.${TIMESTAMP}.`, 'utf8'), Buffer.from(body)]))
      .digest('base64');

    return `v1,${hmac}`;
  }

  function signLegacy(body: Uint8Array): string {
    const hmac = createHmac('sha256', Buffer.from(LEGACY_SECRET, 'utf8')).update(Buffer.concat([Buffer.from(`${ID}.${TIMESTAMP}.`, 'utf8'), Buffer.from(body)])).digest('base64');

    return `v1,${hmac}`;
  }

  test('current recipe decodes the Base64 secret and verifies', async () => {
    const verifier = createPolarCurrentVerifier({ secrets: [CURRENT_SECRET], now: () => NOW });

    const result = await verifier({
      rawBody: BODY,
      headers: {
        'webhook-id': ID,
        'webhook-timestamp': TIMESTAMP,
        'webhook-signature': signCurrent(BODY),
      },
    });

    expect(result.ok).toBe(true);
  });

  test('legacy recipe uses the complete literal secret and verifies', async () => {
    const verifier = createPolarLegacyVerifier({ secrets: [LEGACY_SECRET], now: () => NOW });

    const result = await verifier({
      rawBody: BODY,
      headers: {
        'webhook-id': ID,
        'webhook-timestamp': TIMESTAMP,
        'webhook-signature': signLegacy(BODY),
      },
    });

    expect(result.ok).toBe(true);
  });

  test('does not rescue a current-era signature with a legacy verifier', async () => {
    const currentVerifier = createPolarCurrentVerifier({ secrets: [CURRENT_SECRET], now: () => NOW });
    const legacyVerifier = createPolarLegacyVerifier({ secrets: [LEGACY_SECRET], now: () => NOW });

    const currentResult = await currentVerifier({
      rawBody: BODY,
      headers: {
        'webhook-id': ID,
        'webhook-timestamp': TIMESTAMP,
        'webhook-signature': signCurrent(BODY),
      },
    });

    expect(currentResult.ok).toBe(true);

    const rescued = await legacyVerifier({
      rawBody: BODY,
      headers: {
        'webhook-id': ID,
        'webhook-timestamp': TIMESTAMP,
        'webhook-signature': signCurrent(BODY),
      },
    });

    expect(rescued.ok).toBe(false);

    const legacyResult = await legacyVerifier({
      rawBody: BODY,
      headers: {
        'webhook-id': ID,
        'webhook-timestamp': TIMESTAMP,
        'webhook-signature': signLegacy(BODY),
      },
    });

    expect(legacyResult.ok).toBe(true);

    const reverseRescue = await currentVerifier({
      rawBody: BODY,
      headers: {
        'webhook-id': ID,
        'webhook-timestamp': TIMESTAMP,
        'webhook-signature': signLegacy(BODY),
      },
    });

    expect(reverseRescue.ok).toBe(false);
  });
});

describe('phase10 recipes are usable through verify', () => {
  test('fal helper composes with verify', async () => {
    const request: WebhookRequest = {
      rawBody: BODY,
      headers: {
        'x-fal-webhook-signature': signFal(7, BODY),
        'x-fal-webhook-request-id': FAL_REQUEST,
        'x-fal-webhook-user-id': FAL_USER,
        'x-fal-webhook-timestamp': String(NOW),
      },
    };

    const options = falOptionsFromEnv(base64UrlKey(FAL_KEY), FAL_USER);
    const result = await verify(request, { ...options, now: () => NOW });

    expect(result.ok).toBe(true);
  });
});
