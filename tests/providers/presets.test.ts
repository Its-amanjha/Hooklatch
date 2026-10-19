import { concatBytes, utf8 } from '../../src/internal/bytes.js';
import { verify } from '../../src/index.js';
import type {
  EventIdentity, HeaderInput, Provider, VerificationResult, VerifyOptions,
} from '../../src/types.js';
import { base64Of, hmacBase64 } from './helpers.js';

// Published Svix/Standard Webhooks reference vector (24 decoded key bytes):
// https://docs.svix.com/receiving/verifying-payloads/how
// https://github.com/standard-webhooks/standard-webhooks/blob/7537d2a2d3d52d8f2e0ecd12527af4a9307fd81b/libraries/javascript/src/webhook.test.ts
// Source license metadata caveat: CONTRIBUTING.md#source-and-history-notes.
const SECRET = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
const KEY = Buffer.from('MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw', 'base64');
const ID = 'msg_p5jXN8AQM9LWM0D4loKWxJek';
const TIMESTAMP = '1614265330';
const NOW = Number(TIMESTAMP);
const BODY = utf8('{"test": 2432232314}');
const VECTOR_SIGNATURE = 'g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=';

const OTHER_KEY = Buffer.alloc(24, 7);
const OTHER_SECRET = `whsec_${OTHER_KEY.toString('base64')}`;

const SIGNATURE = `v1,${VECTOR_SIGNATURE}`;

function branded(
  signature: string = SIGNATURE,
  id: string = ID,
  timestamp: string = TIMESTAMP,
) {
  return { 'svix-id': id, 'svix-timestamp': timestamp, 'svix-signature': signature };
}

function canonical(
  signature: string = SIGNATURE,
  id: string = ID,
  timestamp: string = TIMESTAMP,
) {
  return { 'webhook-id': id, 'webhook-timestamp': timestamp, 'webhook-signature': signature };
}

/** Independent test-only HMAC over the exact signed content. */
function sign(
  id: string,
  timestamp: string,
  body: Uint8Array,
  key: string | Uint8Array = KEY,
): string {
  return `v1,${hmacBase64(key, concatBytes(utf8(`${id}.${timestamp}.`), body))}`;
}

function runVerify(
  provider: Provider,
  headers: HeaderInput,
  body: Uint8Array = BODY,
  overrides: Partial<VerifyOptions> = {},
): Promise<VerificationResult> {
  return verify(
    { rawBody: body, headers },
    { provider, secrets: [SECRET], now: () => NOW, ...overrides },
  );
}

function failureReason(result: VerificationResult): string {
  if (result.ok) throw new Error('Expected verification to fail.');

  return result.reason;
}

function successIdentity(result: VerificationResult): EventIdentity {
  if (!result.ok) throw new Error(`Expected success but got ${result.reason}.`);

  return result.identity;
}

const IDENTITY: EventIdentity = {
  deliveryId: null,
  eventId: ID,
  timestamp: NOW,
  authenticatedFields: ['eventId', 'timestamp'],
};

describe('published Svix vector on the public root', () => {
  test('verifies the published vector under the svix id with both header families', async () => {
    for (const headers of [branded(), canonical()]) {
      const result = await runVerify('svix', headers);
      expect(result.ok).toBe(true);
      expect(successIdentity(result)).toEqual(IDENTITY);
    }
  });

  test('verifies the published vector under the clerk id with branded headers', async () => {
    const result = await runVerify('clerk', branded());
    expect(result.ok).toBe(true);
    expect(successIdentity(result)).toEqual(IDENTITY);
  });

  test('keeps standard-webhooks canonical-only and unchanged', async () => {
    expect((await runVerify('standard-webhooks', canonical())).ok).toBe(true);
    expect(failureReason(await runVerify('standard-webhooks', branded())))
      .toBe('missing-signature');
  });
});

describe('clerk branded-only policy', () => {
  test('ignores canonical headers and does not let them repair branded fields', async () => {
    expect(failureReason(await runVerify('clerk', canonical()))).toBe('missing-signature');

    // Branded signature is present, so the existing signature -> identity -> timestamp
    // ordering reports the missing branded id instead of reading the canonical one.
    expect(
      failureReason(
        await runVerify('clerk', {
          'svix-signature': SIGNATURE,
          'webhook-id': ID,
          'webhook-timestamp': TIMESTAMP,
        }),
      ),
    ).toBe('missing-identity');

    // A complete canonical family cannot rescue a malformed branded signature.
    expect(
      failureReason(
        await runVerify('clerk', {
          ...canonical(),
          'svix-signature': 'v1,@@@',
        }),
      ),
    ).toBe('malformed-signature');
  });
});

describe('svix dual-family policy', () => {
  test('accepts equal complete families using the branded triplet', async () => {
    const result = await runVerify('svix', { ...branded(), ...canonical() });
    expect(result.ok).toBe(true);
    expect(successIdentity(result)).toEqual(IDENTITY);
  });

  test('rejects conflicting ids, timestamps, and signatures as malformed', async () => {
    const conflictingSignature = sign(ID, TIMESTAMP, BODY, OTHER_KEY);

    for (const headers of [
      { ...branded(), ...canonical(undefined, 'msg_other') },
      { ...branded(), ...canonical(undefined, undefined, '1614265331') },
      { ...branded(), ...canonical(conflictingSignature) },
    ]) {
      expect(failureReason(await runVerify('svix', headers))).toBe('malformed-signature');
    }
  });

  test('rejects mixed partial families instead of assembling a triplet', async () => {
    for (const headers of [
      { 'svix-id': ID, 'webhook-timestamp': TIMESTAMP, 'webhook-signature': SIGNATURE },
      { 'webhook-id': ID, 'svix-timestamp': TIMESTAMP, 'svix-signature': SIGNATURE },
      { ...branded(), 'webhook-id': ID },
      { ...canonical(), 'svix-id': ID },
    ]) {
      expect(failureReason(await runVerify('svix', headers))).toBe('malformed-signature');
    }
  });

  test('reports missing-signature when neither family is present', async () => {
    expect(failureReason(await runVerify('svix', {}))).toBe('missing-signature');
  });

  test('preserves signature, identity, timestamp ordering for a single family', async () => {
    expect(failureReason(await runVerify('svix', { 'svix-id': ID }))).toBe('missing-signature');
    expect(failureReason(await runVerify('svix', { 'svix-signature': SIGNATURE })))
      .toBe('missing-identity');
    expect(failureReason(await runVerify('svix', { 'svix-id': ID, 'svix-signature': SIGNATURE })))
      .toBe('missing-timestamp');
    expect(failureReason(await runVerify('svix', { 'webhook-timestamp': TIMESTAMP })))
      .toBe('missing-signature');
  });

  test('never tries the other family after a parse failure', async () => {
    // The canonical family is complete, but both families are present, and the
    // branded signature is malformed. This must fail closed rather than fall back.
    expect(
      failureReason(
        await runVerify('svix', {
          ...canonical(),
          'svix-signature': 'v1,@@@',
        }),
      ),
    ).toBe('malformed-signature');
  });
});

describe('signature grammar, identities, and bytes', () => {
  test('accepts a valid v1 alongside unknown versions and multiple tokens', async () => {
    expect((await runVerify('svix', branded(`v2,AAAA ${SIGNATURE}`))).ok).toBe(true);
    expect((await runVerify('svix', branded(`  v1,${VECTOR_SIGNATURE}   v1,${VECTOR_SIGNATURE}  `))).ok)
      .toBe(true);
  });

  test('rejects unsupported-only schemes and malformed recognized tokens', async () => {
    expect(failureReason(await runVerify('svix', branded('v2,AAAA')))).toBe('unsupported-scheme');
    expect(failureReason(await runVerify('svix', branded(`v1a,${base64Of(new Uint8Array(32))}`))))
      .toBe('unsupported-scheme');
    expect(failureReason(await runVerify('svix', branded(`v1,@@@ ${SIGNATURE}`))))
      .toBe('malformed-signature');
  });

  test('rejects comma-combined duplicate singleton values and strict syntax violations', async () => {
    expect(
      failureReason(
        await runVerify('svix', {
          'svix-id': [ID, ID],
          'svix-timestamp': TIMESTAMP,
          'svix-signature': SIGNATURE,
        }),
      ),
    ).toBe('malformed-signature');

    expect(
      failureReason(
        await runVerify('svix', {
          'svix-id': ID,
          'svix-timestamp': TIMESTAMP,
          'svix-signature': [`v1,${VECTOR_SIGNATURE}`, `v1,${VECTOR_SIGNATURE}`],
        }),
      ),
    ).toBe('malformed-signature');

    expect(failureReason(await runVerify('svix', branded(undefined, 'has.dot'))))
      .toBe('malformed-signature');
    expect(failureReason(await runVerify('svix', branded(undefined, ID, ' 1614265330'))))
      .toBe('malformed-signature');
  });

  test('verifies empty, non-JSON, and non-UTF8 raw bodies byte-exactly', async () => {
    const cases: readonly Uint8Array[] = [
      new Uint8Array(0),
      utf8('not json'),
      new Uint8Array([0x00, 0xff, 0x80, 0x41]),
    ];

    for (const body of cases) {
      const result = await runVerify('svix', branded(sign(ID, TIMESTAMP, body)), body);
      expect(result.ok).toBe(true);

      if (!result.ok) continue;
      expect(result.rawBody).toEqual(body);
    }
  });

  test('rejects tampered bodies and a body-only signature', async () => {
    const tampered = concatBytes(BODY, utf8('x'));
    expect(failureReason(await runVerify('svix', branded(), tampered)))
      .toBe('invalid-signature');

    expect(
      failureReason(await runVerify('svix', branded(`v1,${hmacBase64(KEY, BODY)}`))),
    ).toBe('invalid-signature');
  });

  test('authenticates the message id and timestamp through the signature', async () => {
    expect(failureReason(await runVerify('svix', branded(undefined, `${ID}x`))))
      .toBe('invalid-signature');
    expect(failureReason(await runVerify('svix', branded(undefined, ID, '1614265331'))))
      .toBe('invalid-signature');
  });
});

describe('freshness, rotation, and key handling', () => {
  test('accepts the inclusive 300-second window in both directions', async () => {
    expect((await runVerify('svix', branded(), BODY, { now: () => NOW + 300 })).ok).toBe(true);
    expect((await runVerify('svix', branded(), BODY, { now: () => NOW - 300 })).ok).toBe(true);
  });

  test('rejects timestamps one second outside the window', async () => {
    expect(failureReason(await runVerify('svix', branded(), BODY, { now: () => NOW + 301 })))
      .toBe('timestamp-expired');
    expect(failureReason(await runVerify('svix', branded(), BODY, { now: () => NOW - 301 })))
      .toBe('timestamp-future');
  });

  test('tolerance zero admits only an exactly current timestamp', async () => {
    expect(
      (await runVerify('svix', branded(), BODY, { now: () => NOW, toleranceSeconds: 0 })).ok,
    ).toBe(true);
    expect(
      failureReason(
        await runVerify('svix', branded(), BODY, { now: () => NOW + 1, toleranceSeconds: 0 }),
      ),
    ).toBe('timestamp-expired');
    expect(
      failureReason(
        await runVerify('svix', branded(), BODY, { now: () => NOW - 1, toleranceSeconds: 0 }),
      ),
    ).toBe('timestamp-future');
  });

  test('accepts a matching token from a rotated signature list and multiple secrets', async () => {
    const retired = sign(ID, TIMESTAMP, BODY, OTHER_KEY);
    const list = `${retired} ${SIGNATURE}`;

    expect((await runVerify('svix', branded(list))).ok).toBe(true);
    expect((await runVerify('svix', branded(retired), BODY, { secrets: [SECRET, OTHER_SECRET] })).ok)
      .toBe(true);
    expect(
      failureReason(
        await runVerify('svix', branded(retired), BODY, {
          secrets: [`whsec_${base64Of(new Uint8Array(24).fill(3))}`],
        }),
      ),
    ).toBe('invalid-signature');
  });

  test('decodes the Base64 key after an optional whsec_ prefix', async () => {
    expect((await runVerify('svix', branded(), BODY, { secrets: ['MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'] })).ok)
      .toBe(true);

    const literalKeySignature = sign(ID, TIMESTAMP, BODY, utf8(SECRET));
    expect(failureReason(await runVerify('svix', branded(literalKeySignature))))
      .toBe('invalid-signature');
  });

  test('enforces 24-64 decoded key bytes and rejects malformed secrets', async () => {
    const sixtyFourBytes = new Uint8Array(64).fill(9);
    const sixtyFourSecret = `whsec_${base64Of(sixtyFourBytes)}`;
    expect(
      (
        await runVerify('svix', branded(sign(ID, TIMESTAMP, BODY, sixtyFourBytes)), BODY, {
          secrets: [sixtyFourSecret],
        })
      ).ok,
    ).toBe(true);

    // The Svix manual example decodes to 18 bytes. It is a grammar reference and
    // is rejected by the approved 24-64 byte bounds, not misreported as computed wrong.
    const shortSecrets = [
      'whsec_plJ3nmyCDGBKInavdOK15jsl',
      `whsec_${base64Of(new Uint8Array(23))}`,
      `whsec_${base64Of(new Uint8Array(65))}`,
      'whsec_!!!',
      'whsec_',
      '',
    ];

    for (const secret of shortSecrets) {
      await expect(runVerify('svix', branded(), BODY, { secrets: [secret] }))
        .rejects.toMatchObject({ name: 'HooklatchError', code: 'invalid-secret' });
    }
  });
});
