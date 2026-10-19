import { createHash } from 'node:crypto';
import { createVerifier, verify, verifyRequest } from '../../src/index.js';
import { SUPPORTED_PROVIDERS } from '../../src/providers/index.js';
import type {
  EventIdentity,
  HeaderInput,
  Provider,
  VerificationFailureReason,
  VerificationSuccess,
  VerifyOptions,
} from '../../src/types.js';
import {
  ALL_CASES,
  CASES_PER_PROVIDER,
  SECURITY_PROVIDERS,
  SECURITY_SEED,
  buildCases,
  casesFor,
  corpusFingerprint,
  flipBodyByte,
  flipDigestBit,
  headerValueFor,
  hmacToken,
  literalKeyBytes,
  signatureTokenFor,
  standardWebhooksKeyBytes,
} from './deterministic-cases.js';
import type { DeterministicCase } from './deterministic-cases.js';

/**
 * Adversarial qualification of the nine shipped providers through the public
 * root only. All signatures are generated independently in
 * `deterministic-cases.ts`; production parse/decode helpers are never used to
 * build expected values. Synthetic data only; not an official conformance run.
 */

type VerificationResult = Awaited<ReturnType<typeof verify>>;

/** Providers with the shared 300-second default freshness window. */
const TIMESTAMPED_PROVIDERS = ['stripe', 'standard-webhooks', 'clerk', 'svix'] as const;

/** Providers whose signature covers the raw body only (no timestamp). */
const BODY_ONLY_PROVIDERS = ['github', 'shopify', 'razorpay', 'lemon-squeezy'] as const;
const STANDARD_WEBHOOKS_PROVIDERS = ['standard-webhooks', 'clerk', 'svix'] as const;

/** Original six-provider prefix pinned before the Phase 3 corpus extension. */
const LEGACY_PROVIDERS = [
  'stripe',
  'github',
  'shopify',
  'standard-webhooks',
  'clerk',
  'svix',
] as const;

const LEGACY_CASE_COUNT = LEGACY_PROVIDERS.length * CASES_PER_PROVIDER;
const LEGACY_CORPUS_FINGERPRINT_SHA256 = 'f752a2e69f746f2088d9ea4ba79fa809da4adf05f35ffeb9762bde6eaab117b7';
const LEGACY_FULL_RECORD_SHA256 = 'ce21294c247880d8f3ddf3346dcf4a49f17050d106ef877fbb0926d69c58c403';

function optionsFor(
  case_: DeterministicCase,
  secrets: readonly string[] = case_.secrets,
): VerifyOptions {
  return { provider: case_.provider, secrets: [...secrets], now: () => case_.now };
}

function representative(provider: Provider, index: number): DeterministicCase {
  const found = casesFor(provider)[index];

  if (found === undefined) throw new Error(`Missing corpus case ${provider}/${index}.`);

  return found;
}

function requiredTimestamp(case_: DeterministicCase): number {
  if (case_.timestamp === null) throw new Error(`${case_.context}: expected a timestamped case.`);

  return case_.timestamp;
}

function requiredHeader(case_: DeterministicCase, name: string | null): string {
  if (name === null) throw new Error(`${case_.context}: expected a signed identity header.`);

  return name;
}

function expectSuccess(context: string, result: VerificationResult): VerificationSuccess {
  if (!result.ok) throw new Error(`${context}: expected success, got ${result.reason}.`);

  return result;
}

function expectReason(
  context: string,
  result: VerificationResult,
  reason: VerificationFailureReason,
): void {
  if (result.ok) throw new Error(`${context}: expected ${reason}, but verification succeeded.`);

  if (result.reason !== reason) {
    throw new Error(`${context}: expected ${reason}, got ${result.reason}.`);
  }
}

function expectIdentity(
  context: string,
  result: VerificationSuccess,
  expected: EventIdentity,
): void {
  try {
    expect(result.identity).toEqual(expected);
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'unknown assertion failure';

    throw new Error(`${context}: identity mismatch\n${detail}`);
  }
}

/**
 * Canonical full-case serialization; the legacy prefix hash below was captured
 * with the same field order from the immutable pre-extension corpus.
 */
function stableCaseRecord(entry: DeterministicCase): string {
  return JSON.stringify({
    seed: entry.seed,
    provider: entry.provider,
    index: entry.index,
    body: Buffer.from(entry.body).toString('hex'),
    headers: Object.entries(entry.headers),
    activeSecret: entry.activeSecret,
    retiredSecret: entry.retiredSecret,
    wrongSecret: entry.wrongSecret,
    secrets: entry.secrets,
    rotationSecrets: entry.rotationSecrets,
    now: entry.now,
    timestamp: entry.timestamp,
    authenticatedId: entry.authenticatedId,
    deliveryId: entry.deliveryId,
    eventId: entry.eventId,
    signatureHeader: entry.signatureHeader,
    signatureValue: entry.signatureValue,
    signatureToken: entry.signatureToken,
    retiredToken: entry.retiredToken,
    signatureTimestampText: entry.signatureTimestampText,
    encoding: entry.encoding,
    rotationHeader: entry.rotationHeader,
    idHeader: entry.idHeader,
    timestampHeader: entry.timestampHeader,
    unsignedHeaders: Object.entries(entry.unsignedHeaders),
    expectedIdentity: entry.expectedIdentity,
  });
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function toHeaders(headers: Readonly<Record<string, string>>): Headers {
  const output = new Headers();

  for (const [name, value] of Object.entries(headers)) output.set(name, value);

  return output;
}

function lowerCaseKeys(headers: Readonly<Record<string, string>>): HeaderInput {
  return Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));
}

function withTimestampText(case_: DeterministicCase, timestampText: string): HeaderInput {
  const headers = { ...case_.headers };

  if (case_.timestampHeader !== null) {
    headers[case_.timestampHeader] = timestampText;
  } else {
    headers[case_.signatureHeader] = `t=${timestampText},v1=${case_.signatureToken}`;
  }

  return headers;
}

interface MutableOptions {
  provider: Provider;
  secrets: string[];
  now: () => number;
}

async function expectValidCase(
  case_: DeterministicCase,
  headers: HeaderInput = case_.headers,
): Promise<VerificationSuccess> {
  const success = expectSuccess(
    case_.context,
    await verify({ rawBody: case_.body, headers }, optionsFor(case_)),
  );

  expect(success.provider).toBe(case_.provider);
  expect(success.rawBody).toEqual(case_.body);
  expectIdentity(case_.context, success, case_.expectedIdentity);

  return success;
}

describe(`deterministic adversarial corpus construction (seed=0x${SECURITY_SEED.toString(16)})`, () => {
  test('is reproducible from the explicit seed and covers every provider evenly', () => {
    expect(ALL_CASES).toHaveLength(SECURITY_PROVIDERS.length * CASES_PER_PROVIDER);
    expect(corpusFingerprint(buildCases(SECURITY_SEED))).toBe(corpusFingerprint(ALL_CASES));
    expect(corpusFingerprint(buildCases(SECURITY_SEED + 1))).not.toBe(corpusFingerprint(ALL_CASES));

    for (const provider of SECURITY_PROVIDERS) {
      const providerCases = casesFor(provider);

      expect(providerCases).toHaveLength(CASES_PER_PROVIDER);
      expect(providerCases.every((entry) => entry.provider === provider)).toBe(true);
      expect(new Set(providerCases.map((entry) => entry.activeSecret)).size).toBe(CASES_PER_PROVIDER);
      expect(new Set(providerCases.map((entry) => entry.signatureToken)).size).toBe(CASES_PER_PROVIDER);
      expect(new Set(providerCases.map((entry) => entry.body.byteLength)).size)
        .toBeGreaterThanOrEqual(8);
    }
  });

  test('contains empty, NUL, invalid UTF-8, long and nonzero-offset bodies', () => {
    const bodies = ALL_CASES.map((entry) => entry.body);

    expect(bodies.some((body) => body.byteLength === 0)).toBe(true);
    expect(bodies.some((body) => body.includes(0x00))).toBe(true);
    expect(
      bodies.some((body) => body.includes(0xff) || body.includes(0xfe) || body.includes(0x80)),
    ).toBe(true);
    expect(bodies.some((body) => body.byteLength >= 200)).toBe(true);
    expect(ALL_CASES.filter((entry) => entry.body.byteOffset > 0).length)
      .toBeGreaterThanOrEqual(SECURITY_PROVIDERS.length);
  });

  test('covers the exact shipped nine-provider registry with no unmapped branch', () => {
    expect([...SECURITY_PROVIDERS]).toEqual([...SUPPORTED_PROVIDERS]);
    expect(SECURITY_PROVIDERS).toHaveLength(9);
    expect(ALL_CASES).toHaveLength(SUPPORTED_PROVIDERS.length * CASES_PER_PROVIDER);

    for (const provider of SUPPORTED_PROVIDERS) {
      expect(casesFor(provider)).toHaveLength(CASES_PER_PROVIDER);
    }
  });

  test('keeps the original six-provider corpus as a byte-identical prefix', () => {
    const legacy = ALL_CASES.slice(0, LEGACY_CASE_COUNT);

    for (const [position, provider] of LEGACY_PROVIDERS.entries()) {
      const start = position * CASES_PER_PROVIDER;

      expect(legacy.slice(start, start + CASES_PER_PROVIDER).every((entry) => entry.provider === provider))
        .toBe(true);
    }

    expect(sha256(corpusFingerprint(legacy))).toBe(LEGACY_CORPUS_FINGERPRINT_SHA256);
    expect(sha256(legacy.map(stableCaseRecord).join('\n'))).toBe(LEGACY_FULL_RECORD_SHA256);
  });

  test('keeps binary and nonzero-offset bodies for the added providers', () => {
    for (const provider of ['razorpay', 'paddle', 'lemon-squeezy'] as const) {
      const providerCases = casesFor(provider);

      expect(providerCases.some((entry) => entry.body.byteLength === 0)).toBe(true);
      expect(providerCases.some((entry) => entry.body.includes(0x00))).toBe(true);
      expect(
        providerCases.some((entry) =>
          entry.body.includes(0xff) || entry.body.includes(0xfe) || entry.body.includes(0x80)),
      ).toBe(true);
      expect(providerCases.some((entry) => entry.body.byteOffset > 0)).toBe(true);
      expect(providerCases.some((entry) => entry.body.byteLength >= 200)).toBe(true);
    }
  });

  test('maps the added providers to their documented signing recipes', () => {
    const razorpay = casesFor('razorpay');
    const paddle = casesFor('paddle');
    const lemon = casesFor('lemon-squeezy');

    expect(razorpay.every((entry) => entry.signatureHeader === 'X-Razorpay-Signature')).toBe(true);
    expect(razorpay.every((entry) => entry.encoding === 'hex' && entry.timestamp === null)).toBe(true);
    expect(razorpay.every((entry) => entry.expectedIdentity.authenticatedFields.length === 0)).toBe(true);

    const razorpayEventIds = razorpay.map((entry) => entry.headers['X-Razorpay-Event-Id']);
    const absentEventIds = razorpayEventIds.filter((value) => value === undefined);
    const blankEventIds = razorpayEventIds.filter((value) => value !== undefined && value.trim() === '');
    const nonblankEventIds = razorpay.filter((entry) => entry.expectedIdentity.eventId !== null);

    expect(absentEventIds.length).toBeGreaterThan(0);
    expect(blankEventIds.length).toBeGreaterThan(0);
    expect(nonblankEventIds.length).toBeGreaterThan(0);
    expect(nonblankEventIds.every(
      (entry) => entry.headers['X-Razorpay-Event-Id'] === entry.expectedIdentity.eventId,
    )).toBe(true);

    expect(paddle.every((entry) => entry.signatureHeader === 'Paddle-Signature')).toBe(true);
    expect(paddle.every((entry) => entry.encoding === 'hex' && entry.timestamp !== null)).toBe(true);
    expect(paddle.every((entry) => entry.signatureTimestampText !== null)).toBe(true);
    expect(paddle.every((entry) => entry.rotationHeader !== null)).toBe(true);
    expect(paddle.every((entry) => entry.expectedIdentity.authenticatedFields.length === 1
      && entry.expectedIdentity.authenticatedFields[0] === 'timestamp')).toBe(true);

    expect(lemon.every((entry) => entry.signatureHeader === 'X-Signature')).toBe(true);
    expect(lemon.every((entry) => entry.headers['X-Event-Name'] === 'order_created')).toBe(true);
    expect(lemon.every((entry) => entry.expectedIdentity.deliveryId === null
      && entry.expectedIdentity.eventId === null
      && entry.expectedIdentity.timestamp === null
      && entry.expectedIdentity.authenticatedFields.length === 0)).toBe(true);
  });

  test('keeps literal and Base64-decoded key protocols distinct', async () => {
    const decoded = representative('standard-webhooks', 1);
    const sharedSecret = decoded.activeSecret;
    const timestampText = String(requiredTimestamp(decoded));
    const id = decoded.authenticatedId ?? '';

    const stripeContent = Buffer.concat([
      Buffer.from(`${timestampText}.`, 'utf8'),
      Buffer.from(decoded.body),
    ]);

    const standardContent = Buffer.concat([
      Buffer.from(`${id}.${timestampText}.`, 'utf8'),
      Buffer.from(decoded.body),
    ]);

    const literalToken = hmacToken(literalKeyBytes(sharedSecret), stripeContent, 'hex');

    const decodedToken = hmacToken(
      standardWebhooksKeyBytes(sharedSecret),
      standardContent,
      'base64',
    );

    const stripeHeaders = { 'Stripe-Signature': `t=${timestampText},v1=${literalToken}` };

    const standardHeaders = {
      'Webhook-Id': id,
      'Webhook-Timestamp': timestampText,
      'Webhook-Signature': `v1,${decodedToken}`,
    };

    const stripeOptions: VerifyOptions = {
      provider: 'stripe',
      secrets: [sharedSecret],
      now: () => requiredTimestamp(decoded),
    };

    const standardOptions: VerifyOptions = {
      provider: 'standard-webhooks',
      secrets: [sharedSecret],
      now: () => requiredTimestamp(decoded),
    };

    expect(literalToken).toHaveLength(64);
    expect(Buffer.from(sharedSecret, 'utf8')).not.toEqual(standardWebhooksKeyBytes(sharedSecret));
    expectSuccess(
      `${decoded.context} literal-stripe-key`,
      await verify({ rawBody: decoded.body, headers: stripeHeaders }, stripeOptions),
    );
    expectSuccess(
      `${decoded.context} decoded-standard-key`,
      await verify({ rawBody: decoded.body, headers: standardHeaders }, standardOptions),
    );
    expectReason(
      `${decoded.context} literal-key-cannot-verify-standard`,
      await verify(
        {
          rawBody: decoded.body,
          headers: {
            ...standardHeaders,
            'Webhook-Signature': `v1,${hmacToken(
              literalKeyBytes(sharedSecret),
              standardContent,
              'base64',
            )}`,
          },
        },
        standardOptions,
      ),
      'invalid-signature',
    );
    expectReason(
      `${decoded.context} decoded-key-cannot-verify-stripe`,
      await verify(
        {
          rawBody: decoded.body,
          headers: {
            'Stripe-Signature': `t=${timestampText},v1=${hmacToken(
              standardWebhooksKeyBytes(sharedSecret),
              stripeContent,
              'hex',
            )}`,
          },
        },
        stripeOptions,
      ),
      'invalid-signature',
    );
  });
});

describe.each(SECURITY_PROVIDERS)('%s signed corpus through verify()', (provider) => {
  const cases = casesFor(provider);

  test.each(cases)('$context', async (case_) => {
    await expectValidCase(case_);

    const mutatedBody = flipBodyByte(case_.body, case_.index);

    expect(mutatedBody).not.toEqual(case_.body);
    expectReason(
      `${case_.context} body-bit-flip`,
      await verify({ rawBody: mutatedBody, headers: case_.headers }, optionsFor(case_)),
      'invalid-signature',
    );

    const mutatedToken = flipDigestBit(case_.signatureToken, case_.encoding);

    expect(mutatedToken).not.toBe(case_.signatureToken);
    expectReason(
      `${case_.context} digest-bit-flip`,
      await verify(
        {
          rawBody: case_.body,
          headers: {
            ...case_.headers,
            [case_.signatureHeader]: headerValueFor(
              case_,
              mutatedToken,
              case_.signatureTimestampText,
            ),
          },
        },
        optionsFor(case_),
      ),
      'invalid-signature',
    );

    expectReason(
      `${case_.context} wrong-secret`,
      await verify(
        { rawBody: case_.body, headers: case_.headers },
        optionsFor(case_, [case_.wrongSecret]),
      ),
      'invalid-signature',
    );

    const retiredOnly = {
      ...case_.headers,
      [case_.signatureHeader]: headerValueFor(
        case_,
        case_.retiredToken,
        case_.signatureTimestampText,
      ),
    };

    expectSuccess(
      `${case_.context} rotation-secrets`,
      await verify(
        { rawBody: case_.body, headers: retiredOnly },
        optionsFor(case_, case_.rotationSecrets),
      ),
    );
    expectReason(
      `${case_.context} rotation-removal`,
      await verify(
        { rawBody: case_.body, headers: retiredOnly },
        optionsFor(case_, [case_.activeSecret]),
      ),
      'invalid-signature',
    );

    if (case_.rotationHeader !== null) {
      const rotated = { ...case_.headers, [case_.signatureHeader]: case_.rotationHeader };

      expect(case_.retiredToken).not.toBe(case_.signatureToken);
      expectSuccess(
        `${case_.context} rotation-list`,
        await verify(
          { rawBody: case_.body, headers: rotated },
          optionsFor(case_, case_.rotationSecrets),
        ),
      );
      expectReason(
        `${case_.context} rotation-list-wrong-secret`,
        await verify({ rawBody: case_.body, headers: rotated }, optionsFor(case_, [case_.wrongSecret])),
        'invalid-signature',
      );
    }

    if (case_.index % 4 === 0) {
      const tuples = Object.entries(case_.headers);

      expectSuccess(
        `${case_.context} tuple-headers`,
        await verify({ rawBody: case_.body, headers: tuples }, optionsFor(case_)),
      );
      expectSuccess(
        `${case_.context} Headers`,
        await verify({ rawBody: case_.body, headers: toHeaders(case_.headers) }, optionsFor(case_)),
      );
    }
  });
});

describe.each(TIMESTAMPED_PROVIDERS)('%s freshness boundaries through verify()', (provider) => {
  const case_ = representative(provider, 1);
  const timestamp = requiredTimestamp(case_);

  test(`${case_.context} inclusive-window`, async () => {
    for (const delta of [300, -300]) {
      expectSuccess(
        `${case_.context} now-offset=${delta}`,
        await verify(
          { rawBody: case_.body, headers: case_.headers },
          { ...optionsFor(case_), now: () => timestamp + delta },
        ),
      );
    }

    for (const [delta, reason] of [
      [301, 'timestamp-expired'],
      [-301, 'timestamp-future'],
    ] as const) {
      expectReason(
        `${case_.context} now-offset=${delta}`,
        await verify(
          { rawBody: case_.body, headers: case_.headers },
          { ...optionsFor(case_), now: () => timestamp + delta },
        ),
        reason,
      );
    }
  });

  test(`${case_.context} tolerance-zero`, async () => {
    expectSuccess(
      `${case_.context} tolerance=0`,
      await verify(
        { rawBody: case_.body, headers: case_.headers },
        { ...optionsFor(case_), toleranceSeconds: 0 },
      ),
    );
    expectReason(
      `${case_.context} tolerance=0 now+1`,
      await verify(
        { rawBody: case_.body, headers: case_.headers },
        { ...optionsFor(case_), toleranceSeconds: 0, now: () => timestamp + 1 },
      ),
      'timestamp-expired',
    );
    expectReason(
      `${case_.context} tolerance=0 now-1`,
      await verify(
        { rawBody: case_.body, headers: case_.headers },
        { ...optionsFor(case_), toleranceSeconds: 0, now: () => timestamp - 1 },
      ),
      'timestamp-future',
    );
  });

  test(`${case_.context} mac-before-freshness`, async () => {
    const mutatedBody = flipBodyByte(case_.body, 0);

    for (const delta of [301, -301]) {
      expectReason(
        `${case_.context} bad-mac now-offset=${delta}`,
        await verify(
          { rawBody: mutatedBody, headers: case_.headers },
          { ...optionsFor(case_), now: () => timestamp + delta },
        ),
        'invalid-signature',
      );
    }
  });

  test(`${case_.context} signed-timestamp-tamper`, async () => {
    expectReason(
      `${case_.context} timestamp-tamper`,
      await verify(
        { rawBody: case_.body, headers: withTimestampText(case_, String(timestamp + 1)) },
        optionsFor(case_),
      ),
      'invalid-signature',
    );
  });
});

describe('paddle five-second default freshness through verify()', () => {
  const case_ = representative('paddle', 1);
  const timestamp = requiredTimestamp(case_);

  test(`${case_.context} inclusive-five-second-window`, async () => {
    for (const delta of [5, -5]) {
      expectSuccess(
        `${case_.context} now-offset=${delta}`,
        await verify(
          { rawBody: case_.body, headers: case_.headers },
          { ...optionsFor(case_), now: () => timestamp + delta },
        ),
      );
    }

    for (const [delta, reason] of [
      [6, 'timestamp-expired'],
      [-6, 'timestamp-future'],
    ] as const) {
      expectReason(
        `${case_.context} now-offset=${delta}`,
        await verify(
          { rawBody: case_.body, headers: case_.headers },
          { ...optionsFor(case_), now: () => timestamp + delta },
        ),
        reason,
      );
    }
  });

  test(`${case_.context} explicit-tolerance-zero`, async () => {
    expectSuccess(
      `${case_.context} tolerance=0`,
      await verify(
        { rawBody: case_.body, headers: case_.headers },
        { ...optionsFor(case_), toleranceSeconds: 0 },
      ),
    );
    expectReason(
      `${case_.context} tolerance=0 now+1`,
      await verify(
        { rawBody: case_.body, headers: case_.headers },
        { ...optionsFor(case_), toleranceSeconds: 0, now: () => timestamp + 1 },
      ),
      'timestamp-expired',
    );
    expectReason(
      `${case_.context} tolerance=0 now-1`,
      await verify(
        { rawBody: case_.body, headers: case_.headers },
        { ...optionsFor(case_), toleranceSeconds: 0, now: () => timestamp - 1 },
      ),
      'timestamp-future',
    );
  });

  test(`${case_.context} mac-before-freshness`, async () => {
    const mutatedBody = flipBodyByte(case_.body, 0);

    for (const delta of [6, -6]) {
      expectReason(
        `${case_.context} bad-mac now-offset=${delta}`,
        await verify(
          { rawBody: mutatedBody, headers: case_.headers },
          { ...optionsFor(case_), now: () => timestamp + delta },
        ),
        'invalid-signature',
      );
    }
  });

  test(`${case_.context} repeated-h1-rotation-single-keys`, async () => {
    const activeFirst = `ts=${timestamp};h1=${case_.signatureToken};h1=${case_.retiredToken}`;
    const retiredFirst = `ts=${timestamp};h1=${case_.retiredToken};h1=${case_.signatureToken}`;

    expect(case_.signatureToken).not.toBe(case_.retiredToken);

    for (const value of [activeFirst, retiredFirst]) {
      for (const secret of [case_.activeSecret, case_.retiredSecret]) {
        expectSuccess(
          `${case_.context} rotation-single-key`,
          await verify(
            {
              rawBody: case_.body,
              headers: { ...case_.headers, [case_.signatureHeader]: value },
            },
            optionsFor(case_, [secret]),
          ),
        );
      }
    }
  });

  test(`${case_.context} poisoned-recognized-token`, async () => {
    for (const poisoned of [
      `ts=${timestamp};h1=${case_.signatureToken};h1=zz`,
      `ts=${timestamp};h1=${case_.signatureToken};h1=${'0'.repeat(62)}`,
    ]) {
      expectReason(
        `${case_.context} poisoned-h1`,
        await verify(
          {
            rawBody: case_.body,
            headers: { ...case_.headers, [case_.signatureHeader]: poisoned },
          },
          optionsFor(case_),
        ),
        'malformed-signature',
      );
    }
  });
});

describe.each(STANDARD_WEBHOOKS_PROVIDERS)('%s authenticated identity tampering', (provider) => {
  const case_ = representative(provider, 2);
  const idHeader = requiredHeader(case_, case_.idHeader);
  const timestampHeader = requiredHeader(case_, case_.timestampHeader);

  test(`${case_.context} signed-id-and-timestamp-tamper`, async () => {
    expectReason(
      `${case_.context} id-tamper`,
      await verify(
        {
          rawBody: case_.body,
          headers: { ...case_.headers, [idHeader]: `${case_.authenticatedId ?? ''}_mutated` },
        },
        optionsFor(case_),
      ),
      'invalid-signature',
    );
    expectReason(
      `${case_.context} timestamp-tamper`,
      await verify(
        {
          rawBody: case_.body,
          headers: { ...case_.headers, [timestampHeader]: String(requiredTimestamp(case_) + 1) },
        },
        optionsFor(case_),
      ),
      'invalid-signature',
    );
  });

  test(`${case_.context} authenticated-fields`, async () => {
    const success = await expectValidCase(case_);

    expect(success.identity.authenticatedFields).toEqual(['eventId', 'timestamp']);
    expect(success.identity.eventId).toBe(case_.authenticatedId);
    expect(success.identity.timestamp).toBe(requiredTimestamp(case_));
  });
});

describe.each(BODY_ONLY_PROVIDERS)('%s unsigned metadata isolation', (provider) => {
  const case_ = representative(provider, 2);

  test(`${case_.context} unsigned-timestamp-freshness`, async () => {
    const headers = { ...case_.headers, 'X-Synthetic-Unsigned-Timestamp': '1600000000' };

    const success = expectSuccess(
      `${case_.context} unsigned-timestamp`,
      await verify(
        { rawBody: case_.body, headers },
        { ...optionsFor(case_), toleranceSeconds: 0, now: () => 1_800_000_000 },
      ),
    );

    expect(success.identity.timestamp).toBeNull();
    expect(success.identity.authenticatedFields).toEqual([]);
  });

  test(`${case_.context} unsigned-id-tamper`, async () => {
    const unsignedEntries = Object.entries(case_.unsignedHeaders);

    expect(unsignedEntries.length).toBeGreaterThan(0);

    const headers = { ...case_.headers };
    const marker = `mutated_${provider}`;

    for (const [name] of unsignedEntries) headers[name] = marker;

    const success = expectSuccess(
      `${case_.context} unsigned-id-tamper`,
      await verify({ rawBody: case_.body, headers }, optionsFor(case_)),
    );

    expect(success.identity).toEqual({
      deliveryId: provider === 'github' || provider === 'shopify' ? marker : null,
      eventId: provider === 'shopify' || provider === 'razorpay' ? marker : null,
      timestamp: null,
      authenticatedFields: [],
    });
  });
});

describe('razorpay unsigned event identity', () => {
  test('maps absent and blank event ids to null', async () => {
    for (const index of [0, 1, 2]) {
      const case_ = representative('razorpay', index);
      const success = await expectValidCase(case_);

      expect(success.identity).toEqual({
        deliveryId: null,
        eventId: null,
        timestamp: null,
        authenticatedFields: [],
      });
    }
  });

  test('preserves a nonblank event id without authenticating it', async () => {
    const case_ = representative('razorpay', 3);
    const eventId = case_.headers['X-Razorpay-Event-Id'];

    if (eventId === undefined || eventId.trim() === '') {
      throw new Error(`${case_.context}: expected a nonblank event id.`);
    }

    const success = await expectValidCase(case_);

    expect(success.identity.eventId).toBe(eventId);

    const replacement = 'evt_unsigned_replacement';

    const replaced = expectSuccess(
      `${case_.context} event-id-replacement`,
      await verify(
        { rawBody: case_.body, headers: { ...case_.headers, 'X-Razorpay-Event-Id': replacement } },
        optionsFor(case_),
      ),
    );

    expect(replaced.identity.eventId).toBe(replacement);
  });
});

describe('lemon squeezy unsigned metadata', () => {
  test('never interprets X-Event-Name as identity', async () => {
    const case_ = representative('lemon-squeezy', 1);

    const success = expectSuccess(
      `${case_.context} event-name-change`,
      await verify(
        {
          rawBody: case_.body,
          headers: { ...case_.headers, 'X-Event-Name': 'subscription_created' },
        },
        optionsFor(case_),
      ),
    );

    expect(success.identity).toEqual({
      deliveryId: null,
      eventId: null,
      timestamp: null,
      authenticatedFields: [],
    });
  });
});

describe.each(SECURITY_PROVIDERS)('%s header grammar adversaries', (provider) => {
  const case_ = representative(provider, 1);
  const timestamp = case_.timestamp === null ? null : requiredTimestamp(case_);
  const timestampText = timestamp === null ? null : String(timestamp);

  test(`${case_.context} lowercased-and-tuple-representations`, async () => {
    expectSuccess(
      `${case_.context} lowercase-record`,
      await verify({ rawBody: case_.body, headers: lowerCaseKeys(case_.headers) }, optionsFor(case_)),
    );
    expectSuccess(
      `${case_.context} tuple-record`,
      await verify({ rawBody: case_.body, headers: Object.entries(case_.headers) }, optionsFor(case_)),
    );
  });

  test(`${case_.context} duplicate-signature-container`, async () => {
    const duplicateRecord = {
      ...case_.headers,
      [case_.signatureHeader]: [case_.signatureValue, case_.signatureValue],
    };

    const appended = toHeaders(case_.headers);

    appended.append(case_.signatureHeader, case_.signatureValue);

    expectReason(
      `${case_.context} array-combined-signature`,
      await verify({ rawBody: case_.body, headers: duplicateRecord }, optionsFor(case_)),
      'malformed-signature',
    );
    expectReason(
      `${case_.context} Headers-append-signature`,
      await verify({ rawBody: case_.body, headers: appended }, optionsFor(case_)),
      'malformed-signature',
    );

    const duplicateTuples = [
      ...Object.entries(case_.headers),
      [case_.signatureHeader.toLowerCase(), case_.signatureValue] as const,
    ];

    const differentlyCasedRecord = {
      ...case_.headers,
      [case_.signatureHeader.toLowerCase()]: case_.signatureValue,
    };

    expect(Object.keys(differentlyCasedRecord)).toHaveLength(Object.keys(case_.headers).length + 1);

    for (const headers of [duplicateTuples, differentlyCasedRecord]) {
      expectReason(
        `${case_.context} case-insensitive-duplicate-signature`,
        await verify({ rawBody: case_.body, headers }, optionsFor(case_)),
        'malformed-signature',
      );
    }
  });

  test(`${case_.context} timestamp-grammar`, async () => {
    if (timestampText === null) {
      expect(case_.timestamp).toBeNull();
    } else if (case_.provider === 'paddle') {
      const paddleTimestamp = requiredTimestamp(case_);

      expectReason(
        `${case_.context} duplicate-paddle-timestamp`,
        await verify(
          {
            rawBody: case_.body,
            headers: {
              ...case_.headers,
              [case_.signatureHeader]:
                `ts=${paddleTimestamp};ts=${paddleTimestamp};h1=${case_.signatureToken}`,
            },
          },
          optionsFor(case_),
        ),
        'malformed-signature',
      );
      expectReason(
        `${case_.context} noncanonical-paddle-timestamp`,
        await verify(
          {
            rawBody: case_.body,
            headers: {
              ...case_.headers,
              [case_.signatureHeader]: `ts=0${paddleTimestamp};h1=${case_.signatureToken}`,
            },
          },
          optionsFor(case_),
        ),
        'malformed-signature',
      );
    } else if (case_.timestampHeader === null) {
      expectReason(
        `${case_.context} duplicate-stripe-timestamp`,
        await verify(
          {
            rawBody: case_.body,
            headers: {
              ...case_.headers,
              [case_.signatureHeader]: `t=${timestampText},t=${timestampText},v1=${case_.signatureToken}`,
            },
          },
          optionsFor(case_),
        ),
        'malformed-signature',
      );
      expectReason(
        `${case_.context} noncanonical-stripe-timestamp`,
        await verify(
          {
            rawBody: case_.body,
            headers: {
              ...case_.headers,
              [case_.signatureHeader]: `t=0${timestampText},v1=${case_.signatureToken}`,
            },
          },
          optionsFor(case_),
        ),
        'malformed-signature',
      );
    } else {
      expectReason(
        `${case_.context} duplicate-timestamp`,
        await verify(
          {
            rawBody: case_.body,
            headers: { ...case_.headers, [case_.timestampHeader]: [timestampText, timestampText] },
          },
          optionsFor(case_),
        ),
        'malformed-signature',
      );
      expectReason(
        `${case_.context} noncanonical-timestamp`,
        await verify(
          { rawBody: case_.body, headers: withTimestampText(case_, `0${timestampText}`) },
          optionsFor(case_),
        ),
        'malformed-signature',
      );
    }
  });

  test(`${case_.context} alternative-encoding`, async () => {
    const alternative = case_.encoding === 'hex'
      ? case_.signatureToken.toUpperCase()
      : case_.signatureToken.replace(/=+$/, '');

    const headers = {
      ...case_.headers,
      [case_.signatureHeader]: headerValueFor(case_, alternative, case_.signatureTimestampText),
    };

    expect(alternative).not.toBe(case_.signatureToken);
    expectSuccess(
      `${case_.context} canonical-alternative-encoding`,
      await verify({ rawBody: case_.body, headers }, optionsFor(case_)),
    );
  });

  test(`${case_.context} digest-length`, async () => {
    for (const length of [31, 33]) {
      const token = Buffer.alloc(length).toString(case_.encoding);

      const headers = {
        ...case_.headers,
        [case_.signatureHeader]: headerValueFor(case_, token, case_.signatureTimestampText),
      };

      expectReason(
        `${case_.context} digest-length=${length}`,
        await verify({ rawBody: case_.body, headers }, optionsFor(case_)),
        'malformed-signature',
      );
    }
  });

  if (case_.encoding === 'base64') {
    test(`${case_.context} noncanonical-base64-padding-bits`, async () => {
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      const padded = case_.signatureToken;
      const finalIndex = alphabet.indexOf(padded.charAt(padded.length - 2));

      expect(padded).toHaveLength(44);
      expect(padded.endsWith('=')).toBe(true);
      expect(finalIndex).toBeGreaterThanOrEqual(0);
      expect(finalIndex & 3).toBe(0);

      const noncanonical = `${padded.slice(0, -2)}${alphabet.charAt(finalIndex | 1)}=`;
      const decoded = Buffer.from(noncanonical, 'base64');

      expect(noncanonical).not.toBe(padded);
      expect(decoded).toHaveLength(32);
      expect(decoded).toEqual(Buffer.from(padded, 'base64'));
      expect(decoded.toString('base64')).toBe(padded);

      expectReason(
        `${case_.context} noncanonical-base64-padding-bits`,
        await verify(
          {
            rawBody: case_.body,
            headers: {
              ...case_.headers,
              [case_.signatureHeader]: headerValueFor(case_, noncanonical, case_.signatureTimestampText),
            },
          },
          optionsFor(case_),
        ),
        'malformed-signature',
      );
    });
  }

  test(`${case_.context} rotation-grammar`, async () => {
    if (case_.rotationHeader !== null) {
      expectSuccess(
        `${case_.context} distinct-rotation-list`,
        await verify(
          {
            rawBody: case_.body,
            headers: { ...case_.headers, [case_.signatureHeader]: case_.rotationHeader },
          },
          optionsFor(case_, case_.rotationSecrets),
        ),
      );

      const activeValue = headerValueFor(case_, case_.signatureToken, case_.signatureTimestampText);
      const retiredValue = headerValueFor(case_, case_.retiredToken, case_.signatureTimestampText);

      const reversed = case_.provider === 'stripe'
        ? `t=${timestampText},v1=${case_.signatureToken},v1=${case_.retiredToken}`
        : case_.provider === 'paddle'
          ? `ts=${requiredTimestamp(case_)};h1=${case_.signatureToken};h1=${case_.retiredToken}`
          : `${activeValue} ${retiredValue}`;

      expect(case_.signatureToken).not.toBe(case_.retiredToken);

      for (const signature of [case_.rotationHeader, reversed]) {
        for (const secret of [case_.activeSecret, case_.retiredSecret]) {
          expectSuccess(
            `${case_.context} rotation-both-orders-single-secret`,
            await verify(
              {
                rawBody: case_.body,
                headers: { ...case_.headers, [case_.signatureHeader]: signature },
              },
              optionsFor(case_, [secret]),
            ),
          );
        }
      }
    } else {
      expect(case_.rotationHeader).toBeNull();

      const merged = {
        ...case_.headers,
        [case_.signatureHeader]: headerValueFor(
          case_,
          `${case_.retiredToken},${case_.signatureToken}`,
          case_.signatureTimestampText,
        ),
      };

      expectReason(
        `${case_.context} no-rotation-list-grammar`,
        await verify({ rawBody: case_.body, headers: merged }, optionsFor(case_)),
        'malformed-signature',
      );
    }
  });

  test(`${case_.context} mixed-malformed-token`, async () => {
    if (case_.provider === 'stripe') {
      expectReason(
        `${case_.context} mixed-malformed-stripe`,
        await verify(
          {
            rawBody: case_.body,
            headers: {
              ...case_.headers,
              [case_.signatureHeader]: `t=${timestampText},v1=${case_.signatureToken},v1=zz`,
            },
          },
          optionsFor(case_),
        ),
        'malformed-signature',
      );
    } else {
      expectReason(
        `${case_.context} mixed-malformed-token`,
        await verify(
          {
            rawBody: case_.body,
            headers: {
              ...case_.headers,
              [case_.signatureHeader]: headerValueFor(
                case_,
                  case_.provider === 'github' || case_.provider === 'shopify'
                    ? `${case_.signatureToken} ${case_.encoding === 'hex' ? 'zz' : '@@@'}`
                    : `${case_.signatureToken} v1,@@@`,
                case_.signatureTimestampText,
              ),
            },
          },
          optionsFor(case_),
        ),
        'malformed-signature',
      );
    }
  });
});

describe('Clerk branded-family isolation', () => {
  const case_ = representative('clerk', 1);

  const canonical = {
    'Webhook-Id': case_.authenticatedId ?? '',
    'Webhook-Timestamp': String(requiredTimestamp(case_)),
    'Webhook-Signature': case_.signatureValue,
  };

  test(`${case_.context} canonical-only-clerk`, async () => {
    expectReason(
      `${case_.context} canonical-only-clerk`,
      await verify({ rawBody: case_.body, headers: canonical }, optionsFor(case_)),
      'missing-signature',
    );
  });

  test(`${case_.context} canonical-cannot-repair-id`, async () => {
    expectReason(
      `${case_.context} canonical-cannot-repair-id`,
      await verify(
        {
          rawBody: case_.body,
          headers: { ...canonical, 'Svix-Signature': case_.signatureValue },
        },
        optionsFor(case_),
      ),
      'missing-identity',
    );
  });

  test(`${case_.context} canonical-cannot-repair-signature`, async () => {
    expectReason(
      `${case_.context} canonical-cannot-repair-signature`,
      await verify(
        { rawBody: case_.body, headers: { ...canonical, 'Svix-Signature': 'v1,@@@' } },
        optionsFor(case_),
      ),
      'malformed-signature',
    );
  });
});

describe('Svix dual-family fail-closed policy', () => {
  const case_ = representative('svix', 0);
  const branded = { ...case_.headers };

  const canonical = {
    'Webhook-Id': case_.authenticatedId ?? '',
    'Webhook-Timestamp': String(requiredTimestamp(case_)),
    'Webhook-Signature': case_.signatureValue,
  };

  test(`${case_.context} equal-families`, async () => {
    expectSuccess(
      `${case_.context} equal-families`,
      await verify({ rawBody: case_.body, headers: { ...branded, ...canonical } }, optionsFor(case_)),
    );
  });

  test(`${case_.context} conflicting-families`, async () => {
    const conflictingSignature = `v1,${
      flipDigestBit(case_.signatureToken, case_.encoding)
    }`;

    for (const headers of [
      { ...branded, ...canonical, 'Webhook-Id': `${case_.authenticatedId ?? ''}_other` },
      {
        ...branded,
        ...canonical,
        'Webhook-Timestamp': String(requiredTimestamp(case_) + 1),
      },
      { ...branded, ...canonical, 'Webhook-Signature': conflictingSignature },
    ]) {
      expectReason(
        `${case_.context} conflicting-families`,
        await verify({ rawBody: case_.body, headers }, optionsFor(case_)),
        'malformed-signature',
      );
    }
  });

  test(`${case_.context} partial-families`, async () => {
    for (const headers of [
      {
        'Svix-Id': case_.authenticatedId ?? '',
        'Webhook-Timestamp': String(requiredTimestamp(case_)),
        'Webhook-Signature': case_.signatureValue,
      },
      {
        'Webhook-Id': case_.authenticatedId ?? '',
        'Svix-Timestamp': String(requiredTimestamp(case_)),
        'Svix-Signature': case_.signatureValue,
      },
      { ...branded, 'Webhook-Id': case_.authenticatedId ?? '' },
      { ...canonical, 'Svix-Id': case_.authenticatedId ?? '' },
    ]) {
      expectReason(
        `${case_.context} partial-families`,
        await verify({ rawBody: case_.body, headers }, optionsFor(case_)),
        'malformed-signature',
      );
    }
  });

  test(`${case_.context} no-family-fallback`, async () => {
    expectReason(
      `${case_.context} malformed-branded`,
      await verify(
        { rawBody: case_.body, headers: { ...canonical, 'Svix-Signature': 'v1,@@@' } },
        optionsFor(case_),
      ),
      'malformed-signature',
    );
    expectReason(
      `${case_.context} malformed-canonical`,
      await verify(
        { rawBody: case_.body, headers: { ...branded, 'Webhook-Signature': 'v1,@@@' } },
        optionsFor(case_),
      ),
      'malformed-signature',
    );
  });

  test(`${case_.context} no-family`, async () => {
    expectReason(
      `${case_.context} no-family`,
      await verify({ rawBody: case_.body, headers: {} }, optionsFor(case_)),
      'missing-signature',
    );
  });
});

describe.each(SECURITY_PROVIDERS)('%s invocation snapshots', (provider) => {
  const case_ = representative(provider, 2);

  test(`${case_.context} invocation-snapshot`, async () => {
    const backing = new Uint8Array(case_.body.byteLength + 4);

    backing.set(case_.body, 2);

    const view = backing.subarray(2, 2 + case_.body.byteLength);
    const headers = new Headers(case_.headers);
    const secrets = [case_.activeSecret];
    const pending = verify({ rawBody: view, headers }, { provider, secrets, now: () => case_.now });

    backing.fill(0x5a);
    headers.set(case_.signatureHeader, 'mutated-after-call');
    headers.set('X-Late-Header', 'late');
    secrets[0] = case_.wrongSecret;
    secrets.push(case_.retiredSecret);

    const success = expectSuccess(`${case_.context} invocation-snapshot`, await pending);

    expect(success.rawBody).toEqual(case_.body);
    expectIdentity(`${case_.context} invocation-snapshot`, success, case_.expectedIdentity);
  });

  test(`${case_.context} returned-rawBody-copy`, async () => {
    const source = new Uint8Array(case_.body);

    const success = expectSuccess(
      `${case_.context} returned-snapshot`,
      await verify({ rawBody: source, headers: case_.headers }, optionsFor(case_)),
    );

    success.rawBody.fill(0xff);
    expect(source).toEqual(case_.body);

    const again = expectSuccess(
      `${case_.context} returned-snapshot-repeat`,
      await verify({ rawBody: source, headers: case_.headers }, optionsFor(case_)),
    );

    expect(again.rawBody).toEqual(case_.body);
  });

  test(`${case_.context} createVerifier-prepared`, async () => {
    const mutableSecrets = [case_.activeSecret];

    const options: MutableOptions = {
      provider,
      secrets: mutableSecrets,
      now: () => case_.now,
    };

    const verifier = createVerifier(options);

    const retiredOnly = {
      ...case_.headers,
      [case_.signatureHeader]: headerValueFor(
        case_,
        case_.retiredToken,
        case_.signatureTimestampText,
      ),
    };

    mutableSecrets[0] = case_.wrongSecret;
    mutableSecrets.push(case_.retiredSecret);
    options.now = () => case_.now + 86_400;

    expectSuccess(
      `${case_.context} createVerifier-prepared`,
      await verifier({ rawBody: case_.body, headers: case_.headers }),
    );
    expectReason(
      `${case_.context} createVerifier-prepared-secret`,
      await verifier({ rawBody: case_.body, headers: retiredOnly }),
      'invalid-signature',
    );
  });

  test(`${case_.context} createVerifier-body-tamper`, async () => {
    const verifier = createVerifier(optionsFor(case_));

    expectReason(
      `${case_.context} createVerifier-body-tamper`,
      await verifier({ rawBody: flipBodyByte(case_.body, 0), headers: case_.headers }),
      'invalid-signature',
    );
  });
});

describe.each(SECURITY_PROVIDERS)('%s verifyRequest() signed-byte matrix', (provider) => {
  for (const index of [0, 2, 4, 7]) {
    const case_ = representative(provider, index);

    test(`${case_.context} verifies once and rejects reuse`, async () => {
      const request = new Request('https://security.internal/hook', {
        method: 'POST',
        headers: toHeaders(case_.headers),
        body: new Uint8Array(case_.body),
      });

      const success = expectSuccess(
        `${case_.context} verifyRequest`,
        await verifyRequest(request, optionsFor(case_)),
      );

      expect(success.provider).toBe(provider);
      expect(success.rawBody).toEqual(case_.body);
      expectIdentity(`${case_.context} verifyRequest`, success, case_.expectedIdentity);

      await expect(verifyRequest(request, optionsFor(case_))).rejects.toMatchObject({
        name: 'HooklatchError',
        code: 'body-consumed',
      });
    });

    test(`${case_.context} rejects a mutated body`, async () => {
      const request = new Request('https://security.internal/hook', {
        method: 'POST',
        headers: toHeaders(case_.headers),
        body: new Uint8Array(flipBodyByte(case_.body, 0)),
      });

      expectReason(
        `${case_.context} verifyRequest-body-tamper`,
        await verifyRequest(request, optionsFor(case_)),
        'invalid-signature',
      );
    });
  }
});

describe('independent generator consistency', () => {
  test('reproduces every recorded token with the same independent signer', () => {
    for (const case_ of ALL_CASES) {
      const token = signatureTokenFor(
        case_,
        case_.activeSecret,
        case_.signatureTimestampText,
        case_.authenticatedId,
      );

      expect(token).toBe(case_.signatureToken);
    }
  });
});
