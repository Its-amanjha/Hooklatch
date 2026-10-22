import { createHash } from 'node:crypto';
import { createVerifier, verify, verifyRequest } from '../../src/index.js';
import { SUPPORTED_PROVIDERS } from '../../src/providers/index.js';
import type {
  EventIdentity,
  HeaderInput,
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
import type {
  DeterministicCase,
  GrafanaCaseOptions,
  PolarCaseOptions,
  SecurityProvider,
} from './deterministic-cases.js';

/**
 * Adversarial qualification of the nineteen public providers through
 * the public root only, preserving the original sixteen-provider records as a
 * byte-identical prefix. All signatures are generated independently in
 * `deterministic-cases.ts`; production parse/decode helpers are never used to
 * build expected values. Synthetic data only; not an official conformance run.
 */

type VerificationResult = Awaited<ReturnType<typeof verify>>;

/** Providers with the shared 300-second default freshness window. */
const TIMESTAMPED_PROVIDERS = [
  'stripe', 'standard-webhooks', 'clerk', 'svix', 'dodo-payments', 'gitlab', 'replicate',
  'grafana', 'polar',
] as const;

/** Providers whose signature covers the raw body only (no timestamp). */
const BODY_ONLY_PROVIDERS = ['github', 'shopify', 'razorpay', 'lemon-squeezy', 'sentry', 'doppler', 'linear'] as const;

const STANDARD_WEBHOOKS_PROVIDERS = [
  'standard-webhooks', 'clerk', 'svix', 'dodo-payments', 'gitlab', 'replicate', 'polar',
] as const;

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

/** Captured from the immutable sixteen-provider corpus before Stage B edits. */
const PRE_PHASE7_PROVIDER_COUNT = 16;
const PRE_PHASE7_CASE_COUNT = PRE_PHASE7_PROVIDER_COUNT * CASES_PER_PROVIDER;

const PRE_PHASE7_CORPUS_FINGERPRINT_SHA256 =
  '39b22e3c4940c32498da9576ec54de9cb1debbf4eb1af10def1e35e6bb8dfedd';

const PRE_PHASE7_FULL_RECORD_SHA256 =
  '3dcad39cfa58faabda0751e99189cb6830090e3102b5fa55f185168de62862ab';

function optionsFor(
  case_: DeterministicCase,
  secrets: readonly string[] = case_.secrets,
): VerifyOptions {
  const common = { secrets: [...secrets], now: () => case_.now };

  if (case_.provider === 'grafana') {
    const providerOptions = case_.providerOptions;

    if (providerOptions === undefined || !('mode' in providerOptions)) {
      throw new Error(`${case_.context}: expected Grafana provider options.`);
    }

    return { ...common, provider: 'grafana', providerOptions };
  }

  if (case_.provider === 'polar') {
    const providerOptions = case_.providerOptions;

    if (providerOptions === undefined || !('secretMode' in providerOptions)) {
      throw new Error(`${case_.context}: expected Polar provider options.`);
    }

    return { ...common, provider: 'polar', providerOptions };
  }

  return { ...common, provider: case_.provider };
}

function grafanaOptions(
  providerOptions: GrafanaCaseOptions,
  secrets: readonly string[],
  now: number,
  toleranceSeconds?: number,
): VerifyOptions {
  if (toleranceSeconds === undefined) {
    return {
      provider: 'grafana',
      providerOptions,
      secrets: [...secrets],
      now: () => now,
    };
  }

  return {
    provider: 'grafana',
    providerOptions,
    secrets: [...secrets],
    now: () => now,
    toleranceSeconds,
  };
}

function grafanaCaseOptions(case_: DeterministicCase): GrafanaCaseOptions {
  const providerOptions = case_.providerOptions;

  if (providerOptions === undefined || !('mode' in providerOptions)) {
    throw new Error(`${case_.context}: expected Grafana provider options.`);
  }

  return providerOptions;
}

function polarOptions(
  secretMode: PolarCaseOptions['secretMode'],
  secrets: readonly string[],
  now: number,
  toleranceSeconds?: number,
): VerifyOptions {
  if (toleranceSeconds === undefined) {
    return {
      provider: 'polar',
      providerOptions: { secretMode },
      secrets: [...secrets],
      now: () => now,
    };
  }

  return {
    provider: 'polar',
    providerOptions: { secretMode },
    secrets: [...secrets],
    now: () => now,
    toleranceSeconds,
  };
}

function representative(provider: SecurityProvider, index: number): DeterministicCase {
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

function requiredSignatureTimestamp(case_: DeterministicCase): string {
  if (case_.signatureTimestampText === null) {
    throw new Error(`${case_.context}: expected a signed timestamp.`);
  }

  return case_.signatureTimestampText;
}

function requiredAuthenticatedId(case_: DeterministicCase): string {
  if (case_.authenticatedId === null) {
    throw new Error(`${case_.context}: expected an authenticated id.`);
  }

  return case_.authenticatedId;
}

function withoutHeader(headers: Readonly<Record<string, string>>, name: string) {
  const copy = { ...headers };

  delete copy[name];

  return copy;
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
    // Undefined for the original sixteen cases, so their canonical bytes and
    // pinned full-record hashes remain unchanged.
    mode: entry.mode === 'default' ? undefined : entry.mode,
    providerOptions: entry.providerOptions,
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

  test('covers the exact nineteen-provider registry with no unmapped branch', () => {
    expect([...SECURITY_PROVIDERS]).toEqual([...SUPPORTED_PROVIDERS]);
    expect(SECURITY_PROVIDERS).toHaveLength(19);
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

  test('keeps the prior nine-provider corpus byte-identical', () => {
    const prior = ALL_CASES.slice(0, 9 * CASES_PER_PROVIDER);

    expect(sha256(corpusFingerprint(prior)))
      .toBe('4864ef6a1864959c07ade5f4f217b31df269804d7dbe05f70967524768110fc3');
    expect(sha256(prior.map(stableCaseRecord).join('\n')))
      .toBe('88ee3a346728a32643ddb9a93481298b10c875f917bc34f3752eeb8027118673');
  });

  test('preserves all 468 prior cases including headers, keys and identity', () => {
    const prior = ALL_CASES.slice(0, 468);

    expect(sha256(corpusFingerprint(prior)))
      .toBe('b263f77018f0e08d943b45cb42dc745d55abdd2998924ce5969b7c5c55919451');
    expect(sha256(prior.map(stableCaseRecord).join('\n')))
      .toBe('389edc9929a4688e4c85e2a113ce01a362ce7ce82b360c6290f52506516c64a9');
  });

  test('preserves all 576 prior sixteen-provider cases as an exact prefix', () => {
    const prior = ALL_CASES.slice(0, PRE_PHASE7_CASE_COUNT);

    expect(prior).toHaveLength(576);
    expect(prior.every((entry, index) =>
      entry.provider === SECURITY_PROVIDERS[Math.floor(index / CASES_PER_PROVIDER)]))
      .toBe(true);
    expect(sha256(corpusFingerprint(prior))).toBe(PRE_PHASE7_CORPUS_FINGERPRINT_SHA256);
    expect(sha256(prior.map(stableCaseRecord).join('\n'))).toBe(PRE_PHASE7_FULL_RECORD_SHA256);
  });

  test('keeps binary and nonzero-offset bodies for the added providers', () => {
    for (const provider of [
      'razorpay', 'paddle', 'lemon-squeezy', 'dodo-payments', 'gitlab', 'replicate', 'workos',
      'sentry', 'doppler', 'sanity', 'grafana', 'polar',
    ] as const) {
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

  test('maps Grafana and Polar to explicit, configuration-aware recipes', () => {
    const grafana = casesFor('grafana');
    const polar = casesFor('polar');

    expect(grafana.filter((entry) => entry.mode === 'body')).toHaveLength(18);
    expect(grafana.filter((entry) => entry.mode === 'timestamped')).toHaveLength(18);
    expect(grafana.every((entry) => entry.encoding === 'hex')).toBe(true);
    expect(grafana.every((entry) => entry.providerOptions !== undefined
      && 'mode' in entry.providerOptions
      && entry.providerOptions.mode === entry.mode)).toBe(true);
    expect(grafana.filter((entry) => entry.mode === 'body').every((entry) =>
      entry.signatureTimestampText === null
      && entry.timestamp === null
      && entry.expectedIdentity.timestamp === null
      && entry.expectedIdentity.authenticatedFields.length === 0)).toBe(true);
    expect(grafana.filter((entry) => entry.mode === 'timestamped').every((entry) =>
      entry.signatureTimestampText !== null
      && entry.timestamp !== null
      && entry.timestampHeader !== null
      && entry.expectedIdentity.timestamp === entry.timestamp
      && entry.expectedIdentity.authenticatedFields.length === 1
      && entry.expectedIdentity.authenticatedFields[0] === 'timestamp')).toBe(true);

    expect(polar.filter((entry) => entry.mode === 'current')).toHaveLength(18);
    expect(polar.filter((entry) => entry.mode === 'legacy')).toHaveLength(18);
    expect(polar.every((entry) => entry.encoding === 'base64'
      && entry.signatureHeader === 'Webhook-Signature'
      && entry.idHeader === 'Webhook-Id'
      && entry.timestampHeader === 'Webhook-Timestamp'
      && entry.rotationHeader !== null
      && entry.providerOptions !== undefined
      && 'secretMode' in entry.providerOptions
      && entry.providerOptions.secretMode === entry.mode)).toBe(true);
    expect(polar.every((entry) => entry.expectedIdentity.eventId === entry.authenticatedId
      && entry.expectedIdentity.timestamp === entry.timestamp
      && entry.expectedIdentity.authenticatedFields.length === 2
      && entry.expectedIdentity.authenticatedFields[0] === 'eventId'
      && entry.expectedIdentity.authenticatedFields[1] === 'timestamp')).toBe(true);
    expect(polar.filter((entry) => entry.mode === 'current')
      .every((entry) => !entry.activeSecret.includes('whsec_legacy_'))).toBe(true);
    expect(polar.filter((entry) => entry.mode === 'legacy')
      .every((entry) => entry.activeSecret.includes('whsec_legacy_'))).toBe(true);
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
  const timestampText = case_.signatureTimestampText;

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
    if (case_.encoding === 'base64url') {
      expectReason(
        `${case_.context} padded-base64url`,
        await verify(
          { rawBody: case_.body, headers: {
            ...case_.headers,
            [case_.signatureHeader]: headerValueFor(case_, `${case_.signatureToken}=`, timestampText),
          } },
          optionsFor(case_),
        ),
        'malformed-signature',
      );

      return;
    }

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

      const reversed = case_.provider === 'stripe' || case_.provider === 'workos'
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
    const options = { ...optionsFor(case_), secrets };
    const pending = verify({ rawBody: view, headers }, options);

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

    const options = {
      ...optionsFor(case_),
      secrets: mutableSecrets,
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


describe('WorkOS millisecond timestamp policy', () => {
  const case_ = representative('workos', 1);
  const timestamp = requiredTimestamp(case_);
  const timestampText = case_.signatureTimestampText;

  test('retains fractional seconds in signed identity and custom clock', async () => {
    const success = await expectValidCase(case_);

    expect(timestamp % 1).toBe(0.125);
    expect(Number(timestampText)).toBe(timestamp * 1000);
    expect(success.identity).toEqual({
      deliveryId: null,
      eventId: null,
      timestamp,
      authenticatedFields: ['timestamp'],
    });
  });

  test('uses inclusive 180 seconds by default with millisecond outside probes', async () => {
    for (const delta of [180, -180, 179.999, -179.999]) {
      expectSuccess(
        `workos default drift=${delta}`,
        await verify(
          { rawBody: case_.body, headers: case_.headers },
          { ...optionsFor(case_), now: () => timestamp + delta },
        ),
      );
    }

    for (const [delta, reason] of [
      [180.001, 'timestamp-expired'],
      [-180.001, 'timestamp-future'],
    ] as const) {
      expect(Math.abs(timestamp + delta - timestamp)).toBeGreaterThan(180);
      expectReason(
        `workos default drift=${delta}`,
        await verify(
          { rawBody: case_.body, headers: case_.headers },
          { ...optionsFor(case_), now: () => timestamp + delta },
        ),
        reason,
      );
    }
  });

  test('explicit zero is zero-width and HMAC failure precedes freshness', async () => {
    expectSuccess(
      'workos zero at the signed instant',
      await verify(
        { rawBody: case_.body, headers: case_.headers },
        { ...optionsFor(case_), toleranceSeconds: 0 },
      ),
    );

    for (const [delta, reason] of [
      [0.001, 'timestamp-expired'],
      [-0.001, 'timestamp-future'],
    ] as const) {
      expectReason(
        `workos zero drift=${delta}`,
        await verify(
          { rawBody: case_.body, headers: case_.headers },
          { ...optionsFor(case_), toleranceSeconds: 0, now: () => timestamp + delta },
        ),
        reason,
      );
    }

    for (const delta of [180.001, -180.001]) {
      expectReason(
        `workos wrong MAC before drift=${delta}`,
        await verify(
          { rawBody: flipBodyByte(case_.body, 0), headers: case_.headers },
          { ...optionsFor(case_), now: () => timestamp + delta },
        ),
        'invalid-signature',
      );
    }
  });

  test('authenticates original milliseconds, never seconds or unsigned ids', async () => {
    const changed = String(Number(timestampText) + 1);

    expectReason(
      'workos signed millisecond mutation',
      await verify(
        {
          rawBody: case_.body,
          headers: { 'WorkOS-Signature': `t=${changed},v1=${case_.signatureToken}` },
        },
        optionsFor(case_),
      ),
      'invalid-signature',
    );

    const success = expectSuccess(
      'workos ignored body-independent ids',
      await verify(
        {
          rawBody: case_.body,
          headers: { ...case_.headers, 'Webhook-Id': 'unsigned_id', 'WorkOS-Event-Id': 'unsigned_event' },
        },
        optionsFor(case_),
      ),
    );

    expectIdentity(case_.context, success, case_.expectedIdentity);
  });

  test('accepts punctuation in opaque unknown fields but rejects poisoned recognized tokens', async () => {
    const base = `t=${timestampText},v1=${case_.signatureToken}`;

    for (const unknown of ['v0=opaque!+./:;[]{}~', 'v2=UNRECOGNIZED', 'v9=abc_def-123']) {
      expectSuccess(
        `workos opaque ${unknown}`,
        await verify(
          { rawBody: case_.body, headers: { 'WorkOS-Signature': `${base},${unknown}` } },
          optionsFor(case_),
        ),
      );
    }

    for (const suffix of ['v1=zz', `v1=${'0'.repeat(62)}`, 'v2=space value', 'v2=a=b']) {
      expectReason(
        `workos poisoned ${suffix}`,
        await verify(
          { rawBody: case_.body, headers: { 'WorkOS-Signature': `${base},${suffix}` } },
          optionsFor(case_),
        ),
        'malformed-signature',
      );
    }
  });
});

describe.each(['dodo-payments', 'gitlab', 'replicate'] as const)(
  '%s canonical family and endpoint policy',
  (provider) => {
    const case_ = representative(provider, 1);

    test('does not accept branded-only aliases or repair a missing canonical id', async () => {
      const branded = {
        'Svix-Id': case_.authenticatedId ?? '',
        'Svix-Timestamp': String(requiredTimestamp(case_)),
        'Svix-Signature': case_.signatureValue,
      };

      expectReason(
        `${provider} branded-only`,
        await verify({ rawBody: case_.body, headers: branded }, optionsFor(case_)),
        'missing-signature',
      );
      expectReason(
        `${provider} branded cannot repair id`,
        await verify(
          {
            rawBody: case_.body,
            headers: {
              ...branded,
              'Webhook-Signature': case_.signatureValue,
              'Webhook-Timestamp': String(requiredTimestamp(case_)),
            },
          },
          optionsFor(case_),
        ),
        'missing-identity',
      );
    });

    test('binds authentication to endpoint key rather than a vendor label', async () => {
      for (const other of ['dodo-payments', 'gitlab', 'replicate'] as const) {
        expectSuccess(
          `${provider} same-secret protocol compatibility with ${other}`,
          await verify(
            { rawBody: case_.body, headers: case_.headers },
            { provider: other, secrets: [...case_.secrets], now: () => case_.now },
          ),
        );
        expectReason(
          `${provider} separate-secret endpoint ${other}`,
          await verify(
            { rawBody: case_.body, headers: case_.headers },
            {
              provider: other,
              secrets: [representative(other, 2).activeSecret],
              now: () => case_.now,
            },
          ),
          'invalid-signature',
        );
      }
    });
  },
);

describe('GitLab signing-token migration boundary', () => {
  const case_ = representative('gitlab', 1);

  test('never treats legacy token equality as body authentication', async () => {
    expectReason(
      'gitlab legacy token only',
      await verify(
        { rawBody: case_.body, headers: { 'X-Gitlab-Token': case_.activeSecret } },
        optionsFor(case_),
      ),
      'missing-signature',
    );
    expectReason(
      'gitlab valid legacy token cannot rescue wrong signature',
      await verify(
        {
          rawBody: case_.body,
          headers: {
            ...case_.headers,
            'Webhook-Signature': `v1,${flipDigestBit(case_.signatureToken, 'base64')}`,
            'X-Gitlab-Token': case_.activeSecret,
          },
        },
        optionsFor(case_),
      ),
      'invalid-signature',
    );
  });
});


describe('Sanity millisecond authentication and receiver freshness', () => {
  const case_ = representative('sanity', 1);
  const timestamp = requiredTimestamp(case_);
  const timestampText = case_.signatureTimestampText;

  test('retains the original milliseconds and independently signed fractional identity', async () => {
    const success = await expectValidCase(case_);

    expect(timestamp % 1).toBe(0.125);
    expect(Number(timestampText)).toBe(timestamp * 1000);
    expect(case_.signatureToken).toHaveLength(43);
    expect(success.identity).toEqual({
      deliveryId: null, eventId: null, timestamp, authenticatedFields: ['timestamp'],
    });

    const changed = String(Number(timestampText) + 1);

    expectReason(
      'sanity original timestamp is authenticated',
      await verify({
        rawBody: case_.body,
        headers: { [case_.signatureHeader]: `t=${changed},v1=${case_.signatureToken}` },
      }, optionsFor(case_)),
      'invalid-signature',
    );
  });

  test('enforces inclusive 300 seconds, fractional outside boundaries and explicit zero', async () => {
    for (const drift of [-300, 300, -299.999, 299.999]) {
      expectSuccess(
        `sanity inclusive drift=${drift}`,
        await verify({ rawBody: case_.body, headers: case_.headers }, {
          ...optionsFor(case_), now: () => timestamp + drift,
        }),
      );
    }

    for (const [drift, reason] of [
      [300.001, 'timestamp-expired'], [-300.001, 'timestamp-future'],
    ] as const) {
      expect(Math.abs(timestamp + drift - timestamp)).toBeGreaterThan(300);
      expectReason(
        `sanity outside drift=${drift}`,
        await verify({ rawBody: case_.body, headers: case_.headers }, {
          ...optionsFor(case_), now: () => timestamp + drift,
        }),
        reason,
      );
      expectReason(
        `sanity bad MAC before age drift=${drift}`,
        await verify({ rawBody: flipBodyByte(case_.body, 0), headers: case_.headers }, {
          ...optionsFor(case_), now: () => timestamp + drift,
        }),
        'invalid-signature',
      );
    }

    expectSuccess(
      'sanity explicit zero at signed instant',
      await verify({ rawBody: case_.body, headers: case_.headers }, {
        ...optionsFor(case_), toleranceSeconds: 0,
      }),
    );

    for (const [drift, reason] of [
      [0.001, 'timestamp-expired'], [-0.001, 'timestamp-future'],
    ] as const) {
      expectReason(
        `sanity zero width drift=${drift}`,
        await verify({ rawBody: case_.body, headers: case_.headers }, {
          ...optionsFor(case_), toleranceSeconds: 0, now: () => timestamp + drift,
        }),
        reason,
      );
    }
  });

  test('rejects nonzero unused bits even when a permissive decoder yields the valid MAC', async () => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    for (const entry of casesFor('sanity')) {
      const token = entry.signatureToken;
      const finalIndex = alphabet.indexOf(token.charAt(42));
      const noncanonical = `${token.slice(0, 42)}${alphabet.charAt(finalIndex | 1)}`;

      expect(finalIndex).toBeGreaterThanOrEqual(0);
      expect(finalIndex & 3).toBe(0);
      expect(noncanonical).not.toBe(token);
      expect(Buffer.from(noncanonical, 'base64url')).toEqual(Buffer.from(token, 'base64url'));
      expectReason(
        `${entry.context} noncanonical unused bits`,
        await verify({ rawBody: entry.body, headers: {
          [entry.signatureHeader]: headerValueFor(entry, noncanonical, entry.signatureTimestampText),
        } }, optionsFor(entry)),
        'malformed-signature',
      );
    }
  });

  test('rejects structural repairs and pre-2021 timestamps before cryptographic freshness', async () => {
    for (const header of [
      `t=1609459199999,v1=${case_.signatureToken}`,
      `t=1700000000,v1=${case_.signatureToken}`,
      `t=${timestampText};v1=${case_.signatureToken}`,
      `v1=${case_.signatureToken},t=${timestampText}`,
      `t=${timestampText}, v1=${case_.signatureToken}`,
      `t=${timestampText},v1=${case_.signatureToken},v1=${case_.signatureToken}`,
      `t=${timestampText},v1=${case_.signatureToken},v2=unknown`,
    ]) {
      expectReason(
        'sanity no grammar repair or pre-2021 acceptance',
        await verify({ rawBody: case_.body, headers: { [case_.signatureHeader]: header } }, optionsFor(case_)),
        'malformed-signature',
      );
    }
  });
});

describe.each(['sentry', 'doppler'] as const)('%s literal body-only authentication boundary', (provider) => {
  const case_ = representative(provider, 1);

  test('cannot substitute a Base64-decoded key for the configured literal whsec_ string', async () => {
    const decodedKeyToken = hmacToken(standardWebhooksKeyBytes(case_.activeSecret), case_.body, 'hex');

    expect(decodedKeyToken).not.toBe(case_.signatureToken);
    expectReason(
      `${provider} decoded key is a different protocol`,
      await verify({ rawBody: case_.body, headers: {
        ...case_.headers,
        [case_.signatureHeader]: headerValueFor(case_, decodedKeyToken, null),
      } }, optionsFor(case_)),
      'invalid-signature',
    );
  });

  test('retains scheme-specific errors without accepting bearer or unsigned delivery metadata', async () => {
    for (const [header, reason] of [
      [`SHA256=${case_.signatureToken}`, provider === 'doppler' ? 'unsupported-scheme' : 'malformed-signature'],
      [`sha1=${case_.signatureToken}`, provider === 'doppler' ? 'unsupported-scheme' : 'malformed-signature'],
      [`sha1=${'a'.repeat(40)}`, 'malformed-signature'],
    ] as const) {
      expectReason(
        `${provider} foreign scheme ${header.slice(0, 7)}`,
        await verify({ rawBody: case_.body, headers: {
          ...case_.headers,
          [case_.signatureHeader]: header,
          Authorization: `Bearer ${case_.activeSecret}`,
        } }, optionsFor(case_)),
        reason,
      );
    }
  });
});

describe('Grafana explicit body and timestamped configurations', () => {
  const bodyCase = representative('grafana', 2);
  const defaultBodyCase = representative('grafana', 0);
  const timestampedCase = representative('grafana', 1);
  const customTimestampedCase = representative('grafana', 3);
  const defaultSignatureHeader = 'X-Grafana-Alerting-Signature';

  test('verifies each configured layout with role-based identity', async () => {
    const body = await expectValidCase(bodyCase);
    const timestamped = await expectValidCase(timestampedCase);
    const customTimestamped = await expectValidCase(customTimestampedCase);

    expect(body.identity).toEqual({
      deliveryId: null,
      eventId: null,
      timestamp: null,
      authenticatedFields: [],
    });
    expect(timestamped.identity).toEqual({
      deliveryId: null,
      eventId: null,
      timestamp: requiredTimestamp(timestampedCase),
      authenticatedFields: ['timestamp'],
    });
    expect(customTimestamped.identity).toEqual(customTimestampedCase.expectedIdentity);
  });

  test('body mode authenticates only the exact body and ignores timestamp decoys', async () => {
    const stale = String(bodyCase.now + 86_400);

    const headers = {
      ...bodyCase.headers,
      'X-Grafana-Timestamp': stale,
      'X-Grafana-Alt-Timestamp': stale,
    };

    const success = expectSuccess(
      `${bodyCase.context} body timestamp isolation`,
      await verify(
        { rawBody: bodyCase.body, headers },
        grafanaOptions(grafanaCaseOptions(bodyCase), bodyCase.secrets, Number(stale), 0),
      ),
    );

    expect(success.identity).toEqual({
      deliveryId: null,
      eventId: null,
      timestamp: null,
      authenticatedFields: [],
    });

    const timestampedToken = signatureTokenFor(
      bodyCase,
      bodyCase.activeSecret,
      stale,
      null,
    );

    expectReason(
      `${bodyCase.context} body rejects timestamp layout`,
      await verify(
        {
          rawBody: bodyCase.body,
          headers: {
            ...bodyCase.headers,
            [bodyCase.signatureHeader]: timestampedToken,
            'X-Grafana-Timestamp': stale,
          },
        },
        optionsFor(bodyCase),
      ),
      'invalid-signature',
    );
  });

  test('timestamped mode enforces inclusive 300, explicit zero and MAC first', async () => {
    const timestamp = requiredTimestamp(timestampedCase);

    for (const delta of [300, -300]) {
      expectSuccess(
        `${timestampedCase.context} now-offset=${delta}`,
        await verify(
          { rawBody: timestampedCase.body, headers: timestampedCase.headers },
          { ...optionsFor(timestampedCase), now: () => timestamp + delta },
        ),
      );
    }

    for (const [delta, reason] of [
      [301, 'timestamp-expired'],
      [-301, 'timestamp-future'],
    ] as const) {
      expectReason(
        `${timestampedCase.context} now-offset=${delta}`,
        await verify(
          { rawBody: timestampedCase.body, headers: timestampedCase.headers },
          { ...optionsFor(timestampedCase), now: () => timestamp + delta },
        ),
        reason,
      );
    }

    expectSuccess(
      `${timestampedCase.context} explicit zero`,
      await verify(
        { rawBody: timestampedCase.body, headers: timestampedCase.headers },
        { ...optionsFor(timestampedCase), toleranceSeconds: 0 },
      ),
    );

    for (const [delta, reason] of [
      [1, 'timestamp-expired'],
      [-1, 'timestamp-future'],
    ] as const) {
      expectReason(
        `${timestampedCase.context} zero width now-offset=${delta}`,
        await verify(
          { rawBody: timestampedCase.body, headers: timestampedCase.headers },
          { ...optionsFor(timestampedCase), toleranceSeconds: 0, now: () => timestamp + delta },
        ),
        reason,
      );
    }

    for (const delta of [301, -301]) {
      expectReason(
        `${timestampedCase.context} bad MAC before stale now-offset=${delta}`,
        await verify(
          { rawBody: flipBodyByte(timestampedCase.body, 0), headers: timestampedCase.headers },
          { ...optionsFor(timestampedCase), now: () => timestamp + delta },
        ),
        'invalid-signature',
      );
    }

    expectReason(
      `${timestampedCase.context} signed timestamp tamper`,
      await verify(
        {
          rawBody: timestampedCase.body,
          headers: withTimestampText(timestampedCase, String(timestamp + 1)),
        },
        optionsFor(timestampedCase),
      ),
      'invalid-signature',
    );
  });

  test('selected headers are configuration, never request-driven hints', async () => {
    const customHeader = bodyCase.signatureHeader;

    const onlyDefault = {
      ...withoutHeader(bodyCase.headers, customHeader),
      [defaultSignatureHeader]: bodyCase.signatureValue,
    };

    expectReason(
      `${bodyCase.context} custom missing cannot use default`,
      await verify({ rawBody: bodyCase.body, headers: onlyDefault }, optionsFor(bodyCase)),
      'missing-signature',
    );

    const onlyCustom = {
      ...withoutHeader(defaultBodyCase.headers, defaultSignatureHeader),
      'X-Grafana-Signature': defaultBodyCase.signatureValue,
    };

    expectReason(
      `${defaultBodyCase.context} default missing cannot use custom`,
      await verify(
        { rawBody: defaultBodyCase.body, headers: onlyCustom },
        optionsFor(defaultBodyCase),
      ),
      'missing-signature',
    );

    const selectedTimestampHeader = requiredHeader(
      customTimestampedCase,
      customTimestampedCase.timestampHeader,
    );

    const timestampText = requiredSignatureTimestamp(customTimestampedCase);
    const altTimestampHeader = 'X-Grafana-Alt-Timestamp';

    const missingTimestamp = {
      ...withoutHeader(customTimestampedCase.headers, selectedTimestampHeader),
      [altTimestampHeader]: timestampText,
    };

    expectReason(
      `${customTimestampedCase.context} alternate timestamp cannot rescue`,
      await verify(
        { rawBody: customTimestampedCase.body, headers: missingTimestamp },
        optionsFor(customTimestampedCase),
      ),
      'missing-timestamp',
    );

    expectReason(
      `${customTimestampedCase.context} wrong timestamp value`,
      await verify(
        {
          rawBody: customTimestampedCase.body,
          headers: {
            ...customTimestampedCase.headers,
            [selectedTimestampHeader]: String(Number(timestampText) + 1),
          },
        },
        optionsFor(customTimestampedCase),
      ),
      'invalid-signature',
    );
  });

  test('layout is selected by configuration, with no downgrade or upgrade', async () => {
    const timestampText = requiredSignatureTimestamp(timestampedCase);
    const bodyLayoutToken = signatureTokenFor(timestampedCase, timestampedCase.activeSecret, null, null);

    const bodyLayoutHeaders = {
      ...timestampedCase.headers,
      [timestampedCase.signatureHeader]: bodyLayoutToken,
    };

    const body = expectSuccess(
      `${timestampedCase.context} configured body layout`,
      await verify(
        { rawBody: timestampedCase.body, headers: bodyLayoutHeaders },
        grafanaOptions(
          { mode: 'body' },
          timestampedCase.secrets,
          timestampedCase.now,
        ),
      ),
    );

    expect(body.identity).toEqual({
      deliveryId: null,
      eventId: null,
      timestamp: null,
      authenticatedFields: [],
    });
    expectReason(
      `${timestampedCase.context} body layout cannot satisfy timestamped mode`,
      await verify(
        { rawBody: timestampedCase.body, headers: bodyLayoutHeaders },
        optionsFor(timestampedCase),
      ),
      'invalid-signature',
    );

    const timestampedToken = signatureTokenFor(
      timestampedCase,
      timestampedCase.activeSecret,
      timestampText,
      null,
    );

    expectReason(
      `${timestampedCase.context} timestamp layout cannot be upgraded from body mode`,
      await verify(
        {
          rawBody: timestampedCase.body,
          headers: {
            ...timestampedCase.headers,
            [timestampedCase.signatureHeader]: timestampedToken,
          },
        },
        grafanaOptions({ mode: 'body' }, timestampedCase.secrets, timestampedCase.now),
      ),
      'invalid-signature',
    );

    expectReason(
      `${timestampedCase.context} missing timestamp never downgrades`,
      await verify(
        {
          rawBody: timestampedCase.body,
          headers: withoutHeader(
            timestampedCase.headers,
            requiredHeader(timestampedCase, timestampedCase.timestampHeader),
          ),
        },
        optionsFor(timestampedCase),
      ),
      'missing-timestamp',
    );
  });

  test('literal key and header names are not signed', async () => {
    const literalToken = signatureTokenFor(bodyCase, bodyCase.activeSecret, null, null);

    const decodedToken = hmacToken(
      standardWebhooksKeyBytes(bodyCase.activeSecret),
      bodyCase.body,
      'hex',
    );

    expect(literalToken).toBe(bodyCase.signatureToken);
    expect(decodedToken).not.toBe(literalToken);
    expectSuccess(
      `${bodyCase.context} literal secret token`,
      await verify({ rawBody: bodyCase.body, headers: bodyCase.headers }, optionsFor(bodyCase)),
    );
    expectReason(
      `${bodyCase.context} decoded-key token is a different interpretation`,
      await verify(
        {
          rawBody: bodyCase.body,
          headers: { ...bodyCase.headers, [bodyCase.signatureHeader]: decodedToken },
        },
        optionsFor(bodyCase),
      ),
      'invalid-signature',
    );

    const timestampText = requiredSignatureTimestamp(timestampedCase);

    const firstOptions: GrafanaCaseOptions = {
      mode: 'timestamped',
      signatureHeader: 'X-Grafana-One-Signature',
      timestampHeader: 'X-Grafana-One-Timestamp',
    };

    const secondOptions: GrafanaCaseOptions = {
      mode: 'timestamped',
      signatureHeader: 'X-Grafana-Two-Signature',
      timestampHeader: 'X-Grafana-Two-Timestamp',
    };

    for (const [label, options] of [
      ['one', firstOptions],
      ['two', secondOptions],
    ] as const) {
      const headers = {
        [options.signatureHeader ?? '']: timestampedCase.signatureValue,
        [options.timestampHeader]: timestampText,
      };

      expectSuccess(
        `${timestampedCase.context} header-name layout=${label}`,
        await verify(
          { rawBody: timestampedCase.body, headers },
          grafanaOptions(options, timestampedCase.secrets, timestampedCase.now),
        ),
      );
    }
  });

  test('rotation stays inside the selected layout', async () => {
    const retiredBodyToken = signatureTokenFor(
      bodyCase,
      bodyCase.retiredSecret,
      null,
      null,
    );

    const retiredBodyHeaders = {
      ...bodyCase.headers,
      [bodyCase.signatureHeader]: retiredBodyToken,
    };

    expectSuccess(
      `${bodyCase.context} body rotation`,
      await verify(
        { rawBody: bodyCase.body, headers: retiredBodyHeaders },
        optionsFor(bodyCase, bodyCase.rotationSecrets),
      ),
    );
    expectReason(
      `${bodyCase.context} body rotation removal`,
      await verify(
        { rawBody: bodyCase.body, headers: retiredBodyHeaders },
        optionsFor(bodyCase, [bodyCase.activeSecret]),
      ),
      'invalid-signature',
    );

    const timestampText = requiredSignatureTimestamp(timestampedCase);

    const retiredTimestampToken = signatureTokenFor(
      timestampedCase,
      timestampedCase.retiredSecret,
      timestampText,
      null,
    );

    const retiredTimestampHeaders = {
      ...timestampedCase.headers,
      [timestampedCase.signatureHeader]: retiredTimestampToken,
    };

    expectSuccess(
      `${timestampedCase.context} timestamped rotation`,
      await verify(
        { rawBody: timestampedCase.body, headers: retiredTimestampHeaders },
        optionsFor(timestampedCase, timestampedCase.rotationSecrets),
      ),
    );
    expectReason(
      `${timestampedCase.context} timestamped rotation removal`,
      await verify(
        { rawBody: timestampedCase.body, headers: retiredTimestampHeaders },
        optionsFor(timestampedCase, [timestampedCase.activeSecret]),
      ),
      'invalid-signature',
    );
    expectReason(
      `${timestampedCase.context} body-layout rotation cannot cross layout`,
      await verify(
        {
          rawBody: timestampedCase.body,
          headers: {
            ...timestampedCase.headers,
            [timestampedCase.signatureHeader]: signatureTokenFor(
              timestampedCase,
              timestampedCase.retiredSecret,
              null,
              null,
            ),
          },
        },
        optionsFor(timestampedCase, timestampedCase.rotationSecrets),
      ),
      'invalid-signature',
    );
  });
});

describe('Polar configured current and legacy secret modes', () => {
  const currentCase = representative('polar', 2);
  const legacyCase = representative('polar', 1);
  const legacyUnicodeCase = representative('polar', 7);

  test('verifies both modes with role-based canonical identity', async () => {
    for (const case_ of [currentCase, legacyCase, legacyUnicodeCase]) {
      const success = await expectValidCase(case_);

      expect(success.identity).toEqual({
        deliveryId: null,
        eventId: requiredAuthenticatedId(case_),
        timestamp: requiredTimestamp(case_),
        authenticatedFields: ['eventId', 'timestamp'],
      });
    }

    expect(legacyUnicodeCase.activeSecret).toContain('秘密');
  });

  test('current and legacy key interpretations never rescue each other', async () => {
    const secret = currentCase.activeSecret;
    const id = requiredAuthenticatedId(currentCase);
    const timestampText = requiredSignatureTimestamp(currentCase);

    const currentToken = signatureTokenFor(
      currentCase,
      secret,
      timestampText,
      id,
      { secretMode: 'current' },
    );

    const legacyToken = signatureTokenFor(
      currentCase,
      secret,
      timestampText,
      id,
      { secretMode: 'legacy' },
    );

    expect(currentToken).not.toBe(legacyToken);

    const currentHeaders = {
      ...currentCase.headers,
      [currentCase.signatureHeader]: headerValueFor(
        currentCase,
        currentToken,
        timestampText,
      ),
    };

    const legacyHeaders = {
      ...currentCase.headers,
      [currentCase.signatureHeader]: headerValueFor(
        currentCase,
        legacyToken,
        timestampText,
      ),
    };

    expectSuccess(
      `${currentCase.context} current token in current mode`,
      await verify(
        { rawBody: currentCase.body, headers: currentHeaders },
        polarOptions('current', [secret], currentCase.now),
      ),
    );
    expectReason(
      `${currentCase.context} current token cannot satisfy legacy mode`,
      await verify(
        { rawBody: currentCase.body, headers: currentHeaders },
        polarOptions('legacy', [secret], currentCase.now),
      ),
      'invalid-signature',
    );
    expectSuccess(
      `${currentCase.context} legacy token in legacy mode`,
      await verify(
        { rawBody: currentCase.body, headers: legacyHeaders },
        polarOptions('legacy', [secret], currentCase.now),
      ),
    );
    expectReason(
      `${currentCase.context} legacy token cannot satisfy current mode`,
      await verify(
        { rawBody: currentCase.body, headers: legacyHeaders },
        polarOptions('current', [secret], currentCase.now),
      ),
      'invalid-signature',
    );
    await expect(verify(
      { rawBody: currentCase.body, headers: currentHeaders },
      polarOptions('current', [legacyCase.activeSecret], currentCase.now),
    )).rejects.toMatchObject({ name: 'HooklatchError', code: 'invalid-secret' });
  });

  test('canonical headers cannot be repaired by svix aliases', async () => {
    const id = requiredAuthenticatedId(currentCase);
    const timestampText = requiredSignatureTimestamp(currentCase);
    const signatureHeader = currentCase.signatureHeader;
    const idHeader = requiredHeader(currentCase, currentCase.idHeader);
    const timestampHeader = requiredHeader(currentCase, currentCase.timestampHeader);

    for (const [label, headers, reason] of [
      [
        'svix-only',
        {
          'Svix-Id': id,
          'Svix-Timestamp': timestampText,
          'Svix-Signature': currentCase.signatureValue,
        },
        'missing-signature',
      ],
      [
        'svix-timestamp-only',
        {
          [signatureHeader]: currentCase.signatureValue,
          [idHeader]: id,
          'Svix-Timestamp': timestampText,
        },
        'missing-timestamp',
      ],
      [
        'svix-signature-only',
        {
          [idHeader]: id,
          [timestampHeader]: timestampText,
          'Svix-Signature': currentCase.signatureValue,
        },
        'missing-signature',
      ],
      [
        'malformed-canonical-with-valid-svix',
        {
          ...currentCase.headers,
          [signatureHeader]: 'v1,@@@',
          'Svix-Signature': currentCase.signatureValue,
        },
        'malformed-signature',
      ],
    ] as const) {
      expectReason(
        `${currentCase.context} ${label}`,
        await verify({ rawBody: currentCase.body, headers }, optionsFor(currentCase)),
        reason,
      );
    }
  });

  test('binds the canonical layout and does not infer another signing recipe', async () => {
    const bodyOnlyToken = hmacToken(
      standardWebhooksKeyBytes(currentCase.activeSecret),
      currentCase.body,
      'base64',
    );

    const idHeader = requiredHeader(currentCase, currentCase.idHeader);
    const timestampHeader = requiredHeader(currentCase, currentCase.timestampHeader);

    expectReason(
      `${currentCase.context} body-only signed content`,
      await verify(
        {
          rawBody: currentCase.body,
          headers: {
            ...currentCase.headers,
            [currentCase.signatureHeader]: headerValueFor(
              currentCase,
              bodyOnlyToken,
              requiredSignatureTimestamp(currentCase),
            ),
          },
        },
        optionsFor(currentCase),
      ),
      'invalid-signature',
    );
    expectReason(
      `${currentCase.context} missing canonical id`,
      await verify(
        {
          rawBody: currentCase.body,
          headers: withoutHeader(currentCase.headers, idHeader),
        },
        optionsFor(currentCase),
      ),
      'missing-identity',
    );
    expectReason(
      `${currentCase.context} missing canonical timestamp`,
      await verify(
        {
          rawBody: currentCase.body,
          headers: withoutHeader(currentCase.headers, timestampHeader),
        },
        optionsFor(currentCase),
      ),
      'missing-timestamp',
    );
    expectReason(
      `${currentCase.context} alternate timestamp header`,
      await verify(
        {
          rawBody: currentCase.body,
          headers: {
            ...withoutHeader(currentCase.headers, timestampHeader),
            'X-Polar-Timestamp': requiredSignatureTimestamp(currentCase),
          },
        },
        optionsFor(currentCase),
      ),
      'missing-timestamp',
    );
  });

  test('enforces inclusive 300, explicit zero and MAC first in both modes', async () => {
    for (const case_ of [currentCase, legacyCase]) {
      const timestamp = requiredTimestamp(case_);

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

      expectSuccess(
        `${case_.context} explicit zero`,
        await verify(
          { rawBody: case_.body, headers: case_.headers },
          { ...optionsFor(case_), toleranceSeconds: 0 },
        ),
      );

      for (const [delta, reason] of [
        [1, 'timestamp-expired'],
        [-1, 'timestamp-future'],
      ] as const) {
        expectReason(
          `${case_.context} zero width now-offset=${delta}`,
          await verify(
            { rawBody: case_.body, headers: case_.headers },
            { ...optionsFor(case_), toleranceSeconds: 0, now: () => timestamp + delta },
          ),
          reason,
        );
      }

      for (const delta of [301, -301]) {
        expectReason(
          `${case_.context} bad MAC before stale now-offset=${delta}`,
          await verify(
            { rawBody: flipBodyByte(case_.body, 0), headers: case_.headers },
            { ...optionsFor(case_), now: () => timestamp + delta },
          ),
          'invalid-signature',
        );
      }
    }
  });

  test('rotation applies inside the selected mode only', async () => {
    for (const case_ of [currentCase, legacyCase]) {
      const timestampText = requiredSignatureTimestamp(case_);

      const retiredHeaders = {
        ...case_.headers,
        [case_.signatureHeader]: headerValueFor(
          case_,
          case_.retiredToken,
          timestampText,
        ),
      };

      expectSuccess(
        `${case_.context} selected-mode rotation`,
        await verify(
          { rawBody: case_.body, headers: retiredHeaders },
          optionsFor(case_, case_.rotationSecrets),
        ),
      );
      expectReason(
        `${case_.context} rotation removal`,
        await verify(
          { rawBody: case_.body, headers: retiredHeaders },
          optionsFor(case_, [case_.activeSecret]),
        ),
        'invalid-signature',
      );
      expectReason(
        `${case_.context} wrong secret`,
        await verify(
          { rawBody: case_.body, headers: retiredHeaders },
          optionsFor(case_, [case_.wrongSecret]),
        ),
        'invalid-signature',
      );
    }

    const currentRetiredHeaders = {
      ...currentCase.headers,
      [currentCase.signatureHeader]: headerValueFor(
        currentCase,
        currentCase.retiredToken,
        requiredSignatureTimestamp(currentCase),
      ),
    };

    expectReason(
      `${currentCase.context} current rotation cannot cross into legacy mode`,
      await verify(
        { rawBody: currentCase.body, headers: currentRetiredHeaders },
        polarOptions('legacy', currentCase.rotationSecrets, currentCase.now),
      ),
      'invalid-signature',
    );
  });

  test('vendor labels are not signed while endpoint keys remain separate', async () => {
    const standardCase = representative('standard-webhooks', 2);
    const secret = currentCase.activeSecret;

    expectSuccess(
      `${currentCase.context} same canonical bytes as standard-webhooks`,
      await verify(
        { rawBody: currentCase.body, headers: currentCase.headers },
        {
          provider: 'standard-webhooks',
          secrets: [secret],
          now: () => currentCase.now,
        },
      ),
    );
    expectReason(
      `${currentCase.context} separate endpoint secret`,
      await verify(
        { rawBody: currentCase.body, headers: currentCase.headers },
        polarOptions('current', [standardCase.activeSecret], currentCase.now),
      ),
      'invalid-signature',
    );
  });
});
