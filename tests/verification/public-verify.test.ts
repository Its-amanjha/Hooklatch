import { verify } from '../../src/index.js';
import type {
  Provider, VerifyOptions, VerificationSuccess,
} from '../../src/types.js';
import {
  combinedHeader, fixtureBytes, fixtureOptions, loadFixture, representationsOf,
  UNSIGNED_OR_NULL,
} from './helpers.js';
import type { FixtureCase } from './helpers.js';

const PROVIDERS: readonly Provider[] = ['stripe', 'github', 'shopify', 'standard-webhooks'];

const ALL_REASONS: readonly string[] = [
  'missing-signature', 'malformed-signature', 'unsupported-scheme', 'invalid-signature',
  'missing-identity', 'missing-timestamp', 'timestamp-expired', 'timestamp-future',
  'body-too-large',
];

type VerifyResult = Awaited<ReturnType<typeof verify>>;

/** Bytes the case signs over, printed text for leak-safe message assertions. */
function readableBody(case_: FixtureCase): string {
  return Array.from(fixtureBytes(case_), (byte) =>
    byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '?').join('');
}

function signatureHeaderValues(case_: FixtureCase): readonly string[] {
  return Object.entries(case_.request.headers)
    .filter(([name]) => name.toLowerCase().endsWith('signature') || name.toLowerCase().includes('hmac'))
    .flatMap(([, value]) => (Array.isArray(value) ? value : [value]))
    .filter((value): value is string => value !== undefined);
}

function unsignedDeliveryName(provider: Provider): string {
  if (provider === 'github') return 'x-github-delivery';

  if (provider === 'shopify') return 'x-shopify-webhook-id';

  return '\u0000no-such-header\u0000';
}

function unsignedEventName(provider: Provider): string {
  if (provider === 'shopify') return 'x-shopify-event-id';

  return '\u0000no-such-header\u0000';
}

export function assertVerdict(
  provider: Provider, case_: FixtureCase, result: VerifyResult,
): VerificationSuccess | null {
  const expected = case_.expected;
  expect(result.ok).toBe(expected.ok);

  if (!result.ok) {
    const failure = result;
    expect(failure.provider).toBe(provider);
    expect(ALL_REASONS).toContain(failure.reason);
    expect(failure.reason).toBe(expected.reason);
    // Safe static failure messages: non-empty, never echoing secrets, raw signatures or body.
    expect(failure.message.length).toBeGreaterThan(0);
    const body = readableBody(case_);

    if (body.length > 0) expect(failure.message.includes(body)).toBe(false);

    for (const secret of case_.options.secrets) {
      expect(failure.message.includes(secret)).toBe(false);
    }

    for (const signature of signatureHeaderValues(case_)) {
      if (signature.length === 0) continue; // an empty header value matches everything trivially
      expect(failure.message.includes(signature)).toBe(false);
    }

    return null;
  }

  const success = result;
  const pinned = expected.identity;
  expect(success.provider).toBe(provider);
  expect(success.rawBody).toEqual(fixtureBytes(case_));

  if (pinned) {
    expect([...success.identity.authenticatedFields].sort())
      .toEqual([...pinned.authenticatedFields].sort());
    expect(success.identity.timestamp).toBe(pinned.timestamp);

    for (const field of ['deliveryId', 'eventId'] as const) {
      const pinnedValue = pinned[field];

      if (pinnedValue === UNSIGNED_OR_NULL) {
        const headerName = field === 'deliveryId' ? unsignedDeliveryName(provider) : unsignedEventName(provider);
        const headerValue = combinedHeader(case_, headerName);
        expect(success.identity[field]).toBe(headerValue ?? null);
      } else {
        expect(success.identity[field]).toBe(pinnedValue);
      }
    }
  }

  return success;
}

export async function runCase(provider: Provider, case_: FixtureCase): Promise<VerifyResult> {
  const representations = representationsOf(case_);

  const first = await verify(
    { rawBody: fixtureBytes(case_), headers: representations[0]! },
    fixtureOptions(provider, case_),
  );

  assertVerdict(provider, case_, first);

  // Representation parity: identical verdicts across record / tuple-list / Headers.
  for (const representation of representations.slice(1)) {
    const result = await verify(
      { rawBody: fixtureBytes(case_), headers: representation },
      fixtureOptions(provider, case_),
    );

    const firstOk = first.ok;
    expect(result.ok).toBe(firstOk);

    if (result.ok && firstOk) {
      const firstSuccess = first;
      expect(result.identity).toEqual(firstSuccess.identity);
      expect(result.rawBody).toEqual(firstSuccess.rawBody);
    } else if (!result.ok && !firstOk) {
      expect(result.reason).toBe(first.reason);
    }
  }

  return first;
}



describe.each(PROVIDERS)('provider %s — contract-fixture requests via verify()', (provider) => {
  const cases = loadFixture(provider);
  test.each(cases)('$id', async (case_) => {
    await runCase(provider, case_);
  });
});

describe('input snapshot semantics (mutation after the call, before awaiting)', () => {
  const SNAPSHOT_CASES: readonly (readonly [Provider, string])[] = [
    ['stripe', 'happy-path'],
    ['github', 'reference-vector-2026-10-18'],
    ['shopify', 'happy-path'],
    ['standard-webhooks', 'local-anchor'],
  ];

  test.each(SNAPSHOT_CASES)(
    '%s: caller byte mutations during awaits do not change the verified snapshot',
    async (provider, caseId) => {
      const case_ = loadFixture(provider).find((entry) => entry.id === caseId);

      if (!case_) throw new Error(`Snapshot fixture missing: ${provider}/${caseId}`);
      const bytes = fixtureBytes(case_);
      const original = Uint8Array.from(bytes);
      const pending = verify({ rawBody: bytes, headers: case_.request.headers }, fixtureOptions(provider, case_));
      bytes[0] = bytes[0]! ^ 0xff;
      const result = await pending;
      expect(result.ok).toBe(true);

      if (!result.ok) return;
      expect(result.rawBody).toEqual(original);
    },
  );

  test.each(SNAPSHOT_CASES)(
    '%s: caller secret mutations during awaits do not change the verdict',
    async (provider, caseId) => {
      const case_ = loadFixture(provider).find((entry) => entry.id === caseId);

      if (!case_) throw new Error(`Snapshot fixture missing: ${provider}/${caseId}`);
      const secrets = [...case_.options.secrets];

      const options: VerifyOptions = {
        ...fixtureOptions(provider, case_),
        secrets,
      };

      const pending = verify({ rawBody: fixtureBytes(case_), headers: case_.request.headers }, options);
      secrets[0] = 'whsec_mutated_after_call_00';
      const result = await pending;
      expect(result.ok).toBe(case_.expected.ok);
    },
  );
});
