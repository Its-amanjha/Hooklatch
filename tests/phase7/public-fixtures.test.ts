import { createVerifier, verify, verifyRequest } from '../../src/index.js';
import type {
  HeaderInput, VerificationResult, VerificationSuccess,
} from '../../src/types.js';
import type { FixtureCase, FixtureExpected, FixtureProvider } from '../verification/helpers.js';
import { fixtureBytes, fixtureOptions, loadFixture, representationsOf } from '../verification/helpers.js';

/**
 * Phase 7 Stage B — public fixture replay for Grafana and Polar (GLM).
 *
 * Every corpus row, from tests/fixtures/grafana.json (50) and polar.json (40),
 * is replayed through the public verify / verifyRequest / createVerifier entry
 * points. Record and tuple representations preserve outer header whitespace;
 * the WHATWG Headers representation may trim, so rows that distinguish the two
 * carry a webHeadersExpected override which also governs the verifyRequest view.
 *
 * This base registers 16 providers and carries no Grafana/Polar option types,
 * so all replay expectations are contract-first RED by design:
 * normalizeOptions rejects the literal provider name with the public
 * 'unknown-provider' code before any provider code runs. Assertions become
 * exact once Codex's Stage B integration registers both providers. No casts,
 * fallback outcomes, partial reasons or flattened option dictionaries are used
 * here or in helpers.ts.
 */

const GRAFANA_CASES = loadFixture('grafana');
const POLAR_CASES = loadFixture('polar');

interface ReplayView {
  readonly label: 'record' | 'tuple' | 'whatwg-headers';
  readonly headers: HeaderInput;
  readonly expected: FixtureExpected;
}

/** The three header representations the contract declares equivalent. */
function replayViews(case_: FixtureCase): readonly ReplayView[] {
  const representations = representationsOf(case_);

  return [
    { label: 'record', headers: representations[0]!, expected: case_.expected },
    { label: 'tuple', headers: representations[1]!, expected: case_.expected },
    { label: 'whatwg-headers', headers: representations[2]!, expected: case_.webHeadersExpected ?? case_.expected },
  ];
}

function isVerifySuccess(result: VerificationResult): result is VerificationSuccess {
  return result.ok;
}

/** Printable rendering of signed bytes for leak-safe message checks. */
function readableBody(rawBody: Uint8Array): string {
  return Array.from(rawBody, (byte) => (byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '?')).join('');
}

function assertOutcome(provider: FixtureProvider, case_: FixtureCase, expected: FixtureExpected, rawBody: Uint8Array, result: VerificationResult): void {
  if (expected.ok) {
    if (!isVerifySuccess(result)) {
      throw new Error(`Expected success for ${provider}/${case_.id}, got failure reason ${result.reason}`);
    }

    expect(result.provider).toBe(provider);
    expect(result.rawBody).toEqual(rawBody);

    const pinned = expected.identity;

    if (pinned === undefined) throw new Error(`Missing expected identity pin for ${provider}/${case_.id}`);

    expect([...result.identity.authenticatedFields].sort()).toEqual([...pinned.authenticatedFields].sort());
    expect(result.identity.deliveryId).toBe(pinned.deliveryId);
    expect(result.identity.eventId).toBe(pinned.eventId);
    expect(result.identity.timestamp).toBe(pinned.timestamp);

    return;
  }

  if (isVerifySuccess(result)) {
    throw new Error(`Expected failure for ${provider}/${case_.id}, got ok`);
  }

  expect(result.provider).toBe(provider);
  expect(result.reason).toBe(expected.reason);
  expect(result.message.length).toBeGreaterThan(0);

  const bodyText = readableBody(rawBody);

  if (bodyText.length > 0) expect(result.message.includes(bodyText)).toBe(false);

  for (const secret of case_.options.secrets) {
    expect(result.message.includes(secret)).toBe(false);
  }
}

async function verifyViews(provider: FixtureProvider, case_: FixtureCase): Promise<void> {
  const options = fixtureOptions(provider, case_);

  for (const view of replayViews(case_)) {
    const rawBody = fixtureBytes(case_);
    const result = await verify({ rawBody, headers: view.headers }, options);

    assertOutcome(provider, case_, view.expected, rawBody, result);
  }
}

const WEBHOOK_URL = 'https://hooklatch.test/webhook';

async function verifyRequestCase(provider: FixtureProvider, case_: FixtureCase): Promise<void> {
  const options = fixtureOptions(provider, case_);
  const views = replayViews(case_);
  const rawBody = fixtureBytes(case_);
  const webSource = views[2]!.headers;

  if (!(webSource instanceof Headers)) throw new Error('The third fixture representation must be WHATWG Headers');

  // The WHATWG node trims outer header whitespace exactly like the Headers view.
  const request = new Request(WEBHOOK_URL, { method: 'POST', headers: webSource, body: new Uint8Array(rawBody) });
  const result = await verifyRequest(request, options);

  assertOutcome(provider, case_, views[2]!.expected, rawBody, result);
}

async function snapshotCase(provider: FixtureProvider, case_: FixtureCase): Promise<void> {
  const options = fixtureOptions(provider, case_);
  const views = replayViews(case_);
  const verifier = createVerifier(options);

  // Same correlated options object decodes the direct call and the factory call.
  const directBytes = fixtureBytes(case_);
  const direct = await verify({ rawBody: directBytes, headers: views[0]!.headers }, options);

  const recordBytes = fixtureBytes(case_);
  const recordResult = await verifier({ rawBody: recordBytes, headers: views[0]!.headers });

  assertOutcome(provider, case_, views[0]!.expected, recordBytes, recordResult);
  expect(recordResult).toEqual(direct);

  const repeatBytes = fixtureBytes(case_);
  const repeatResult = await verifier({ rawBody: repeatBytes, headers: views[0]!.headers });

  assertOutcome(provider, case_, views[0]!.expected, repeatBytes, repeatResult);
  expect(repeatResult).toEqual(recordResult);

  const webBytes = fixtureBytes(case_);
  const webResult = await verifier({ rawBody: webBytes, headers: views[2]!.headers });

  assertOutcome(provider, case_, views[2]!.expected, webBytes, webResult);
}

describe('Phase 7 public fixture inventory (contract-first)', () => {
  test('grafana enumerates all 50 rows with unique ids and local provenance', () => {
    expect(GRAFANA_CASES).toHaveLength(50);
    expect(new Set(GRAFANA_CASES.map((case_) => case_.id)).size).toBe(GRAFANA_CASES.length);
    expect(GRAFANA_CASES.every((case_) => case_.provenance.class === 'local')).toBe(true);
  });

  test('polar enumerates all 40 rows with unique ids and local provenance', () => {
    expect(POLAR_CASES).toHaveLength(40);
    expect(new Set(POLAR_CASES.map((case_) => case_.id)).size).toBe(POLAR_CASES.length);
    expect(POLAR_CASES.every((case_) => case_.provenance.class === 'local')).toBe(true);
  });

  test('every grafana row carries typed providerOptions (mode correlation on load)', () => {
    expect(GRAFANA_CASES.every((case_) => case_.options.providerOptions !== undefined)).toBe(true);
  });

  test('three grafana rows and one polar row pin WHATWG Headers overrides', () => {
    expect(GRAFANA_CASES.filter((case_) => case_.webHeadersExpected !== undefined)).toHaveLength(3);
    expect(POLAR_CASES.filter((case_) => case_.webHeadersExpected !== undefined)).toHaveLength(1);
  });

  test('grafana boundary rows omit toleranceSeconds; zero-width rows pin 0', () => {
    const plus300 = GRAFANA_CASES.find((case_) => case_.id === 'boundary-plus300-ok');
    const expiredBeyond = GRAFANA_CASES.find((case_) => case_.id === 'boundary-minus301-expired');

    if (plus300 === undefined || expiredBeyond === undefined) throw new Error('Missing grafana boundary fixture rows');

    expect(fixtureOptions('grafana', plus300).toleranceSeconds).toBeUndefined();
    expect(fixtureOptions('grafana', expiredBeyond).toleranceSeconds).toBeUndefined();
    expect(GRAFANA_CASES.filter((case_) => case_.options.toleranceSeconds === 0)).toHaveLength(3);
  });

  test('polar boundary rows omit toleranceSeconds; zero-width rows pin 0', () => {
    const plus300 = POLAR_CASES.find((case_) => case_.id === 'boundary-plus300-ok');
    const expiredBeyond = POLAR_CASES.find((case_) => case_.id === 'boundary-minus301-expired');

    if (plus300 === undefined || expiredBeyond === undefined) throw new Error('Missing polar boundary fixture rows');

    expect(fixtureOptions('polar', plus300).toleranceSeconds).toBeUndefined();
    expect(fixtureOptions('polar', expiredBeyond).toleranceSeconds).toBeUndefined();
    expect(POLAR_CASES.filter((case_) => case_.options.toleranceSeconds === 0)).toHaveLength(3);
  });
});

describe.each([['grafana', GRAFANA_CASES], ['polar', POLAR_CASES]] as const)('%s public replay', (provider, cases) => {
  test.each(cases)('$id · verify across record, tuple and WHATWG Headers views', async (case_) => {
    await verifyViews(provider, case_);
  });

  test.each(cases)('$id · verifyRequest WHATWG override view', async (case_) => {
    await verifyRequestCase(provider, case_);
  });

  test.each(cases)('$id · createVerifier snapshot behavior and correlated options', async (case_) => {
    await snapshotCase(provider, case_);
  });
});
