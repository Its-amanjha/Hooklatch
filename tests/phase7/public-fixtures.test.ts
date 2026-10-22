import { readFileSync } from 'node:fs';

import { createVerifier, verify, verifyRequest } from '../../src/index.js';
import type { HeaderInput, VerificationResult, VerifyOptions } from '../../src/types.js';
import type { FixtureCase } from '../verification/helpers.js';
import { fixtureBytes, isFixtureFile, representationsOf } from '../verification/helpers.js';

/**
 * Phase 7 GLM Stage B — public fixture replay for Grafana and Polar.
 *
 * Replays all 50 Grafana + 40 Polar cases through verify / verifyRequest /
 * createVerifier, across record, tuple and WHATWG Headers representations.
 *
 * Base has 16 providers and no Grafana/Polar option types. The correlated
 * literal branches below are RED at this base by design; they become valid once
 * Codex adds the two providers and their option types in Stage B. Do not
 * replace them with casts or flattened dictionaries.
 */

function loadCases(fileName: string): readonly FixtureCase[] {
  const parsed: unknown = JSON.parse(readFileSync(new URL(`../fixtures/${fileName}`, import.meta.url), 'utf8'));

  if (!isFixtureFile(parsed)) throw new Error(`Invalid fixture file ${fileName}`);

  return parsed.cases;
}

const GRAFANA_CASES = loadCases('grafana.json');
const POLAR_CASES = loadCases('polar.json');

const ENTRYPOINTS = ['verify', 'verifyRequest', 'createVerifier'] as const;

type EntryPoint = (typeof ENTRYPOINTS)[number];

function casesFor(provider: 'grafana' | 'polar'): readonly FixtureCase[] {
  return provider === 'grafana' ? GRAFANA_CASES : POLAR_CASES;
}

function firstPositive(provider: 'grafana' | 'polar'): FixtureCase {
  const fixture = casesFor(provider).find((entry) => entry.expected.ok);

  if (fixture === undefined) throw new Error(`Missing positive fixture for ${provider}`);

  return fixture;
}

// Correlated literal branches: the provider literal determines the options shape.
// RED at this base: 'grafana' and 'polar' are not yet members of Provider and
// VerifyOptions has no providerOptions field. These branches become valid once
// Codex adds both in Stage B.
type GrafanaFixtureOptions = {
  provider: 'grafana';
  secrets: readonly string[];
  now: () => number;
  toleranceSeconds?: number;
  maxBodyBytes?: number;
  providerOptions: unknown;
};

type PolarFixtureOptions = {
  provider: 'polar';
  secrets: readonly string[];
  now: () => number;
  toleranceSeconds?: number;
  maxBodyBytes?: number;
  providerOptions?: unknown;
};

function optionsFor(provider: 'grafana' | 'polar', fixture: FixtureCase): GrafanaFixtureOptions | PolarFixtureOptions {
  if (provider === 'grafana') {
    const options: GrafanaFixtureOptions = {
      provider: 'grafana',
      secrets: [...fixture.options.secrets],
      now: () => fixture.options.now,
      providerOptions: fixture.options.providerOptions,
    };

    if (fixture.options.toleranceSeconds !== undefined) options.toleranceSeconds = fixture.options.toleranceSeconds;

    if (fixture.options.maxBodyBytes !== undefined) options.maxBodyBytes = fixture.options.maxBodyBytes;

    return options;
  }

  const options: PolarFixtureOptions = {
    provider: 'polar',
    secrets: [...fixture.options.secrets],
    now: () => fixture.options.now,
  };

  if (fixture.options.providerOptions !== undefined) options.providerOptions = fixture.options.providerOptions;

  if (fixture.options.toleranceSeconds !== undefined) options.toleranceSeconds = fixture.options.toleranceSeconds;

  if (fixture.options.maxBodyBytes !== undefined) options.maxBodyBytes = fixture.options.maxBodyBytes;

  // SAFETY: same invariant as above — fixture validation already checked types.
  return options;
}

function webHeaders(input: HeaderInput): Headers {
  if (input instanceof Headers) return new Headers(input);

  const headers = new Headers();

  if (Array.isArray(input)) {
    for (const [name, value] of input) headers.append(name, value);
  } else {
    for (const [name, value] of Object.entries(input)) {
      if (value === undefined) continue;

      if (Array.isArray(value)) {
        for (const part of value) headers.append(name, part);
      } else headers.append(name, value);
    }
  }

  return headers;
}

async function invoke(entrypoint: EntryPoint, rawBody: Uint8Array, headers: HeaderInput, options: VerifyOptions): Promise<VerificationResult> {
  if (entrypoint === 'verify') return verify({ rawBody, headers }, options);

  if (entrypoint === 'createVerifier') return createVerifier(options)({ rawBody, headers });

  return verifyRequest(new Request('https://hooklatch.test/webhook', {
    method: 'POST', headers: webHeaders(headers), body: new Uint8Array(rawBody),
  }), options);
}

describe('Phase 7 public fixture enumeration', () => {
  test('grafana has 50 cases with unique ids', () => {
    expect(GRAFANA_CASES).toHaveLength(50);
    expect(new Set(GRAFANA_CASES.map((entry) => entry.id)).size).toBe(GRAFANA_CASES.length);
  });

  test('polar has 40 cases with unique ids', () => {
    expect(POLAR_CASES).toHaveLength(40);
    expect(new Set(POLAR_CASES.map((entry) => entry.id)).size).toBe(POLAR_CASES.length);
  });
});

describe.each(['grafana', 'polar'] as const)('%s public fixture replay', (provider) => {
  const fixtures = provider === 'grafana' ? GRAFANA_CASES : POLAR_CASES;

  describe.each(ENTRYPOINTS)('%s', (entrypoint) => {
    test.each(fixtures)('$id has exact outcomes across record, tuples and Headers', async (fixture) => {
      const body = fixtureBytes(fixture);

      for (const headers of representationsOf(fixture)) {
        const expected = headers instanceof Headers ? (fixture.webHeadersExpected ?? fixture.expected) : fixture.expected;
        const result = await invoke(entrypoint, body, headers, optionsFor(provider, fixture));

        expect(result.ok).toBe(expected.ok);
        expect(result.provider).toBe(provider);

        if (result.ok) {
          expect(fixture.expected.identity).toBeDefined();
          expect(result.identity).toEqual(expected.identity ?? fixture.expected.identity);
          expect(result.rawBody).toEqual(body);
        } else {
          expect(result.reason).toBe(expected.reason);
        }
      }
    });
  });

  test('createVerifier uses the same correlated options as verify', async () => {
    const fixture = firstPositive(provider);
    const body = fixtureBytes(fixture);
    const options = optionsFor(provider, fixture);

    const direct = await verify({ rawBody: body, headers: fixture.request.headers }, options);
    const viaFactory = await createVerifier(options)({ rawBody: body, headers: fixture.request.headers });

    expect(direct).toEqual(viaFactory);
  });
});

describe('Phase 7 signed identity and raw bytes', () => {
  for (const provider of ['grafana', 'polar'] as const) {
    const fixture = firstPositive(provider);

    test(`${provider}: success exposes every identity field and raw body`, async () => {
      const body = fixtureBytes(fixture);
      const result = await verify({ rawBody: body, headers: fixture.request.headers }, optionsFor(provider, fixture));

      expect(result.ok).toBe(true);

      if (result.ok) {
        const expected = fixture.expected.identity;

        if (expected === undefined) throw new Error('Missing expected identity');

        expect(result.identity.deliveryId).toBe(expected.deliveryId);
        expect(result.identity.eventId).toBe(expected.eventId);
        expect(result.identity.timestamp).toBe(expected.timestamp);
        expect(result.identity.authenticatedFields).toEqual(expected.authenticatedFields);
        expect(result.rawBody).toEqual(body);
        expect(result.rawBody.byteLength).toBe(body.byteLength);
      }
    });
  }
});

describe('Phase 7 omitted tolerance uses real defaults', () => {
  test('grafana timestamped omits tolerance so the 300-second default applies', async () => {
    const fixture = GRAFANA_CASES.find((entry) => entry.expected.identity?.timestamp !== null && entry.expected.identity?.timestamp !== undefined);

    if (fixture === undefined) throw new Error('Missing timestamped grafana fixture');

    const identity = fixture.expected.identity;

    if (identity?.timestamp === null || identity?.timestamp === undefined) throw new Error('Missing grafana timestamp');

    const timestamp = identity.timestamp;
    const options = optionsFor('grafana', fixture);
    // Ensure tolerance is omitted to exercise the real default.
    // SAFETY: the cast targets an optional numeric field on a named owner type;
    // deleting it exercises the omitted-tolerance default path.
    delete (options as { toleranceSeconds?: number }).toleranceSeconds;

    const atBoundary = await verify({ rawBody: fixtureBytes(fixture), headers: fixture.request.headers }, { ...options, now: () => timestamp + 300 });
    const pastBoundary = await verify({ rawBody: fixtureBytes(fixture), headers: fixture.request.headers }, { ...options, now: () => timestamp + 301 });

    expect(atBoundary.ok).toBe(true);
    expect(pastBoundary.ok).toBe(false);

    if (!pastBoundary.ok) expect(pastBoundary.reason).toBe('timestamp-expired');
  });
});

// (imports consolidated above)
