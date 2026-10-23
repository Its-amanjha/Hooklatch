import { verify } from '../../src/index.js';
import type { Provider as PublicProvider } from '../../src/types.js';

/** This historical fixture suite uses HMAC credentials; asymmetric coverage is separate. */
type Provider = Exclude<PublicProvider, 'fal'>;

import { fixtureBytes, fixtureOptions, loadFixture } from './helpers.js';
import type { FixtureCase } from './helpers.js';

const HAPPY_CASES: readonly (readonly [Provider, string])[] = [
  ['stripe', 'happy-path'],
  ['github', 'reference-vector-2026-10-18'],
  ['shopify', 'happy-path'],
  ['standard-webhooks', 'local-anchor'],
];

function caseById(provider: Provider, id: string): FixtureCase {
  const found = loadFixture(provider).find((entry) => entry.id === id);

  if (!found) throw new Error(`Fixture missing: ${provider}/${id}`);

  return found;
}

describe('no network activity inside verification', () => {
  const originalFetch = globalThis.fetch;

  beforeAll(() => {
    globalThis.fetch = async (): Promise<Response> => {
      throw new Error('Network access inside verification is forbidden.');
    };
  });

  afterAll(() => {
    globalThis.fetch = originalFetch;
  });

  test.each(HAPPY_CASES)('%s: verifying a published/local vector never reaches the network', async (provider, caseId) => {
    const case_ = caseById(provider, caseId);

    const result = await verify(
      { rawBody: fixtureBytes(case_), headers: case_.request.headers },
      fixtureOptions(provider, case_),
    );

    // If an implementation attempted a fetch this would not be a clean verify.
    expect(result.ok).toBe(true);
  });
});
