import { HooklatchError, verify, verifyRequest, createVerifier } from '../../src/index.js';
import type { Provider as PublicProvider, VerifyOptions } from '../../src/types.js';

/** This historical fixture suite uses HMAC credentials; asymmetric coverage is separate. */
type Provider = Exclude<PublicProvider, 'fal'>;

import { fixtureBytes, fixtureOptions, loadFixture } from './helpers.js';
import type { FixtureCase } from './helpers.js';

const stripeHappy: FixtureCase = loadFixture('stripe').find((entry) => entry.id === 'happy-path')!;
const swLocal: FixtureCase = loadFixture('standard-webhooks').find((entry) => entry.id === 'local-anchor')!;

function requestOf(case_: FixtureCase, provider?: Provider) {
  return {
    request: { rawBody: fixtureBytes(case_), headers: case_.request.headers },
    options: fixtureOptions(provider ?? 'stripe', case_),
  };
}

function expectCreateThrows(options: VerifyOptions, expectedCode: string): void {
  expect(() => createVerifier(options)).toThrow(HooklatchError);

  try {
    createVerifier(options);
  } catch (error) {
    if (!(error instanceof HooklatchError)) throw error;
    expect(error.code).toBe(expectedCode);
  }
}

describe('createVerifier() — preconfigured verification on the public root', () => {
  test('verifies with options applied once', async () => {
    if (!stripeHappy) throw new Error('Fixture missing');
    const { options, request } = requestOf(stripeHappy);
    const preconfigured = createVerifier(options);
    const result = await preconfigured(request);
    expect(result.ok).toBe(true);

    if (!result.ok) return;
    expect(result.provider).toBe('stripe');
    expect(result.rawBody).toEqual(fixtureBytes(stripeHappy));
    expect(result.identity.timestamp).toBe(stripeHappy.options.now);
  });

  test('rejects unknown providers (setup error, before any input is read)', () => {
    // SAFETY: Deliberately invalid provider exercises runtime validation beyond the public union.
    expectCreateThrows({ provider: 'nope', secrets: ['x'] } as never, 'unknown-provider');
    expectCreateThrows({ provider: 'stripe', secrets: [] }, 'missing-secrets');
    expectCreateThrows({
      provider: 'stripe',
      secrets: ['whsec_tern_fixture_synthetic_00', ''],
    }, 'invalid-secret');
  });

  test.each([
    ['toleranceSeconds NaN', { provider: 'stripe', secrets: ['whsec_x'], toleranceSeconds: Number.NaN }],
    ['toleranceSeconds negative', { provider: 'stripe', secrets: ['whsec_x'], toleranceSeconds: -1 }],
    ['toleranceSeconds Infinity', { provider: 'stripe', secrets: ['whsec_x'], toleranceSeconds: Number.POSITIVE_INFINITY }],
    ['maxBodyBytes zero', { provider: 'stripe', secrets: ['whsec_x'], maxBodyBytes: 0 }],
    ['maxBodyBytes negative', { provider: 'stripe', secrets: ['whsec_x'], maxBodyBytes: -1 }],
    ['now non-function', { provider: 'stripe', secrets: ['whsec_x'], now: 4102444800 }],
  ])('invalid options: %s (setup error, never a silent verify)', (_title, options) => {
    // SAFETY: The table intentionally includes an invalid clock to verify runtime rejection.
    expectCreateThrows(options as VerifyOptions, 'invalid-options');
  });
});

describe('verify() — option and secret configuration gates on the public root', () => {
  const { request } = requestOf(swLocal, 'standard-webhooks');

  test('rejects missing and invalid secrets before verification', async () => {
    await expect(verify(request, { provider: 'standard-webhooks', secrets: [], now: () => 1614265330 }))
      .rejects.toMatchObject({ code: 'missing-secrets' });
    await expect(
      verify(request, {
        provider: 'standard-webhooks',
        secrets: ['whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=', ''],
        now: () => 1614265330,
      }),
    ).rejects.toMatchObject({ code: 'invalid-secret' });
  });

  test('rejects invalid tolerance and body limits', async () => {
    await expect(
      verify(request, { provider: 'standard-webhooks', secrets: ['whsec_'], toleranceSeconds: -5, now: () => 1614265330 }),
    ).rejects.toMatchObject({ code: 'invalid-options' });
    await expect(
      verifyRequest(new Request('https://fixture.internal/hook', { method: 'POST', body: '' }), {
        provider: 'standard-webhooks',
        secrets: ['whsec_'],
        maxBodyBytes: Number.NaN,
      }),
    ).rejects.toMatchObject({ code: 'invalid-options' });
  });
});
