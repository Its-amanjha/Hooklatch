import { HooklatchError, verify, verifyRequest, createVerifier } from '../../src/index.js';
import type { Provider, VerifyOptions, WebhookRequest } from '../../src/types.js';
import { fixtureBytes, loadFixture } from './helpers.js';
import type { FixtureCase } from './helpers.js';

const stripeHappy: FixtureCase = loadFixture('stripe').find((entry) => entry.id === 'happy-path')!;
const swLocal: FixtureCase = loadFixture('standard-webhooks').find((entry) => entry.id === 'local-anchor')!;

function requestOf(case_: FixtureCase, provider?: Provider): { request: WebhookRequest; options: VerifyOptions } {
  return {
    request: { rawBody: fixtureBytes(case_), headers: case_.request.headers },
    options: {
      provider: provider ?? 'stripe',
      secrets: case_.options.secrets,
      ...(case_.options.toleranceSeconds === undefined ? {} : { toleranceSeconds: case_.options.toleranceSeconds }),
      now: () => case_.options.now,
    },
  };
}

function expectCreateThrows(options: VerifyOptions, expectedCode: string): void {
  let thrown: unknown = null;
  try {
    createVerifier(options);
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(HooklatchError);
  if (thrown instanceof HooklatchError) expect(thrown.code).toBe(expectedCode);
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
    expectCreateThrows({ provider: 'nope', secrets: ['x'] } as unknown as VerifyOptions, 'unknown-provider');
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
