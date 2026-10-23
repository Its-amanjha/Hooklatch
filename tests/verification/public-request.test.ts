import { verifyRequest } from '../../src/index.js';
import { HooklatchError } from '../../src/errors.js';
import type { Provider as PublicProvider, VerifyOptions } from '../../src/types.js';

/** This historical fixture suite uses HMAC credentials; asymmetric coverage is separate. */
type Provider = Exclude<PublicProvider, 'fal'>;

import { fixtureBytes, fixtureOptions, loadFixture } from './helpers.js';
import type { FixtureCase } from './helpers.js';

function caseById(provider: Provider, id: string): FixtureCase {
  const found = loadFixture(provider).find((entry) => entry.id === id);

  if (!found) throw new Error(`Fixture missing: ${provider}/${id}`);

  return found;
}

function isHeaderList(value: string | readonly string[]): value is readonly string[] { return Array.isArray(value); }

function headersOf(case_: FixtureCase): Headers {
  const headers = new Headers();

  for (const [name, value] of Object.entries(case_.request.headers)) {
    if (isHeaderList(value)) {
      for (const item of value) headers.append(name, item);
    } else {
      headers.append(name, value);
    }
  }

  return headers;
}

function toRequest(case_: FixtureCase, bodyOverride?: Uint8Array): Request {
  return new Request('https://fixture.internal/hook', {
    method: 'POST',
    headers: headersOf(case_),
    body: new Uint8Array(bodyOverride ?? fixtureBytes(case_)),
  });
}

function toStreamRequest(chunks: readonly Uint8Array[], case_: FixtureCase): Request {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });

  const init: RequestInit & { duplex: 'half' } = { method: 'POST', headers: headersOf(case_), body: stream, duplex: 'half' };

  return new Request('https://fixture.internal/hook', init);
}

const stripeText = caseById('stripe', 'non-json-body-verified'); // body 'TERN', signed
const stripeHappy = caseById('stripe', 'happy-path');
const githubVector = caseById('github', 'reference-vector-2026-10-18');

describe('verifyRequest() — bounded Request reading on the public root', () => {
  test('verifies a fully consumed-once Request and returns the verified snapshot', async () => {
    const request = toRequest(githubVector);
    const result = await verifyRequest(request, fixtureOptions('github', githubVector));
    expect(result.ok).toBe(true);

    if (!result.ok) return;
    expect(result.provider).toBe('github');
    expect(result.rawBody).toEqual(fixtureBytes(githubVector));
    expect(new TextDecoder().decode(result.rawBody)).toBe('Hello, World!');
  });

  test('setup error: options are validated before any body is read', async () => {
    const request = toRequest(stripeText);
    await request.text(); // consume first so a body error would otherwise win
    const invalid = { provider: 'nope', secrets: ['whsec_tern_fixture_synthetic_00'], now: () => 4102444800 };
    // SAFETY: The invalid provider deliberately bypasses the static union to test runtime setup validation.
    await expect(verifyRequest(request, invalid as VerifyOptions))
      .rejects.toMatchObject({ name: 'HooklatchError', code: 'unknown-provider' });
  });

  test('setup error: missing secrets win over an already consumed body', async () => {
    const request = toRequest(stripeText);
    await request.text();
    const options: VerifyOptions = { provider: 'stripe', secrets: [], now: () => 4102444800 };
    await expect(verifyRequest(request, options))
      .rejects.toMatchObject({ name: 'HooklatchError', code: 'missing-secrets' });
  });

  test('already consumed bodies throw HooklatchError body-consumed', async () => {
    const request = toRequest(stripeText);
    await request.text();
    await expect(verifyRequest(request, fixtureOptions('stripe', stripeText)))
      .rejects.toMatchObject({ name: 'HooklatchError', code: 'body-consumed' });
  });

  test('locked-but-unread bodies are also setup errors', async () => {
    const request = toRequest(stripeHappy);
    request.body?.getReader(); // lock the stream without reading
    await expect(verifyRequest(request, fixtureOptions('stripe', stripeHappy)))
      .rejects.toBeInstanceOf(HooklatchError);
  });

  test('overflow through a stream without Content-Length fails as body-too-large', async () => {
    // The signature header is irrelevant here: size enforcement precedes signature checks.
    const request = toStreamRequest(
      [new TextEncoder().encode('TERN'), new TextEncoder().encode('X')],
      stripeText,
    );

    const result = await verifyRequest(request, { ...fixtureOptions('stripe', stripeText), maxBodyBytes: 4 });
    expect(result.ok).toBe(false);

    if (!result.ok) expect(result.reason).toBe('body-too-large');
  });

  test('bodies exactly at maxBodyBytes still verify', async () => {
    const request = toRequest(stripeText);
    const options = { ...fixtureOptions('stripe', stripeText), maxBodyBytes: 4 };
    const result = await verifyRequest(request, options);
    expect(result.ok).toBe(true);
  });
});
