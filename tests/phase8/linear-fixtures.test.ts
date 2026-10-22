import { createVerifier, verify, verifyRequest } from '../../src/index.js';
import { diagnose } from '../../src/diagnostics/index.js';
import type { VerificationResult } from '../../src/types.js';
import { fixtureBytes, fixtureOptions, loadFixture, representationsOf } from '../verification/helpers.js';
import type { FixtureExpected } from '../verification/helpers.js';

const CASES = loadFixture('linear');
const MESSAGE_CANARY = 'hooklatch-private-linear-diagnostic-message';

function assertResult(result: VerificationResult, expected: FixtureExpected, bytes: Uint8Array): void {
  expect(result.provider).toBe('linear');
  expect(result.ok).toBe(expected.ok);

  if (result.ok) {
    expect(result.rawBody).toEqual(bytes);
    expect(result.identity).toEqual(expected.identity);

    return;
  }

  expect(result.reason).toBe(expected.reason);
  const diagnostic = diagnose({ ...result, message: MESSAGE_CANARY }, { verbose: true });
  expect(diagnostic.provider).toBe('linear');
  expect(diagnostic.code).toBe(expected.reason);
  expect(diagnostic.detail?.expectedHeaders).toEqual(['Linear-Signature']);
  expect(diagnostic.detail?.grammar).toContain('Signature authentication only');
  expect(JSON.stringify(diagnostic)).not.toContain(MESSAGE_CANARY);
}

test.each(CASES)('$id replays through the public APIs with exact representation outcomes', async (fixture) => {
  const bytes = fixtureBytes(fixture);
  const options = fixtureOptions('linear', fixture);
  const prepared = createVerifier(options);
  const views = representationsOf(fixture);

  for (const [index, headers] of views.entries()) {
    const expected = index === 2 ? fixture.webHeadersExpected ?? fixture.expected : fixture.expected;
    const request = { rawBody: bytes, headers };
    assertResult(await verify(request, options), expected, bytes);
    assertResult(await prepared(request), expected, bytes);
  }

  const webHeaders = views[2];

  if (!(webHeaders instanceof Headers)) throw new Error('Missing WHATWG fixture view.');

  const request = new Request('https://hooklatch.test/webhook', {
    method: 'POST', body: new Uint8Array(bytes), headers: webHeaders,
  });

  assertResult(await verifyRequest(request, options), fixture.webHeadersExpected ?? fixture.expected, bytes);
});

test('Linear public replay includes the entire reviewed corpus and normalization overrides', () => {
  expect(CASES).toHaveLength(31);
  expect(new Set(CASES.map((fixture) => fixture.id)).size).toBe(CASES.length);
  expect(CASES.filter((fixture) => fixture.webHeadersExpected !== undefined)).toHaveLength(2);
});
