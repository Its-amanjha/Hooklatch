import { readFileSync } from 'node:fs';
import { createVerifier, HooklatchError, verify, verifyRequest } from '../../src/index.js';
import type { FixtureCase } from './helpers.js';
import { fixtureBytes, fixtureOptions, representationsOf } from './helpers.js';

/**
 * Phase 2 preset fixture matrix on the public root. The shared fixture loader
 * deliberately excludes the preset providers ("legacy fixture files only"),
 * so this file validates `clerk.json` and `svix.json` directly with its own
 * named guards instead of editing shared test code.
 *
 * The preset matrix additionally requires: every failure pins exactly one
 * `expected.reason`, and every success pins the full authenticated identity
 * (presets authenticate eventId and timestamp; deliveryId stays null).
 */

type PresetProvider = 'clerk' | 'svix';

function isString(value: unknown): value is string { return typeof value === 'string'; }

function isHeaderValue(value: unknown): value is string | readonly string[] {
  return isString(value) || (Array.isArray(value) && value.every(isString));
}

function isPresetCase(value: unknown): value is FixtureCase {
  if (typeof value !== 'object' || value === null) return false;

  if (!('id' in value) || !isString(value.id)) return false;

  if (!('request' in value) || typeof value.request !== 'object' || value.request === null) return false;

  if (!('bodyBase64' in value.request) || !isString(value.request.bodyBase64)) return false;

  if (!('headers' in value.request) || typeof value.request.headers !== 'object' || value.request.headers === null) return false;

  if (!Object.values(value.request.headers).every(isHeaderValue)) return false;

  if (!('options' in value) || typeof value.options !== 'object' || value.options === null) return false;

  if (!('secrets' in value.options) || !Array.isArray(value.options.secrets) || !value.options.secrets.every(isString)) return false;

  if (!('now' in value.options) || typeof value.options.now !== 'number') return false;

  if ('toleranceSeconds' in value.options && typeof value.options.toleranceSeconds !== 'number') return false;

  if ('maxBodyBytes' in value.options && typeof value.options.maxBodyBytes !== 'number') return false;

  if (!('expected' in value) || typeof value.expected !== 'object' || value.expected === null) return false;

  if (!('ok' in value.expected) || typeof value.expected.ok !== 'boolean') return false;

  if (!value.expected.ok) {
    if (!('reason' in value.expected) || !isString(value.expected.reason)) return false;
  } else {
    if (!('identity' in value.expected) || typeof value.expected.identity !== 'object' || value.expected.identity === null) return false;

    if (!('deliveryId' in value.expected.identity) || typeof value.expected.identity.deliveryId !== 'string' && value.expected.identity.deliveryId !== null) return false;

    if (!('eventId' in value.expected.identity) || !isString(value.expected.identity.eventId)) return false;

    if (!('timestamp' in value.expected.identity) || typeof value.expected.identity.timestamp !== 'number') return false;

    if (!('authenticatedFields' in value.expected.identity) || !Array.isArray(value.expected.identity.authenticatedFields) || !value.expected.identity.authenticatedFields.every(isString)) return false;
  }

  if (!('provenance' in value) || typeof value.provenance !== 'object' || value.provenance === null) return false;

  if (!('class' in value.provenance) || (value.provenance.class !== 'reference' && value.provenance.class !== 'local')) return false;

  if (!('source' in value.provenance) || !isString(value.provenance.source)) return false;

  if ('commit' in value.provenance && !isString(value.provenance.commit)) return false;

  if ('fetched' in value.provenance && !isString(value.provenance.fetched)) return false;

  if ('notes' in value && !isString(value.notes)) return false;

  return true;
}

interface PresetFixtureFile { readonly cases: readonly FixtureCase[] }

function isPresetFixtureFile(value: unknown): value is PresetFixtureFile {
  if (typeof value !== 'object' || value === null || !('cases' in value) || !Array.isArray(value.cases)) return false;

  return value.cases.every(isPresetCase);
}

function loadPresetFixtures(provider: PresetProvider): readonly FixtureCase[] {
  const raw = readFileSync(new URL(`../fixtures/${provider}.json`, import.meta.url), 'utf8');
  const parsed: unknown = JSON.parse(raw);

  if (!isPresetFixtureFile(parsed)) throw new Error(`Fixture file for ${provider} is malformed`);

  return parsed.cases;
}

test.each(['clerk', 'svix'] as const)('%s canonicality fixture has a full-size noncanonical digest', (provider) => {
  const fixture = loadPresetFixtures(provider).find((entry) => entry.id === 'noncanonical-signature-base64');
  expect(fixture).toBeDefined();
  const signature = fixture?.request.headers['svix-signature'];

  if (!isString(signature)) throw new Error('Expected the noncanonical signature fixture.');
  const encoded = signature.slice('v1,'.length);
  const decoded = Buffer.from(encoded, 'base64');
  expect(decoded.byteLength).toBe(32);
  expect(decoded.toString('base64')).not.toBe(encoded);
});

test('the wrong-signature-before-stale fixture is actually outside tolerance', () => {
  const fixture = loadPresetFixtures('svix').find((entry) => entry.id === 'wrong-signature-beats-stale');

  if (!fixture) throw new Error('Missing ordering fixture.');
  const timestamp = Number(fixture.request.headers['svix-timestamp']);
  expect(fixture.options.now - timestamp).toBeGreaterThan(fixture.options.toleranceSeconds ?? 300);
});

function requireCase(cases: readonly FixtureCase[], id: string): FixtureCase {
  const found = cases.find((entry) => entry.id === id);

  if (found === undefined) throw new Error(`Fixture case ${id} is missing from the matrix.`);

  return found;
}

async function assertFixture(provider: PresetProvider, fixtureCase: FixtureCase): Promise<void> {
  const bytes = fixtureBytes(fixtureCase);
  const options = fixtureOptions(provider, fixtureCase);

  for (const headers of representationsOf(fixtureCase)) {
    const result = await verify({ rawBody: bytes, headers }, options);

    if (fixtureCase.expected.ok) {
      if (!result.ok) throw new Error(`Expected fixture success but got ${result.reason}: ${result.message}`);
      expect(result.identity).toEqual(fixtureCase.expected.identity);
      expect(result.rawBody).toEqual(bytes);
    } else {
      if (result.ok) throw new Error(`Expected failure ${fixtureCase.expected.reason} but verification succeeded`);
      expect(result.reason).toBe(fixtureCase.expected.reason);
    }
  }
}

function headersInstanceFor(fixtureCase: FixtureCase): Headers {
  for (const representation of representationsOf(fixtureCase)) {
    if (representation instanceof Headers) return representation;
  }

  throw new Error('The fixture builder produced no Headers representation.');
}

function expectInvalidSecret(provider: PresetProvider, secret: string): void {
  let caught: unknown;

  try {
    createVerifier({ provider, secrets: [secret] });
  } catch (error) {
    caught = error;
  }

  if (!(caught instanceof HooklatchError)) throw new Error('Expected a synchronous HooklatchError');
  expect(caught.code).toBe('invalid-secret');
  expect(caught.message).not.toContain(secret);
}

const clerkCases = loadPresetFixtures('clerk');
const svixCases = loadPresetFixtures('svix');

const CLERK_IDS = [
  'branded-reference-vector',
  'local-anchor',
  'local-anchor-non-json-body',
  'local-anchor-empty-body',
  'rotation-both-signatures',
  'canonical-divergent-ignored',
  'canonical-only-missing-signature',
  'canonical-cannot-repair-malformed-branded',
  'branded-signature-canonical-identity-ordering',
  'tampered-body',
  'wrong-key',
  'rotation-old-removed',
  'stale-301-rejected',
  'future-301-rejected',
  'noncanonical-signature-base64',
  'unsupported-scheme-only',
];

const SVIX_IDS = [
  'branded-reference-vector',
  'canonical-reference-vector',
  'local-anchor',
  'local-anchor-canonical',
  'local-anchor-non-json-body',
  'local-anchor-empty-body',
  'dual-equal-families-accept',
  'rotation-both-signatures',
  'dual-unequal-canonical-signature',
  'dual-unequal-canonical-id',
  'dual-partial-families-malformed',
  'dual-branded-malformed-no-canonical-rescue',
  'missing-branded-signature-header',
  'unsupported-scheme-only',
  'noncanonical-signature-base64',
  'comma-combined-duplicate-id',
  'tampered-body',
  'tampered-event-id',
  'wrong-key',
  'rotation-old-removed',
  'stale-301-rejected',
  'future-301-rejected',
  'zero-width-tolerance-expired',
  'wrong-signature-beats-stale',
];

describe('preset fixture integrity', () => {
  test('clerk.json keeps its pinned case inventory', () => {
    expect(clerkCases.map((entry) => entry.id)).toEqual(CLERK_IDS);
  });

  test('svix.json keeps its pinned case inventory', () => {
    expect(svixCases.map((entry) => entry.id)).toEqual(SVIX_IDS);
  });
});

describe('clerk preset fixture matrix (public root, all header representations)', () => {
  for (const fixtureCase of clerkCases) {
    test(`clerk fixture ${fixtureCase.id}`, async () => {
      await assertFixture('clerk', fixtureCase);
    });
  }
});

describe('svix preset fixture matrix (public root, all header representations)', () => {
  for (const fixtureCase of svixCases) {
    test(`svix fixture ${fixtureCase.id}`, async () => {
      await assertFixture('svix', fixtureCase);
    });
  }
});

describe('preset policy contrasts on identical bytes', () => {
  test('divergent dual-family bytes verify under clerk and fail closed under svix', async () => {
    const divergent = requireCase(clerkCases, 'canonical-divergent-ignored');
    const bytes = fixtureBytes(divergent);
    const headers = divergent.request.headers;
    // The rotation fixture supplies both synthetic keys so neither verdict can
    // be attributed to a missing matching secret.
    const secrets = requireCase(svixCases, 'rotation-both-signatures').options.secrets;
    const shared = { secrets, toleranceSeconds: 300, now: () => divergent.options.now } as const;

    const svixResult = await verify({ rawBody: bytes, headers }, { ...shared, provider: 'svix' });

    if (svixResult.ok) throw new Error('svix must reject unequal dual families');
    expect(svixResult.reason).toBe('malformed-signature');

    const clerkResult = await verify({ rawBody: bytes, headers }, { ...shared, provider: 'clerk' });

    if (!clerkResult.ok) throw new Error(`clerk must ignore canonical divergence but got ${clerkResult.reason}`);
    expect(clerkResult.identity).toEqual(divergent.expected.identity);
  });
});

describe('preset freshness boundaries beyond the pinned cases', () => {
  test('the 300-second inclusive window verifies in both directions', async () => {
    for (const provider of ['clerk', 'svix'] as const) {
      const anchor = requireCase(provider === 'clerk' ? clerkCases : svixCases, 'local-anchor');
      const bytes = fixtureBytes(anchor);
      const base = fixtureOptions(provider, anchor);

      for (const drift of [300, -300]) {
        const result = await verify({ rawBody: bytes, headers: anchor.request.headers }, { ...base, now: () => anchor.options.now + drift });

        if (!result.ok) throw new Error(`Expected the inclusive window to verify but got ${result.reason}`);
        expect(result.identity).toEqual(anchor.expected.identity);
      }
    }
  });
});

describe('preset secret handling at the createVerifier boundary', () => {
  // Published on the Svix manual verification page; it decodes to exactly 18
  // key bytes and is rejected by the approved 24-64 byte bounds, never
  // misreported as a computed signature mismatch.
  const published18ByteExample = 'whsec_plJ3nmyCDGBKInavdOK15jsl';
  // Synthetic boundary keys: Base64 of UTF-8 '0123456789abcdefghijklmn' (24
  // bytes), and bytes of value 1 or 9 at 23/64/65 bytes.
  const key24 = 'whsec_MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1u';
  const key23 = 'whsec_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=';
  const key64 = 'whsec_CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ==';
  const key65 = 'whsec_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=';

  test('rejects the published 18-byte example with invalid-secret without echoing it', () => {
    for (const provider of ['clerk', 'svix'] as const) {
      expectInvalidSecret(provider, published18ByteExample);
    }
  });

  test('rejects 23 and 65 decoded key bytes', () => {
    for (const provider of ['clerk', 'svix'] as const) {
      expectInvalidSecret(provider, key23);
      expectInvalidSecret(provider, key65);
    }
  });

  test('accepts exactly 24 and 64 decoded key bytes', () => {
    for (const provider of ['clerk', 'svix'] as const) {
      expect(() => createVerifier({ provider, secrets: [key24] })).not.toThrow();
      expect(() => createVerifier({ provider, secrets: [key64] })).not.toThrow();
    }
  });
});

describe('verifyRequest keeps the preset recipe on the public root', () => {
  test('verifies the svix anchor through a real Request', async () => {
    const anchor = requireCase(svixCases, 'local-anchor');

    const request = new Request('https://example.test/webhook', {
      method: 'POST',
      body: new Uint8Array(fixtureBytes(anchor)),
      headers: headersInstanceFor(anchor),
    });

    const result = await verifyRequest(request, fixtureOptions('svix', anchor));

    if (!result.ok) throw new Error(`Expected verifyRequest success but got ${result.reason}`);
    expect(result.identity).toEqual(anchor.expected.identity);
    expect(result.rawBody).toEqual(fixtureBytes(anchor));
  });

  test('verifies the clerk anchor through a real Request', async () => {
    const anchor = requireCase(clerkCases, 'local-anchor');

    const request = new Request('https://example.test/webhook', {
      method: 'POST',
      body: new Uint8Array(fixtureBytes(anchor)),
      headers: headersInstanceFor(anchor),
    });

    const result = await verifyRequest(request, fixtureOptions('clerk', anchor));

    if (!result.ok) throw new Error(`Expected verifyRequest success but got ${result.reason}`);
    expect(result.identity).toEqual(anchor.expected.identity);
    expect(result.rawBody).toEqual(fixtureBytes(anchor));
  });
});
