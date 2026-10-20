import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { combinedHeader, fixtureBytes, isFixtureFile } from '../verification/helpers.js';
import type { FixtureCase } from '../verification/helpers.js';

/**
 * Stage A anchor suite for the three phase-5 fixture files (sentry, doppler,
 * sanity). It never imports provider modules, the Provider union, or
 * verification entry points: the new provider IDs stay unregistered and these
 * tests validate fixture data only. Every positive and freshness-only signature
 * is re-derived with node:crypto from the recorded header text and exact bytes;
 * deliberately invalid well-formed signatures are proven to match no configured
 * secret; grammar failures keep their exact contract reasons. Fractional-*
 * drift assertions mirror IEEE double behaviour (phase-4 convention): exact
 * .125-multiples are asserted with toBe, non-representable .001 drifts only
 * through range mirrors.
 */

function loadPhase5FixtureFile(fileName: string): readonly FixtureCase[] {
  const raw = readFileSync(new URL(`../fixtures/${fileName}`, import.meta.url), 'utf8');
  const parsed: unknown = JSON.parse(raw);

  if (!isFixtureFile(parsed)) throw new Error(`Phase 5 fixture file ${fileName} is malformed`);

  return parsed.cases;
}

function findCase(cases: readonly FixtureCase[], id: string): FixtureCase {
  const found = cases.find((fixture) => fixture.id === id);

  if (found === undefined) throw new Error(`Fixture case not found: ${id}`);

  return found;
}

const SENTRY_SIG_HEADER = 'sentry-hook-signature';
const DOPPLER_SIG_HEADER = 'x-doppler-signature';
const SANITY_SIG_HEADER = 'sanity-webhook-signature';

const HEX_64 = /^[0-9a-f]{64}$/i;
const LOWER_HEX_32 = /^[0-9a-f]{32}$/;
const LOWER_HEX_63 = /^[0-9a-f]{63}$/;
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;
const LOWER_HEX_65 = /^[0-9a-f]{65}$/;
const BASE64_STD_TOKEN = /^[A-Za-z0-9+/]+={0,2}$/;
const SANITY_CANONICAL_DECIMAL = /^(?:0|[1-9]\d*)$/;
const SANITY_DIGEST_SHORT = /^[A-Za-z0-9_-]{42}$/;
const SANITY_MIN_MS = 1609459200000;
const NONHEX_SENTINEL_CHAR = 'g';

const UTF8_LOOSE = new TextDecoder('utf-8');
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true });

const SENTRY_MAIN_SECRET = 'hooklatch_stage_a_sentry_secret';
const SENTRY_NEW_SECRET = 'hooklatch_stage_a_sentry_rotated_new_secret';
const DOPPLER_MAIN_SECRET = 'hooklatch_stage_a_doppler_secret';
const DOPPLER_NEW_SECRET = 'hooklatch_stage_a_doppler_rotated_new_secret';
const SANITY_MAIN_SECRET = 'hooklatch_stage_a_sanity_secret';
const SANITY_NEW_SECRET = 'hooklatch_stage_a_sanity_rotated_new_secret';
const SANITY_WRONG_KEY = 'hooklatch_stage_a_sanity_wrong_key';

/** Failure vocabulary sentry supports: bare 64-hex, no scheme grammar, no signed timestamp. */
const SENTRY_REASONS = new Set(['missing-signature', 'malformed-signature', 'invalid-signature']);

/** Failure vocabulary doppler supports: signed sha256= mode has schemes but no signed timestamp. */
const DOPPLER_REASONS = new Set(['missing-signature', 'malformed-signature', 'unsupported-scheme', 'invalid-signature']);

/** Failure vocabulary sanity supports: strict header grammar plus signed-clock checks. */
const SANITY_REASONS = new Set(['missing-signature', 'malformed-signature', 'invalid-signature', 'timestamp-expired', 'timestamp-future']);

const SENTRY_CASE_IDS = [
  'positive-baseline',
  'positive-uppercase-hex-accepted',
  'positive-unsigned-headers-present',
  'positive-unsigned-headers-forged-still-ok',
  'rotation-both-secrets-accept-old',
  'rotation-old-secret-after-removal',
  'empty-body-signed',
  'non-json-body-signed',
  'invalid-utf8-body-signed',
  'tampered-body',
  'missing-signature-header',
  'blank-signature-is-missing',
  'empty-value-is-missing-signature',
  'prefixed-sha256-64-hex-is-malformed',
  'sha1-prefixed-64-hex-is-malformed',
  'standard-webhooks-token-list-is-malformed',
  'outer-whitespace-is-malformed',
  'inner-whitespace-is-malformed',
  'comma-combined-duplicates-are-malformed',
  'short-63-hex-is-malformed',
  'long-65-hex-is-malformed',
  'non-hex-64-chars-are-malformed',
  'trailing-comma-is-malformed',
  'other-sentry-headers-alone-is-missing',
];

const DOPPLER_CASE_IDS = [
  'positive-baseline',
  'positive-uppercase-hex-accepted',
  'rotation-both-secrets-accept-old',
  'rotation-old-secret-after-removal',
  'empty-body-signed',
  'non-json-body-signed',
  'invalid-utf8-body-signed',
  'tampered-body',
  'missing-x-doppler-signature-header',
  'blank-signature-is-missing',
  'empty-value-is-missing-signature',
  'sha1-64-hex-is-unsupported-scheme',
  'md5-64-hex-is-unsupported-scheme',
  'uppercase-sha256-prefix-is-unsupported-scheme',
  'sha1-40-hex-is-malformed',
  'bare-hex-no-prefix-is-malformed',
  'comma-combined-duplicates-are-malformed',
  'standard-webhooks-token-list-is-malformed',
  'extra-equals-is-malformed',
  'leading-whitespace-is-malformed',
  'trailing-whitespace-is-malformed',
  'empty-digest-is-malformed',
  'non-hex-digest-is-malformed',
  'short-63-hex-is-malformed',
];

const SANITY_CASE_IDS = [
  'positive-baseline',
  'positive-fractional-identity-125',
  'positive-fractional-identity-250',
  'positive-fractional-identity-500',
  'positive-mixed-case-base64url-digest',
  'positive-idempotency-key-header-ignored',
  'rotation-both-secrets-accept-old',
  'rotation-old-secret-after-removal',
  'empty-body-signed',
  'nul-byte-body-signed',
  'non-json-body-signed',
  'invalid-utf8-body-signed',
  'tampered-body',
  'tampered-signed-timestamp-text',
  'wrong-signature-beats-stale',
  'boundary-plus300-omitted-tolerance',
  'boundary-plus301-omitted-tolerance',
  'boundary-minus300-omitted-tolerance',
  'boundary-minus301-omitted-tolerance',
  'fractional-boundary-plus-300-125-ok',
  'fractional-boundary-plus-300-125-expired',
  'fractional-boundary-plus-300-001-mirrored-expired',
  'fractional-inside-plus-299-875-ok',
  'fractional-boundary-minus-300-025-ok',
  'fractional-boundary-minus-300-025-future',
  'fractional-boundary-minus-300-001-mirrored-future',
  'fractional-inside-minus-299-5-ok',
  'explicit-zero-fractional-exact-ok',
  'explicit-zero-drift-expired',
  'override-tolerance-60-at-edge-ok',
  'override-tolerance-60-past-expired',
  'min-timestamp-inclusive-ok',
  'below-min-timestamp-is-malformed',
  'zero-timestamp-below-min-is-malformed',
  'beyond-safe-t-is-malformed',
  'leading-zero-t-is-malformed',
  'negative-t-is-malformed',
  'plus-signed-t-is-malformed',
  'decimal-point-t-is-malformed',
  'missing-signature-header',
  'blank-signature-is-missing',
  't-only-is-malformed',
  'v1-only-is-malformed',
  'v2-only-is-malformed',
  'reversed-field-order-is-malformed',
  'space-separator-is-malformed',
  'space-after-comma-is-malformed',
  'semicolon-separator-is-malformed',
  'outer-whitespace-is-malformed',
  'key-space-t-is-malformed',
  'inner-space-t-is-malformed',
  'duplicate-t-even-equal-is-malformed',
  'duplicate-v1-even-equal-is-malformed',
  'extra-v2-field-is-malformed',
  'digest-42-chars-is-malformed',
  'digest-with-equals-padding-is-malformed',
  'digest-standard-base64-chars-is-malformed',
  'digest-noncanonical-padbits-is-malformed',
];

interface SanityAnchorHeader {
  readonly msText: string;
  readonly digestText: string;
}

/** Mirrors the accepted sanity subset: exact canonical comma form, canonical ms at or above the minimum, canonical unpadded base64url digest of 32 bytes. */
function readSanitySignatureForAnchor(value: string): SanityAnchorHeader | null {
  const structured = /^t=(\d+),v1=([A-Za-z0-9_-]{43})$/.exec(value);
  const msText = structured?.[1];
  const digestText = structured?.[2];

  if (msText === undefined || digestText === undefined) return null;

  if (!SANITY_CANONICAL_DECIMAL.test(msText)) return null;

  const msNumber = Number(msText);

  if (!Number.isSafeInteger(msNumber)) return null;

  if (BigInt(msText) < BigInt(SANITY_MIN_MS)) return null;

  const digestBytes = Buffer.from(digestText, 'base64url');

  return digestBytes.byteLength === 32 && digestBytes.toString('base64url') === digestText ? { msText, digestText } : null;
}

/** Bare 64-hex only; either case is accepted for the sentry value. */
function readSentryHexForAnchor(value: string): string | null {
  return HEX_64.test(value) ? value.toLowerCase() : null;
}

/** Exact case-sensitive sha256= prefix, 64 hex either case. */
function readDopplerValueForAnchor(value: string): string | null {
  if (!value.startsWith('sha256=')) return null;

  return HEX_64.test(value.slice('sha256='.length)) ? value.slice('sha256='.length).toLowerCase() : null;
}

function bodySignatureVerifies(fixture: FixtureCase, hexValue: string, bytes: Uint8Array): boolean {
  return fixture.options.secrets.some((secret) => createHmac('sha256', secret).update(bytes).digest('hex') === hexValue);
}

function sanitySignatureVerifies(fixture: FixtureCase, msText: string, digestText: string, bytes: Uint8Array): boolean {
  return fixture.options.secrets.some((secret) =>
    createHmac('sha256', secret).update(`${msText}.`).update(bytes).digest('base64url') === digestText);
}

/** HMAC-SHA256 under one literal UTF-8 key rendered as base64url, for re-deriving removed-secret and wrong-key values. */
function sanityDigestWith(keyLabel: string, msText: string, bytes: Uint8Array): string {
  return createHmac('sha256', keyLabel).update(`${msText}.`).update(bytes).digest('base64url');
}

const SENTRY_CASES = loadPhase5FixtureFile('sentry.json');
const DOPPLER_CASES = loadPhase5FixtureFile('doppler.json');
const SANITY_CASES = loadPhase5FixtureFile('sanity.json');

const SENTRY_SOURCE_MARKERS = [
  'https://docs.sentry.io/integrations/integration-platform/webhooks',
  '72757dae9b6d527e564c81d4921dec0d62d7beca',
  '9cca6d24b06f58bfccbda225aa543a6fd5319f59',
  'integration-platform mode only',
];

const DOPPLER_SOURCE_MARKERS = [
  'https://docs.doppler.com/docs/webhooks',
  'sha256= mode only',
  'no Basic/Bearer fallback',
];

const SANITY_SOURCE_MARKERS = [
  'https://www.sanity.io/docs/content-lake/webhook-best-practices',
  'e0c211ed6cd80465a70829e335c9e219f37839ba',
  'receiver policy',
];

describe('phase 5 fixture inventory', () => {
  it('loads the three new fixture files with the pinned case counts and ids', () => {
    expect(SENTRY_CASES.map((fixture) => fixture.id)).toEqual(SENTRY_CASE_IDS);
    expect(DOPPLER_CASES.map((fixture) => fixture.id)).toEqual(DOPPLER_CASE_IDS);
    expect(SANITY_CASES.map((fixture) => fixture.id)).toEqual(SANITY_CASE_IDS);
  });

  it('keeps every case locally generated rather than claiming reference-vector provenance', () => {
    const allCases = [...SENTRY_CASES, ...DOPPLER_CASES, ...SANITY_CASES];

    expect(allCases.every((fixture) => fixture.provenance.class === 'local')).toBe(true);
    expect(allCases.every((fixture) => !('commit' in fixture.provenance) && !('fetched' in fixture.provenance))).toBe(true);
  });

  it('pins the primary research sources in every provenance string', () => {
    const problems = [
      { fileName: 'sentry.json', cases: SENTRY_CASES, markers: SENTRY_SOURCE_MARKERS },
      { fileName: 'doppler.json', cases: DOPPLER_CASES, markers: DOPPLER_SOURCE_MARKERS },
      { fileName: 'sanity.json', cases: SANITY_CASES, markers: SANITY_SOURCE_MARKERS },
    ].flatMap(({ fileName, cases, markers }) => cases.flatMap((fixture) => markers
      .filter((marker) => !fixture.provenance.source.includes(marker))
      .map((marker) => `${fileName}/${fixture.id}: provenance misses '${marker}'`)));

    expect(problems).toEqual([]);
  });

  it('restricts every failure reason to the frozen contract vocabulary', () => {
    const problems = [
      { fileName: 'sentry.json', cases: SENTRY_CASES, reasons: SENTRY_REASONS },
      { fileName: 'doppler.json', cases: DOPPLER_CASES, reasons: DOPPLER_REASONS },
      { fileName: 'sanity.json', cases: SANITY_CASES, reasons: SANITY_REASONS },
    ].flatMap(({ fileName, cases, reasons }) => cases.flatMap((fixture) => {
      if (fixture.expected.ok) {
        return fixture.expected.reason === undefined ? [] : [`${fileName}/${fixture.id}: ok case carries a reason`];
      }

      return reasons.has(fixture.expected.reason ?? '') ? [] : [`${fileName}/${fixture.id}: reason '${fixture.expected.reason}' outside vocabulary`];
    }));

    expect(problems).toEqual([]);
  });

  it('never applies freshness families in the no-signed-timestamp corpora', () => {
    const freshnessLeaks = [...SENTRY_CASES, ...DOPPLER_CASES].flatMap((fixture) => ((fixture.expected.reason === 'timestamp-expired' || fixture.expected.reason === 'timestamp-future')
      ? [fixture.id]
      : []));

    expect(freshnessLeaks).toEqual([]);
  });

  it('never invents scheme families inside the strict sanity corpus', () => {
    const schemeLeaks = SANITY_CASES.flatMap((fixture) => (fixture.expected.reason === 'unsupported-scheme' ? [fixture.id] : []));

    expect(schemeLeaks).toEqual([]);
  });
});

describe('sentry fixture anchors', () => {
  it('recalculates every positive signature and pins the all-null identity map', () => {
    const problems = SENTRY_CASES.flatMap((fixture) => {
      if (!fixture.expected.ok) return [];

      const anchorHex = readSentryHexForAnchor(combinedHeader(fixture, SENTRY_SIG_HEADER) ?? '');

      if (anchorHex === null) return [`${fixture.id}: positive header is outside the well-formed anchor subset`];

      if (!bodySignatureVerifies(fixture, anchorHex, fixtureBytes(fixture))) return [`${fixture.id}: recorded digest does not verify against any configured secret`];

      const identity = fixture.expected.identity;

      if (identity?.deliveryId !== null || identity?.eventId !== null || identity?.timestamp !== null || identity?.authenticatedFields.length !== 0) {
        return [`${fixture.id}: identity is not the all-null body-only map`];
      }

      return [];
    });

    expect(problems).toEqual([]);
  });

  it('proves deliberately invalid well-formed signatures match no configured secret', () => {
    const mismatches = SENTRY_CASES.flatMap((fixture) => {
      if (fixture.expected.reason !== 'invalid-signature') return [];

      const anchorHex = readSentryHexForAnchor(combinedHeader(fixture, SENTRY_SIG_HEADER) ?? '');

      if (anchorHex === null) return [`${fixture.id}: invalid-signature fixture is not well-formed`];

      return bodySignatureVerifies(fixture, anchorHex, fixtureBytes(fixture)) ? [`${fixture.id}: supposedly invalid signature actually verifies`] : [];
    });

    expect(mismatches).toEqual([]);
  });

  it('proves reserved context headers cannot authenticate or poison acceptance', () => {
    const baseline = findCase(SENTRY_CASES, 'positive-baseline');
    const present = findCase(SENTRY_CASES, 'positive-unsigned-headers-present');
    const forged = findCase(SENTRY_CASES, 'positive-unsigned-headers-forged-still-ok');

    expect(present.request.bodyBase64).toBe(baseline.request.bodyBase64);
    expect(combinedHeader(present, SENTRY_SIG_HEADER)).toBe(combinedHeader(baseline, SENTRY_SIG_HEADER));
    expect(combinedHeader(present, 'sentry-hook-timestamp')).toBeDefined();
    expect(combinedHeader(present, 'request-id')).toBeDefined();
    expect(combinedHeader(present, 'sentry-hook-resource')).toBeDefined();

    const forgedTimestamp = combinedHeader(forged, 'sentry-hook-timestamp') ?? '';

    expect(forged.request.bodyBase64).toBe(baseline.request.bodyBase64);
    expect(combinedHeader(forged, SENTRY_SIG_HEADER)).toBe(combinedHeader(baseline, SENTRY_SIG_HEADER));
    expect(parseInt(forgedTimestamp, 10) - baseline.options.now).toBeGreaterThan(300);
    expect(combinedHeader(forged, 'request-id')).not.toBe(combinedHeader(baseline, 'request-id'));

    for (const fixture of [present, forged]) {
      expect(fixture.expected.ok).toBe(true);
      expect(fixture.expected.identity?.timestamp).toBeNull();
      expect(fixture.expected.identity?.authenticatedFields).toEqual([]);
    }
  });

  it('pins malformed prefixed-value expectations whose inner hex authenticates', () => {
    const probes = [
      { id: 'prefixed-sha256-64-hex-is-malformed', pattern: /^sha256=([0-9a-f]{64})$/ },
      { id: 'sha1-prefixed-64-hex-is-malformed', pattern: /^sha1=([0-9a-f]{64})$/ },
    ];

    const problems = probes.flatMap(({ id, pattern }) => {
      const fixture = findCase(SENTRY_CASES, id);
      const matched = pattern.exec(combinedHeader(fixture, SENTRY_SIG_HEADER) ?? '');
      const innerHex = matched === null ? undefined : matched[1];

      if (innerHex === undefined) return [`${fixture.id}: prefixed probe no longer records a 64-hex inner value`];

      if (!bodySignatureVerifies(fixture, innerHex, fixtureBytes(fixture))) return [`${fixture.id}: inner hex is not a real MAC`];

      return fixture.expected.reason === 'malformed-signature' ? [] : [`${fixture.id}: changed contract reason`];
    });

    expect(problems).toEqual([]);
  });

  it('pins the raw shapes behind the missing and malformed families', () => {
    expect(combinedHeader(findCase(SENTRY_CASES, 'missing-signature-header'), SENTRY_SIG_HEADER)).toBeUndefined();
    expect(combinedHeader(findCase(SENTRY_CASES, 'other-sentry-headers-alone-is-missing'), SENTRY_SIG_HEADER)).toBeUndefined();

    const blank = combinedHeader(findCase(SENTRY_CASES, 'blank-signature-is-missing'), SENTRY_SIG_HEADER) ?? '';

    expect(blank.length).toBeGreaterThan(0);
    expect(blank.trim()).toBe('');

    expect(combinedHeader(findCase(SENTRY_CASES, 'empty-value-is-missing-signature'), SENTRY_SIG_HEADER)).toBe('');

    const listToken = combinedHeader(findCase(SENTRY_CASES, 'standard-webhooks-token-list-is-malformed'), SENTRY_SIG_HEADER) ?? '';

    expect(listToken.startsWith('v1,')).toBe(true);
    expect(listToken.slice(3)).toHaveLength(44);
    expect(listToken.slice(3)).toMatch(BASE64_STD_TOKEN);

    const outer = combinedHeader(findCase(SENTRY_CASES, 'outer-whitespace-is-malformed'), SENTRY_SIG_HEADER) ?? '';

    expect(outer.startsWith(' ')).toBe(true);
    expect(outer.endsWith(' ')).toBe(true);
    expect(outer.trim()).toMatch(LOWER_HEX_64);

    const inner = combinedHeader(findCase(SENTRY_CASES, 'inner-whitespace-is-malformed'), SENTRY_SIG_HEADER) ?? '';
    const innerParts = inner.split(' ');

    expect(innerParts).toHaveLength(2);
    expect(innerParts.map((part) => LOWER_HEX_32.test(part)).every(Boolean)).toBe(true);

    const commaCase = findCase(SENTRY_CASES, 'comma-combined-duplicates-are-malformed');
    const commaValue = combinedHeader(commaCase, SENTRY_SIG_HEADER) ?? '';
    const commaHalves = commaValue.split(', ');

    expect(commaHalves).toHaveLength(2);
    expect(commaHalves[0]).toBe(commaHalves[1]);
    expect(commaHalves[0]).toMatch(LOWER_HEX_64);

    expect(combinedHeader(findCase(SENTRY_CASES, 'short-63-hex-is-malformed'), SENTRY_SIG_HEADER) ?? '').toMatch(LOWER_HEX_63);
    expect(combinedHeader(findCase(SENTRY_CASES, 'long-65-hex-is-malformed'), SENTRY_SIG_HEADER) ?? '').toMatch(LOWER_HEX_65);

    const nonhex = combinedHeader(findCase(SENTRY_CASES, 'non-hex-64-chars-are-malformed'), SENTRY_SIG_HEADER) ?? '';

    expect(nonhex).toHaveLength(64);
    expect(nonhex.charAt(0)).toBe(NONHEX_SENTINEL_CHAR);
    expect(nonhex.slice(1)).toMatch(LOWER_HEX_63);

    const trailing = combinedHeader(findCase(SENTRY_CASES, 'trailing-comma-is-malformed'), SENTRY_SIG_HEADER) ?? '';

    expect(trailing.endsWith(',')).toBe(true);
    expect(trailing.slice(0, -1)).toMatch(LOWER_HEX_64);
  });

  it('keeps the recorded signature untouched while the body changes', () => {
    const baseline = findCase(SENTRY_CASES, 'positive-baseline');
    const tampered = findCase(SENTRY_CASES, 'tampered-body');

    expect(tampered.request.headers).toEqual(baseline.request.headers);
    expect(tampered.request.bodyBase64).not.toBe(baseline.request.bodyBase64);
    expect(tampered.expected.reason).toBe('invalid-signature');
  });

  it('signs empty, non-JSON and invalid-UTF-8 bodies over the exact bytes', () => {
    expect(fixtureBytes(findCase(SENTRY_CASES, 'empty-body-signed')).length).toBe(0);
    expect(() => JSON.parse(UTF8_LOOSE.decode(fixtureBytes(findCase(SENTRY_CASES, 'non-json-body-signed'))))).toThrow();
    expect(() => UTF8_STRICT.decode(fixtureBytes(findCase(SENTRY_CASES, 'invalid-utf8-body-signed')))).toThrow();
  });

  it('checks fixture MACs against retained and removed secret accept-sets', () => {
    const acceptCase = findCase(SENTRY_CASES, 'rotation-both-secrets-accept-old');
    const removalCase = findCase(SENTRY_CASES, 'rotation-old-secret-after-removal');

    expect(acceptCase.options.secrets).toEqual([SENTRY_MAIN_SECRET, SENTRY_NEW_SECRET]);
    expect(acceptCase.expected.ok).toBe(true);
    expect(bodySignatureVerifies(acceptCase, readSentryHexForAnchor(combinedHeader(acceptCase, SENTRY_SIG_HEADER) ?? '') ?? '', fixtureBytes(acceptCase))).toBe(true);

    const removalHex = readSentryHexForAnchor(combinedHeader(removalCase, SENTRY_SIG_HEADER) ?? '');

    expect(removalHex).toBe(combinedHeader(acceptCase, SENTRY_SIG_HEADER)?.toLowerCase());
    expect(removalCase.options.secrets).toEqual([SENTRY_NEW_SECRET]);
    expect(removalCase.expected.reason).toBe('invalid-signature');
    expect(removalHex === null ? false : bodySignatureVerifies(removalCase, removalHex, fixtureBytes(removalCase))).toBe(false);
    expect(removalHex).toBe(createHmac('sha256', SENTRY_MAIN_SECRET).update(fixtureBytes(removalCase)).digest('hex'));
  });
});

describe('doppler fixture anchors', () => {
  it('recalculates every positive signature and pins the all-null identity map', () => {
    const problems = DOPPLER_CASES.flatMap((fixture) => {
      if (!fixture.expected.ok) return [];

      const anchorHex = readDopplerValueForAnchor(combinedHeader(fixture, DOPPLER_SIG_HEADER) ?? '');

      if (anchorHex === null) return [`${fixture.id}: positive header is outside the well-formed anchor subset`];

      if (!bodySignatureVerifies(fixture, anchorHex, fixtureBytes(fixture))) return [`${fixture.id}: recorded digest does not verify against any configured secret`];

      const identity = fixture.expected.identity;

      if (identity?.deliveryId !== null || identity?.eventId !== null || identity?.timestamp !== null || identity?.authenticatedFields.length !== 0) {
        return [`${fixture.id}: identity is not the all-null body-only map`];
      }

      return [];
    });

    expect(problems).toEqual([]);
  });

  it('proves deliberately invalid well-formed signatures match no configured secret', () => {
    const mismatches = DOPPLER_CASES.flatMap((fixture) => {
      if (fixture.expected.reason !== 'invalid-signature') return [];

      const anchorHex = readDopplerValueForAnchor(combinedHeader(fixture, DOPPLER_SIG_HEADER) ?? '');

      if (anchorHex === null) return [`${fixture.id}: invalid-signature fixture is not well-formed`];

      return bodySignatureVerifies(fixture, anchorHex, fixtureBytes(fixture)) ? [`${fixture.id}: supposedly invalid signature actually verifies`] : [];
    });

    expect(mismatches).toEqual([]);
  });

  it('supports only the exact lowercase sha256= scheme with shape-correct inner digests', () => {
    const schemeProbes = [
      { id: 'sha1-64-hex-is-unsupported-scheme', scheme: 'sha1' },
      { id: 'md5-64-hex-is-unsupported-scheme', scheme: 'md5' },
      { id: 'uppercase-sha256-prefix-is-unsupported-scheme', scheme: 'SHA256' },
    ];

    const problems = schemeProbes.flatMap(({ id, scheme }) => {
      const fixture = findCase(DOPPLER_CASES, id);
      const innerPattern = new RegExp(`^${scheme}=([0-9a-f]{64})$`);
      const matched = innerPattern.exec(combinedHeader(fixture, DOPPLER_SIG_HEADER) ?? '');
      const innerHex = matched === null ? undefined : matched[1];

      if (innerHex === undefined) return [`${fixture.id}: scheme probe no longer records a 64-hex inner value`];

      if (!bodySignatureVerifies(fixture, innerHex, fixtureBytes(fixture))) return [`${fixture.id}: inner hex is not a real MAC`];

      return fixture.expected.reason === 'unsupported-scheme' ? [] : [`${fixture.id}: changed contract reason`];
    });

    const shortProbe = findCase(DOPPLER_CASES, 'sha1-40-hex-is-malformed');
    const shortMatched = /^sha1=([0-9a-f]{40})$/.exec(combinedHeader(shortProbe, DOPPLER_SIG_HEADER) ?? '');

    expect(shortMatched).not.toBeNull();
    expect(combinedHeader(shortProbe, DOPPLER_SIG_HEADER) ?? '').toHaveLength(45);
    expect(shortProbe.expected.reason).toBe('malformed-signature');
    expect(problems).toEqual([]);
  });

  it('pins the raw shapes behind the missing and malformed families', () => {
    expect(combinedHeader(findCase(DOPPLER_CASES, 'missing-x-doppler-signature-header'), DOPPLER_SIG_HEADER)).toBeUndefined();

    const blank = combinedHeader(findCase(DOPPLER_CASES, 'blank-signature-is-missing'), DOPPLER_SIG_HEADER) ?? '';

    expect(blank.length).toBeGreaterThan(0);
    expect(blank.trim()).toBe('');

    expect(combinedHeader(findCase(DOPPLER_CASES, 'empty-value-is-missing-signature'), DOPPLER_SIG_HEADER)).toBe('');

    expect(combinedHeader(findCase(DOPPLER_CASES, 'bare-hex-no-prefix-is-malformed'), DOPPLER_SIG_HEADER) ?? '').toMatch(LOWER_HEX_64);

    const commaCase = findCase(DOPPLER_CASES, 'comma-combined-duplicates-are-malformed');
    const commaValue = combinedHeader(commaCase, DOPPLER_SIG_HEADER) ?? '';

    expect(commaValue).toMatch(/^sha256=[0-9a-f]{64}, sha256=[0-9a-f]{64}$/);

    const listToken = combinedHeader(findCase(DOPPLER_CASES, 'standard-webhooks-token-list-is-malformed'), DOPPLER_SIG_HEADER) ?? '';

    expect(listToken.startsWith('v1,')).toBe(true);
    expect(listToken.slice(3)).toHaveLength(44);
    expect(listToken.slice(3)).toMatch(BASE64_STD_TOKEN);

    expect(combinedHeader(findCase(DOPPLER_CASES, 'extra-equals-is-malformed'), DOPPLER_SIG_HEADER) ?? '').toMatch(/^sha256==[0-9a-f]{64}$/);

    const leading = combinedHeader(findCase(DOPPLER_CASES, 'leading-whitespace-is-malformed'), DOPPLER_SIG_HEADER) ?? '';

    expect(leading.startsWith(' ')).toBe(true);
    expect(leading.trim()).toMatch(/^sha256=[0-9a-f]{64}$/);

    const trailing = combinedHeader(findCase(DOPPLER_CASES, 'trailing-whitespace-is-malformed'), DOPPLER_SIG_HEADER) ?? '';

    expect(trailing.endsWith(' ')).toBe(true);
    expect(trailing.trim()).toMatch(/^sha256=[0-9a-f]{64}$/);

    expect(combinedHeader(findCase(DOPPLER_CASES, 'empty-digest-is-malformed'), DOPPLER_SIG_HEADER)).toBe('sha256=');

    const nonhex = combinedHeader(findCase(DOPPLER_CASES, 'non-hex-digest-is-malformed'), DOPPLER_SIG_HEADER) ?? '';

    expect(nonhex.startsWith(`sha256=${NONHEX_SENTINEL_CHAR}`)).toBe(true);
    expect(nonhex.slice('sha256='.length)).toHaveLength(64);

    expect(combinedHeader(findCase(DOPPLER_CASES, 'short-63-hex-is-malformed'), DOPPLER_SIG_HEADER) ?? '').toMatch(/^sha256=[0-9a-f]{63}$/);
  });

  it('keeps the recorded signature untouched while the body changes', () => {
    const baseline = findCase(DOPPLER_CASES, 'positive-baseline');
    const tampered = findCase(DOPPLER_CASES, 'tampered-body');

    expect(tampered.request.headers).toEqual(baseline.request.headers);
    expect(tampered.request.bodyBase64).not.toBe(baseline.request.bodyBase64);
    expect(tampered.expected.reason).toBe('invalid-signature');
  });

  it('signs empty, non-JSON and invalid-UTF-8 bodies over the exact bytes', () => {
    expect(fixtureBytes(findCase(DOPPLER_CASES, 'empty-body-signed')).length).toBe(0);
    expect(() => JSON.parse(UTF8_LOOSE.decode(fixtureBytes(findCase(DOPPLER_CASES, 'non-json-body-signed'))))).toThrow();
    expect(() => UTF8_STRICT.decode(fixtureBytes(findCase(DOPPLER_CASES, 'invalid-utf8-body-signed')))).toThrow();
  });

  it('checks fixture MACs against retained and removed secret accept-sets', () => {
    const acceptCase = findCase(DOPPLER_CASES, 'rotation-both-secrets-accept-old');
    const removalCase = findCase(DOPPLER_CASES, 'rotation-old-secret-after-removal');

    expect(acceptCase.options.secrets).toEqual([DOPPLER_MAIN_SECRET, DOPPLER_NEW_SECRET]);
    expect(acceptCase.expected.ok).toBe(true);
    expect(bodySignatureVerifies(acceptCase, readDopplerValueForAnchor(combinedHeader(acceptCase, DOPPLER_SIG_HEADER) ?? '') ?? '', fixtureBytes(acceptCase))).toBe(true);

    const removalHex = readDopplerValueForAnchor(combinedHeader(removalCase, DOPPLER_SIG_HEADER) ?? '');

    expect(removalHex).toBe(combinedHeader(acceptCase, DOPPLER_SIG_HEADER)?.slice('sha256='.length).toLowerCase());
    expect(removalCase.options.secrets).toEqual([DOPPLER_NEW_SECRET]);
    expect(removalCase.expected.reason).toBe('invalid-signature');
    expect(removalHex === null ? false : bodySignatureVerifies(removalCase, removalHex, fixtureBytes(removalCase))).toBe(false);
    expect(removalHex).toBe(createHmac('sha256', DOPPLER_MAIN_SECRET).update(fixtureBytes(removalCase)).digest('hex'));
  });
});

describe('sanity fixture anchors', () => {
  it('recalculates every positive signature and mirrors Number(t)/1000 identity', () => {
    const problems = SANITY_CASES.flatMap((fixture) => {
      if (!fixture.expected.ok) return [];

      const anchorHeader = readSanitySignatureForAnchor(combinedHeader(fixture, SANITY_SIG_HEADER) ?? '');

      if (anchorHeader === null) return [`${fixture.id}: positive header is outside the accepted anchor subset`];

      if (!sanitySignatureVerifies(fixture, anchorHeader.msText, anchorHeader.digestText, fixtureBytes(fixture))) {
        return [`${fixture.id}: recorded digest does not verify against any configured secret`];
      }

      const identity = fixture.expected.identity;
      const mirrorTimestamp = Number(anchorHeader.msText) / 1000;

      if (identity?.deliveryId !== null || identity?.eventId !== null || identity?.timestamp !== mirrorTimestamp) {
        return [`${fixture.id}: identity is not the canonical sanity map with Number(t)/1000`];
      }

      if (identity?.authenticatedFields.length !== 1 || identity?.authenticatedFields[0] !== 'timestamp') {
        return [`${fixture.id}: authenticatedFields is not exactly ['timestamp']`];
      }

      return [];
    });

    expect(problems).toEqual([]);
  });

  it('proves deliberately invalid well-formed signatures match no configured secret', () => {
    const mismatches = SANITY_CASES.flatMap((fixture) => {
      if (fixture.expected.reason !== 'invalid-signature') return [];

      const anchorHeader = readSanitySignatureForAnchor(combinedHeader(fixture, SANITY_SIG_HEADER) ?? '');

      if (anchorHeader === null) return [`${fixture.id}: invalid-signature fixture is not well-formed`];

      const verified = sanitySignatureVerifies(fixture, anchorHeader.msText, anchorHeader.digestText, fixtureBytes(fixture));

      return verified ? [`${fixture.id}: supposedly invalid signature actually verifies`] : [];
    });

    expect(mismatches).toEqual([]);
  });

  it('proves the MAC stays valid for every freshness-only failure', () => {
    const unverified = SANITY_CASES.flatMap((fixture) => {
      const freshnessOnly = fixture.expected.reason === 'timestamp-expired' || fixture.expected.reason === 'timestamp-future';

      if (!freshnessOnly) return [];

      const anchorHeader = readSanitySignatureForAnchor(combinedHeader(fixture, SANITY_SIG_HEADER) ?? '');

      if (anchorHeader === null) return [`${fixture.id}: freshness-only fixture is not well-formed`];

      const verified = sanitySignatureVerifies(fixture, anchorHeader.msText, anchorHeader.digestText, fixtureBytes(fixture));

      return verified ? [] : [`${fixture.id}: freshness-only failure has no valid MAC`];
    });

    expect(unverified).toEqual([]);
  });

  it('pins the symmetric 300-second boundary with exact and IEEE-safe comparisons', () => {
    interface SanityBoundaryCheck {
      readonly id: string;
      readonly ok: boolean;
      readonly reason?: 'timestamp-expired' | 'timestamp-future';
      readonly exact?: number;
      readonly beyondPast?: number;
      readonly beyondFuture?: number;
    }

    const checks: readonly SanityBoundaryCheck[] = [
      { id: 'boundary-plus300-omitted-tolerance', ok: true, exact: 300 },
      { id: 'boundary-plus301-omitted-tolerance', ok: false, reason: 'timestamp-expired', exact: 301 },
      { id: 'boundary-minus300-omitted-tolerance', ok: true, exact: -300 },
      { id: 'boundary-minus301-omitted-tolerance', ok: false, reason: 'timestamp-future', exact: -301 },
      { id: 'fractional-boundary-plus-300-125-ok', ok: true, exact: 300 },
      { id: 'fractional-boundary-plus-300-125-expired', ok: false, reason: 'timestamp-expired', exact: 300.125 },
      { id: 'fractional-inside-plus-299-875-ok', ok: true, exact: 299.875 },
      { id: 'fractional-boundary-minus-300-025-ok', ok: true, exact: -300 },
      { id: 'fractional-boundary-minus-300-025-future', ok: false, reason: 'timestamp-future', exact: -300.125 },
      { id: 'fractional-inside-minus-299-5-ok', ok: true, exact: -299.5 },
    ];

    for (const check of checks) {
      const fixture = findCase(SANITY_CASES, check.id);
      const anchorHeader = readSanitySignatureForAnchor(combinedHeader(fixture, SANITY_SIG_HEADER) ?? '');
      const identityTs = Number(anchorHeader?.msText ?? '') / 1000;

      expect('toleranceSeconds' in fixture.options).toBe(false);
      expect(fixture.expected.ok).toBe(check.ok);

      if (check.ok) {
        expect(fixture.expected.identity?.timestamp).toBe(identityTs);
      }

      if (!check.ok) {
        expect(fixture.expected.reason).toBe(check.reason);
        expect(fixture.expected.identity).toBeUndefined();
      }

      if (check.exact !== undefined) {
        expect(fixture.options.now - identityTs).toBe(check.exact);
      }

      if (check.beyondPast !== undefined) {
        expect(fixture.options.now - identityTs).toBeGreaterThan(check.beyondPast);
      }

      if (check.beyondFuture !== undefined) {
        expect(identityTs - fixture.options.now).toBeGreaterThan(check.beyondFuture);
      }
    }
  });

  it('asserts non-representable .001 drifts only through mirrored ranges', () => {
    const checks = [
      { id: 'fractional-boundary-plus-300-001-mirrored-expired', reason: 'timestamp-expired', futureSide: false },
      { id: 'fractional-boundary-minus-300-001-mirrored-future', reason: 'timestamp-future', futureSide: true },
    ];

    for (const check of checks) {
      const fixture = findCase(SANITY_CASES, check.id);
      const anchorHeader = readSanitySignatureForAnchor(combinedHeader(fixture, SANITY_SIG_HEADER) ?? '');
      const identityTs = Number(anchorHeader?.msText ?? '') / 1000;
      const drift = check.futureSide ? identityTs - fixture.options.now : fixture.options.now - identityTs;

      expect(fixture.expected.ok).toBe(false);
      expect(fixture.expected.reason).toBe(check.reason);
      expect(fixture.expected.identity).toBeUndefined();
      expect('toleranceSeconds' in fixture.options).toBe(false);
      expect(drift).toBeGreaterThan(300);
      expect(drift).toBeLessThan(301);
    }
  });

  it('pins the explicit zero-width match and the nonzero zero-tolerance drift', () => {
    const zeroOk = findCase(SANITY_CASES, 'explicit-zero-fractional-exact-ok');
    const zeroOkHeader = readSanitySignatureForAnchor(combinedHeader(zeroOk, SANITY_SIG_HEADER) ?? '');
    const zeroOkIdentity = Number(zeroOkHeader?.msText ?? '') / 1000;

    expect(zeroOkHeader?.msText).toBe('1700000000125');
    expect(zeroOk.options.toleranceSeconds).toBe(0);
    expect(zeroOk.options.now).toBe(zeroOkIdentity);
    expect(zeroOk.expected.ok).toBe(true);
    expect(zeroOk.expected.identity?.timestamp).toBe(zeroOkIdentity);

    const zeroDrift = findCase(SANITY_CASES, 'explicit-zero-drift-expired');
    const zeroDriftHeader = readSanitySignatureForAnchor(combinedHeader(zeroDrift, SANITY_SIG_HEADER) ?? '');
    const zeroDriftIdentity = Number(zeroDriftHeader?.msText ?? '') / 1000;

    expect(zeroDriftHeader?.msText).toBe('1700000000000');
    expect(zeroDrift.options.toleranceSeconds).toBe(0);
    expect(zeroDrift.options.now - zeroDriftIdentity).toBe(0.125);
    expect(zeroDrift.expected.reason).toBe('timestamp-expired');
    expect(zeroDrift.expected.identity).toBeUndefined();
  });

  it('pins the explicit tolerance override at its own edge', () => {
    const edgeOk = findCase(SANITY_CASES, 'override-tolerance-60-at-edge-ok');
    const edgeHeader = readSanitySignatureForAnchor(combinedHeader(edgeOk, SANITY_SIG_HEADER) ?? '');

    expect(edgeHeader?.msText).toBe('1700000000000');
    expect(edgeOk.options.toleranceSeconds).toBe(60);
    expect(edgeOk.options.now).toBe(1700000060);
    expect(edgeOk.expected.ok).toBe(true);
    expect(edgeOk.expected.identity?.timestamp).toBe(1700000000);

    const pastExpired = findCase(SANITY_CASES, 'override-tolerance-60-past-expired');

    expect(pastExpired.options.toleranceSeconds).toBe(60);
    expect(pastExpired.options.now).toBe(1700000061);
    expect(pastExpired.expected.reason).toBe('timestamp-expired');
    expect(pastExpired.expected.identity).toBeUndefined();
  });

  it('pins stale bad-MAC fixture expectations without executing verification order', () => {
    const fixture = findCase(SANITY_CASES, 'wrong-signature-beats-stale');
    const anchorHeader = readSanitySignatureForAnchor(combinedHeader(fixture, SANITY_SIG_HEADER) ?? '');
    const identityTs = Number(anchorHeader?.msText ?? '') / 1000;

    expect(anchorHeader?.msText).toBe('1700000000000');
    expect(fixture.options.now - identityTs).toBe(301);
    expect(fixture.expected.ok).toBe(false);
    expect(fixture.expected.reason).toBe('invalid-signature');
    expect(fixture.expected.identity).toBeUndefined();
    expect(fixture.options.secrets).toEqual([SANITY_MAIN_SECRET]);
    expect(sanitySignatureVerifies(fixture, anchorHeader?.msText ?? '', anchorHeader?.digestText ?? '', fixtureBytes(fixture))).toBe(false);
    expect(anchorHeader?.digestText).toBe(sanityDigestWith(SANITY_WRONG_KEY, anchorHeader?.msText ?? '', fixtureBytes(fixture)));
  });

  it('keeps the recorded signature untouched while tampering body or signed timestamp', () => {
    const baseline = findCase(SANITY_CASES, 'positive-baseline');
    const bodyTamper = findCase(SANITY_CASES, 'tampered-body');
    const tTamper = findCase(SANITY_CASES, 'tampered-signed-timestamp-text');

    const baselineHeader = readSanitySignatureForAnchor(combinedHeader(baseline, SANITY_SIG_HEADER) ?? '');
    const bodyHeader = readSanitySignatureForAnchor(combinedHeader(bodyTamper, SANITY_SIG_HEADER) ?? '');
    const tTamperHeader = readSanitySignatureForAnchor(combinedHeader(tTamper, SANITY_SIG_HEADER) ?? '');

    expect(bodyHeader?.digestText).toBe(baselineHeader?.digestText);
    expect(bodyHeader?.msText).toBe(baselineHeader?.msText);
    expect(bodyTamper.request.bodyBase64).not.toBe(baseline.request.bodyBase64);
    expect(bodyTamper.expected.reason).toBe('invalid-signature');
    expect(sanitySignatureVerifies(bodyTamper, bodyHeader?.msText ?? '', bodyHeader?.digestText ?? '', fixtureBytes(bodyTamper))).toBe(false);

    expect(tTamperHeader?.msText).toBe('1700000000100');
    expect(tTamperHeader?.digestText).toBe(baselineHeader?.digestText);
    expect(tTamper.expected.reason).toBe('invalid-signature');
    expect(sanitySignatureVerifies(tTamper, tTamperHeader?.msText ?? '', tTamperHeader?.digestText ?? '', fixtureBytes(tTamper))).toBe(false);
  });

  it('pins the minimum-timestamp policy at millisecond edges', () => {
    const minOk = findCase(SANITY_CASES, 'min-timestamp-inclusive-ok');
    const minHeader = readSanitySignatureForAnchor(combinedHeader(minOk, SANITY_SIG_HEADER) ?? '');

    expect(SANITY_MIN_MS).toBe(1609459200000);
    expect(minHeader?.msText).toBe('1609459200000');
    expect(minOk.expected.ok).toBe(true);
    expect(minOk.expected.identity?.timestamp).toBe(1609459200);

    const baselineHeader = readSanitySignatureForAnchor(combinedHeader(findCase(SANITY_CASES, 'positive-baseline'), SANITY_SIG_HEADER) ?? '');

    const belowMin = findCase(SANITY_CASES, 'below-min-timestamp-is-malformed');
    const zeroMin = findCase(SANITY_CASES, 'zero-timestamp-below-min-is-malformed');
    const belowMinHeader = readSanitySignatureForAnchor(combinedHeader(belowMin, SANITY_SIG_HEADER) ?? '');
    const zeroMinHeader = readSanitySignatureForAnchor(combinedHeader(zeroMin, SANITY_SIG_HEADER) ?? '');

    expect(belowMinHeader).toBeNull();
    expect(zeroMinHeader).toBeNull();
    expect((combinedHeader(belowMin, SANITY_SIG_HEADER) ?? '').startsWith('t=1609459199999,')).toBe(true);
    expect((combinedHeader(zeroMin, SANITY_SIG_HEADER) ?? '').startsWith('t=0,')).toBe(true);
    expect(combinedHeader(belowMin, SANITY_SIG_HEADER)).toBe(`t=1609459199999,v1=${baselineHeader?.digestText ?? ''}`);
    expect(combinedHeader(zeroMin, SANITY_SIG_HEADER)).toBe(`t=0,v1=${baselineHeader?.digestText ?? ''}`);
    expect(belowMin.expected.reason).toBe('malformed-signature');
    expect(zeroMin.expected.reason).toBe('malformed-signature');
  });

  it('pins the contract grammar outcomes exactly, with no invented alternative codes', () => {
    const outcomes = [
      { id: 'missing-signature-header', reason: 'missing-signature' },
      { id: 'blank-signature-is-missing', reason: 'missing-signature' },
      { id: 't-only-is-malformed', reason: 'malformed-signature' },
      { id: 'v1-only-is-malformed', reason: 'malformed-signature' },
      { id: 'v2-only-is-malformed', reason: 'malformed-signature' },
      { id: 'reversed-field-order-is-malformed', reason: 'malformed-signature' },
      { id: 'space-separator-is-malformed', reason: 'malformed-signature' },
      { id: 'space-after-comma-is-malformed', reason: 'malformed-signature' },
      { id: 'semicolon-separator-is-malformed', reason: 'malformed-signature' },
      { id: 'outer-whitespace-is-malformed', reason: 'malformed-signature' },
      { id: 'key-space-t-is-malformed', reason: 'malformed-signature' },
      { id: 'inner-space-t-is-malformed', reason: 'malformed-signature' },
      { id: 'duplicate-t-even-equal-is-malformed', reason: 'malformed-signature' },
      { id: 'duplicate-v1-even-equal-is-malformed', reason: 'malformed-signature' },
      { id: 'extra-v2-field-is-malformed', reason: 'malformed-signature' },
      { id: 'digest-42-chars-is-malformed', reason: 'malformed-signature' },
      { id: 'digest-with-equals-padding-is-malformed', reason: 'malformed-signature' },
      { id: 'digest-standard-base64-chars-is-malformed', reason: 'malformed-signature' },
      { id: 'digest-noncanonical-padbits-is-malformed', reason: 'malformed-signature' },
      { id: 'below-min-timestamp-is-malformed', reason: 'malformed-signature' },
      { id: 'zero-timestamp-below-min-is-malformed', reason: 'malformed-signature' },
      { id: 'beyond-safe-t-is-malformed', reason: 'malformed-signature' },
      { id: 'leading-zero-t-is-malformed', reason: 'malformed-signature' },
      { id: 'negative-t-is-malformed', reason: 'malformed-signature' },
      { id: 'plus-signed-t-is-malformed', reason: 'malformed-signature' },
      { id: 'decimal-point-t-is-malformed', reason: 'malformed-signature' },
      { id: 'tampered-body', reason: 'invalid-signature' },
      { id: 'tampered-signed-timestamp-text', reason: 'invalid-signature' },
      { id: 'wrong-signature-beats-stale', reason: 'invalid-signature' },
      { id: 'rotation-old-secret-after-removal', reason: 'invalid-signature' },
      { id: 'boundary-plus301-omitted-tolerance', reason: 'timestamp-expired' },
      { id: 'fractional-boundary-plus-300-125-expired', reason: 'timestamp-expired' },
      { id: 'fractional-boundary-plus-300-001-mirrored-expired', reason: 'timestamp-expired' },
      { id: 'explicit-zero-drift-expired', reason: 'timestamp-expired' },
      { id: 'override-tolerance-60-past-expired', reason: 'timestamp-expired' },
      { id: 'boundary-minus301-omitted-tolerance', reason: 'timestamp-future' },
      { id: 'fractional-boundary-minus-300-025-future', reason: 'timestamp-future' },
      { id: 'fractional-boundary-minus-300-001-mirrored-future', reason: 'timestamp-future' },
    ];

    const mismatches = outcomes.flatMap(({ id, reason }) => {
      const fixture = findCase(SANITY_CASES, id);

      return fixture.expected.ok || fixture.expected.reason !== reason ? [`${id}: expected ${reason}`] : [];
    });

    expect(mismatches).toEqual([]);
  });

  it('pins the raw shapes behind the sanity header-field grammar failures', () => {
    expect(combinedHeader(findCase(SANITY_CASES, 'missing-signature-header'), SANITY_SIG_HEADER)).toBeUndefined();

    const blank = combinedHeader(findCase(SANITY_CASES, 'blank-signature-is-missing'), SANITY_SIG_HEADER) ?? '';

    expect(blank.length).toBeGreaterThan(0);
    expect(blank.trim()).toBe('');

    expect(combinedHeader(findCase(SANITY_CASES, 't-only-is-malformed'), SANITY_SIG_HEADER) ?? '').toBe('t=1700000000000');

    expect(combinedHeader(findCase(SANITY_CASES, 'v1-only-is-malformed'), SANITY_SIG_HEADER) ?? '').toMatch(/^v1=[A-Za-z0-9_-]{43}$/);

    expect(combinedHeader(findCase(SANITY_CASES, 'v2-only-is-malformed'), SANITY_SIG_HEADER) ?? '').toMatch(/^v2=[A-Za-z0-9_-]{43}$/);

    expect(combinedHeader(findCase(SANITY_CASES, 'reversed-field-order-is-malformed'), SANITY_SIG_HEADER) ?? '').toMatch(/^v1=[A-Za-z0-9_-]{43},t=\d+$/);

    expect(combinedHeader(findCase(SANITY_CASES, 'space-separator-is-malformed'), SANITY_SIG_HEADER) ?? '').toMatch(/^t=\d+ v1=[A-Za-z0-9_-]{43}$/);

    expect(combinedHeader(findCase(SANITY_CASES, 'space-after-comma-is-malformed'), SANITY_SIG_HEADER) ?? '').toMatch(/^t=\d+, v1=[A-Za-z0-9_-]{43}$/);

    expect(combinedHeader(findCase(SANITY_CASES, 'semicolon-separator-is-malformed'), SANITY_SIG_HEADER) ?? '').toMatch(/^t=\d+;v1=[A-Za-z0-9_-]{43}$/);

    expect(combinedHeader(findCase(SANITY_CASES, 'outer-whitespace-is-malformed'), SANITY_SIG_HEADER) ?? '').toMatch(/^ t=\d+,v1=[A-Za-z0-9_-]{43} $/);

    expect(combinedHeader(findCase(SANITY_CASES, 'key-space-t-is-malformed'), SANITY_SIG_HEADER) ?? '').toMatch(/^t =\d+,v1=[A-Za-z0-9_-]{43}$/);

    expect(combinedHeader(findCase(SANITY_CASES, 'inner-space-t-is-malformed'), SANITY_SIG_HEADER) ?? '').toMatch(/^t=\d+ \d+,v1=[A-Za-z0-9_-]{43}$/);

    expect(combinedHeader(findCase(SANITY_CASES, 'duplicate-t-even-equal-is-malformed'), SANITY_SIG_HEADER) ?? '').toMatch(/^t=\d+,t=\d+,v1=[A-Za-z0-9_-]{43}$/);

    expect(combinedHeader(findCase(SANITY_CASES, 'duplicate-v1-even-equal-is-malformed'), SANITY_SIG_HEADER) ?? '').toMatch(/^t=\d+,v1=[A-Za-z0-9_-]{43},v1=[A-Za-z0-9_-]{43}$/);

    expect(combinedHeader(findCase(SANITY_CASES, 'extra-v2-field-is-malformed'), SANITY_SIG_HEADER) ?? '').toMatch(/^t=\d+,v1=[A-Za-z0-9_-]{43},v2=[A-Za-z0-9_-]{43}$/);
  });

  it('pins the t-text failures that canonical-number or safety rules must reject', () => {
    const tTextProbes = [
      { id: 'beyond-safe-t-is-malformed', prefix: 't=9007199254740993,' },
      { id: 'leading-zero-t-is-malformed', prefix: 't=0170000000000,' },
      { id: 'negative-t-is-malformed', prefix: 't=-1,' },
      { id: 'plus-signed-t-is-malformed', prefix: 't=+' },
      { id: 'decimal-point-t-is-malformed', prefix: 't=1700000000000.5,' },
    ];

    for (const probe of tTextProbes) {
      const fixture = findCase(SANITY_CASES, probe.id);
      const value = combinedHeader(fixture, SANITY_SIG_HEADER) ?? '';

      expect(value.startsWith(probe.prefix)).toBe(true);
      expect(fixture.expected.reason).toBe('malformed-signature');
    }
  });

  it('pins the digest-shape rejections around the strict 43-character window', () => {
    const baselineHeader = readSanitySignatureForAnchor(combinedHeader(findCase(SANITY_CASES, 'positive-baseline'), SANITY_SIG_HEADER) ?? '');
    const baselineDigest = baselineHeader?.digestText ?? '';

    const short42 = findCase(SANITY_CASES, 'digest-42-chars-is-malformed');
    const short42Value = combinedHeader(short42, SANITY_SIG_HEADER) ?? '';
    const short42DigestOnly = short42Value.slice('t=1700000000000,v1='.length);

    expect(short42Value).toBe(`t=1700000000000,v1=${baselineDigest.slice(0, 42)}`);
    expect(short42DigestOnly).toMatch(SANITY_DIGEST_SHORT);
    expect(short42.expected.reason).toBe('malformed-signature');

    const padded = findCase(SANITY_CASES, 'digest-with-equals-padding-is-malformed');
    const paddedValue = combinedHeader(padded, SANITY_SIG_HEADER) ?? '';

    expect(paddedValue).toBe(`t=1700000000000,v1=${baselineDigest}=`);
    expect(paddedValue).toMatch(/^t=\d+,v1=[A-Za-z0-9_-]{43}=$/);
    expect(padded.expected.reason).toBe('malformed-signature');

    const swap = findCase(SANITY_CASES, 'digest-standard-base64-chars-is-malformed');
    const swapValue = combinedHeader(swap, SANITY_SIG_HEADER) ?? '';
    const swapDigestOnly = swapValue.slice('t=1700000000000,v1='.length);
    const mixedHeader = combinedHeader(findCase(SANITY_CASES, 'positive-mixed-case-base64url-digest'), SANITY_SIG_HEADER) ?? '';
    const mixedDigestOnly = mixedHeader.slice(mixedHeader.indexOf(',v1=') + ',v1='.length);

    expect(swapDigestOnly).toHaveLength(43);
    expect(/[+/]/.test(swapDigestOnly)).toBe(true);
    expect(swapDigestOnly.replaceAll('+', '-').replaceAll('/', '_')).toBe(mixedDigestOnly);
    expect(swap.expected.reason).toBe('malformed-signature');

    const padbits = findCase(SANITY_CASES, 'digest-noncanonical-padbits-is-malformed');
    const padbitsValue = combinedHeader(padbits, SANITY_SIG_HEADER) ?? '';
    const padbitsDigestOnly = padbitsValue.slice('t=1700000000000,v1='.length);

    expect(padbitsValue).toMatch(/^t=\d+,v1=[A-Za-z0-9_-]{43}$/);
    expect(readSanitySignatureForAnchor(padbitsValue)).toBeNull();

    const padbitsBytes = Buffer.from(padbitsDigestOnly, 'base64url');

    expect(padbitsBytes.byteLength).toBe(32);
    expect(padbitsBytes.toString('base64url')).not.toBe(padbitsDigestOnly);
    expect(padbitsBytes.equals(Buffer.from(baselineDigest, 'base64url'))).toBe(true);
    expect(padbits.expected.reason).toBe('malformed-signature');
  });

  it('signs empty, NUL, non-JSON and invalid-UTF-8 bodies as opaque bytes', () => {
    expect(fixtureBytes(findCase(SANITY_CASES, 'empty-body-signed')).length).toBe(0);

    const nulBytes = fixtureBytes(findCase(SANITY_CASES, 'nul-byte-body-signed'));

    expect([...nulBytes]).toEqual([0x00, 0x01, 0x02]);
    expect(() => UTF8_STRICT.decode(fixtureBytes(findCase(SANITY_CASES, 'invalid-utf8-body-signed')))).toThrow();
    expect(() => JSON.parse(UTF8_LOOSE.decode(fixtureBytes(findCase(SANITY_CASES, 'non-json-body-signed'))))).toThrow();
  });

  it('checks fixture MACs against retained and removed secret accept-sets', () => {
    const acceptCase = findCase(SANITY_CASES, 'rotation-both-secrets-accept-old');
    const removalCase = findCase(SANITY_CASES, 'rotation-old-secret-after-removal');
    const acceptHeader = readSanitySignatureForAnchor(combinedHeader(acceptCase, SANITY_SIG_HEADER) ?? '');
    const removalHeader = readSanitySignatureForAnchor(combinedHeader(removalCase, SANITY_SIG_HEADER) ?? '');

    expect(acceptCase.options.secrets).toEqual([SANITY_MAIN_SECRET, SANITY_NEW_SECRET]);
    expect(acceptCase.expected.ok).toBe(true);
    expect(sanitySignatureVerifies(acceptCase, acceptHeader?.msText ?? '', acceptHeader?.digestText ?? '', fixtureBytes(acceptCase))).toBe(true);

    expect(removalHeader?.digestText).toBe(acceptHeader?.digestText);
    expect(removalHeader?.msText).toBe(acceptHeader?.msText);
    expect(removalCase.options.secrets).toEqual([SANITY_NEW_SECRET]);
    expect(removalCase.expected.reason).toBe('invalid-signature');
    expect(sanitySignatureVerifies(removalCase, removalHeader?.msText ?? '', removalHeader?.digestText ?? '', fixtureBytes(removalCase))).toBe(false);
    expect(removalHeader?.digestText).toBe(sanityDigestWith(SANITY_MAIN_SECRET, removalHeader?.msText ?? '', fixtureBytes(removalCase)));
  });
});

describe('across the two hex corpora', () => {
  it('contrasts the same sha1 shape sentry declares malformed and doppler declares unsupported', () => {
    const sentryFixture = findCase(SENTRY_CASES, 'sha1-prefixed-64-hex-is-malformed');
    const dopplerFixture = findCase(DOPPLER_CASES, 'sha1-64-hex-is-unsupported-scheme');

    expect(sentryFixture.expected.reason).toBe('malformed-signature');
    expect(dopplerFixture.expected.reason).toBe('unsupported-scheme');
  });
});
