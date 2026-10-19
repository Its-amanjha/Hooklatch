import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { combinedHeader, fixtureBytes } from '../verification/helpers.js';
import type { FixtureCase } from '../verification/helpers.js';

/**
 * Stage A anchor suite for the four phase-4 fixture files (dodo-payments,
 * gitlab, replicate, workos). It never imports provider modules, the Provider
 * union, or verification entry points: the new provider IDs stay unregistered
 * and these tests validate fixture data only. Every positive and
 * freshness-only signature is re-derived with node:crypto from the recorded
 * header text and exact bytes; deliberately invalid well-formed signatures are
 * proven to match no configured secret; grammar failures keep their exact
 * contract reasons.
 */

interface Phase4FixtureFile {
  readonly cases: readonly FixtureCase[];
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isIdentityValue(value: unknown): value is string | number | null {
  return value === null || typeof value === 'string' || typeof value === 'number';
}

function isHeaderValue(value: unknown): value is string | readonly string[] {
  return isString(value) || (Array.isArray(value) && value.every(isString));
}

/** Mirrors the shared loader's schema guard; the shared loader is legacy-files-only and must stay unchanged. */
function isFixtureFile(value: unknown): value is Phase4FixtureFile {
  if (typeof value !== 'object' || value === null || !('cases' in value) || !Array.isArray(value.cases)) return false;

  return value.cases.every((entry: unknown): entry is FixtureCase => {
    if (typeof entry !== 'object' || entry === null) return false;

    if (!('id' in entry) || typeof entry.id !== 'string') return false;

    if (!('request' in entry) || typeof entry.request !== 'object' || entry.request === null) return false;

    if (!('bodyBase64' in entry.request) || typeof entry.request.bodyBase64 !== 'string') return false;

    if (!('headers' in entry.request) || typeof entry.request.headers !== 'object' || entry.request.headers === null) return false;

    if (!Object.values(entry.request.headers).every(isHeaderValue)) return false;

    if (!('options' in entry) || typeof entry.options !== 'object' || entry.options === null) return false;

    if (!('secrets' in entry.options) || !Array.isArray(entry.options.secrets) || !entry.options.secrets.every(isString)) return false;

    if (!('now' in entry.options) || typeof entry.options.now !== 'number') return false;

    if ('toleranceSeconds' in entry.options && typeof entry.options.toleranceSeconds !== 'number') return false;

    if (!('expected' in entry) || typeof entry.expected !== 'object' || entry.expected === null) return false;

    if (!('ok' in entry.expected) || typeof entry.expected.ok !== 'boolean') return false;

    if ('reason' in entry.expected && typeof entry.expected.reason !== 'string') return false;

    if ('identity' in entry.expected) {
      const identity = entry.expected.identity;

      if (typeof identity !== 'object' || identity === null) return false;

      if (!('deliveryId' in identity) || !isIdentityValue(identity.deliveryId)) return false;

      if (!('eventId' in identity) || !isIdentityValue(identity.eventId)) return false;

      if (!('timestamp' in identity) || (identity.timestamp !== null && typeof identity.timestamp !== 'number')) return false;

      if (!('authenticatedFields' in identity) || !Array.isArray(identity.authenticatedFields) || !identity.authenticatedFields.every(isString)) return false;
    }

    if (!('provenance' in entry) || typeof entry.provenance !== 'object' || entry.provenance === null) return false;

    if (!('class' in entry.provenance) || (entry.provenance.class !== 'reference' && entry.provenance.class !== 'local')) return false;

    if ('commit' in entry.provenance && typeof entry.provenance.commit !== 'string') return false;

    if ('fetched' in entry.provenance && typeof entry.provenance.fetched !== 'string') return false;

    if ('notes' in entry && typeof entry.notes !== 'string') return false;

    return 'source' in entry.provenance && typeof entry.provenance.source === 'string';
  });
}

function loadPhase4FixtureFile(fileName: string): readonly FixtureCase[] {
  const raw = readFileSync(new URL(`../fixtures/${fileName}`, import.meta.url), 'utf8');
  const parsed: unknown = JSON.parse(raw);

  if (!isFixtureFile(parsed)) throw new Error(`Phase 4 fixture file ${fileName} is malformed`);

  return parsed.cases;
}

function findCase(cases: readonly FixtureCase[], id: string): FixtureCase {
  const found = cases.find((fixture) => fixture.id === id);

  if (found === undefined) throw new Error(`Fixture case not found: ${id}`);

  return found;
}

const CANONICAL_ID_HEADER = 'webhook-id';
const CANONICAL_TS_HEADER = 'webhook-timestamp';
const CANONICAL_SIG_HEADER = 'webhook-signature';
const WORKOS_SIG_HEADER = 'workos-signature';
const GITLAB_TOKEN_HEADER = 'x-gitlab-token';
const LEGACY_TOKEN = 'hooklatch_stage_a_legacy_token';

const BASE64_TOKEN = /^[A-Za-z0-9+/]+={0,2}$/;
const SCHEME_TOKEN = /^[A-Za-z0-9_-]+$/;
const HEX_64 = /^[0-9a-f]{64}$/i;
const HEX_CHARS = /^[0-9a-f]*$/i;
const CANONICAL_DECIMAL = /^(?:0|[1-9]\d*)$/;

const UTF8_LOOSE = new TextDecoder('utf-8');
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true });

/** Frozen contract failure vocabulary for the three Standard Webhooks providers. */
const CANONICAL_REASONS = new Set([
  'missing-signature',
  'malformed-signature',
  'unsupported-scheme',
  'missing-identity',
  'missing-timestamp',
  'invalid-signature',
  'timestamp-expired',
  'timestamp-future',
]);

/** Frozen contract failure vocabulary for WorkOS, which has no identity headers. */
const WORKOS_REASONS = new Set([
  'missing-signature',
  'malformed-signature',
  'unsupported-scheme',
  'missing-timestamp',
  'invalid-signature',
  'timestamp-expired',
  'timestamp-future',
]);

const DODO_CASE_IDS = [
  'positive-baseline',
  'positive-extra-unsigned-header-ignored',
  'positive-bare-base64-secret',
  'rotation-both-signatures',
  'rotation-old-secret-after-removal',
  'boundary-plus300-omitted-tolerance',
  'boundary-plus301-omitted-tolerance',
  'boundary-minus300-omitted-tolerance',
  'boundary-minus301-omitted-tolerance',
  'zero-width-exact-ok',
  'zero-width-drift-expired',
  'wrong-signature-beats-stale',
  'tampered-body',
  'tampered-webhook-id',
  'empty-body-signed',
  'non-json-body-signed',
  'invalid-utf8-body-signed',
  'missing-signature-header',
  'whitespace-only-signature-is-missing',
  'malformed-v1-token-is-malformed',
  'trailing-comma-token-is-malformed',
  'comma-combined-duplicates-fail',
  'malformed-sibling-poisons',
  'v2-only-token-is-unsupported-scheme',
  'v2-with-valid-v1-accepted',
  'missing-webhook-id-is-missing-identity',
  'webhook-id-with-dot-is-malformed',
  'webhook-id-with-comma-is-malformed',
  'missing-webhook-timestamp-is-missing-timestamp',
  'zero-padded-timestamp-is-malformed',
  'branded-svix-headers-alone-missing',
];

const GITLAB_CASE_IDS = [
  'positive-baseline',
  'positive-extra-unsigned-header-ignored',
  'positive-bare-base64-secret',
  'rotation-both-signatures',
  'rotation-old-secret-after-removal',
  'boundary-plus300-omitted-tolerance',
  'boundary-plus301-omitted-tolerance',
  'boundary-minus300-omitted-tolerance',
  'boundary-minus301-omitted-tolerance',
  'zero-width-exact-ok',
  'zero-width-drift-expired',
  'wrong-signature-beats-stale',
  'tampered-body',
  'tampered-webhook-id',
  'empty-body-signed',
  'non-json-body-signed',
  'invalid-utf8-body-signed',
  'missing-signature-header',
  'whitespace-only-signature-is-missing',
  'malformed-v1-token-is-malformed',
  'trailing-comma-token-is-malformed',
  'comma-combined-duplicates-fail',
  'malformed-sibling-poisons',
  'v2-only-token-is-unsupported-scheme',
  'v2-with-valid-v1-accepted',
  'missing-webhook-id-is-missing-identity',
  'webhook-id-with-dot-is-malformed',
  'webhook-id-with-comma-is-malformed',
  'missing-webhook-timestamp-is-missing-timestamp',
  'zero-padded-timestamp-is-malformed',
  'branded-svix-headers-alone-missing',
  'legacy-token-ignored-with-valid-signature',
  'legacy-token-no-fallback-on-invalid-signature',
  'legacy-token-only-is-missing-signature',
];

const REPLICATE_CASE_IDS = [
  'positive-baseline',
  'positive-extra-unsigned-header-ignored',
  'positive-bare-base64-secret',
  'rotation-both-signatures',
  'rotation-old-secret-after-removal',
  'boundary-plus300-omitted-tolerance',
  'boundary-plus301-omitted-tolerance',
  'boundary-minus300-omitted-tolerance',
  'boundary-minus301-omitted-tolerance',
  'zero-width-exact-ok',
  'zero-width-drift-expired',
  'wrong-signature-beats-stale',
  'tampered-body',
  'tampered-webhook-id',
  'empty-body-signed',
  'non-json-body-signed',
  'invalid-utf8-body-signed',
  'missing-signature-header',
  'whitespace-only-signature-is-missing',
  'malformed-v1-token-is-malformed',
  'trailing-comma-token-is-malformed',
  'comma-combined-duplicates-fail',
  'malformed-sibling-poisons',
  'v2-only-token-is-unsupported-scheme',
  'v2-with-valid-v1-accepted',
  'missing-webhook-id-is-missing-identity',
  'webhook-id-with-dot-is-malformed',
  'webhook-id-with-comma-is-malformed',
  'missing-webhook-timestamp-is-missing-timestamp',
  'zero-padded-timestamp-is-malformed',
  'branded-svix-headers-alone-missing',
];

const WORKOS_CASE_IDS = [
  'positive-baseline',
  'positive-fractional-identity-t125',
  'positive-fractional-identity-t250',
  'positive-fractional-identity-t500',
  'positive-mixed-case-hex-accepted',
  'positive-outer-whitespace-accepted',
  'positive-field-order-independent',
  'positive-unknown-v2-field-accepted',
  'positive-unknown-v0-sibling-accepted',
  'rotation-repeated-v1-distinct-keys',
  'rotation-repeated-v1-same-value',
  'boundary-plus-180-omitted-ok',
  'boundary-plus-180-001-expired',
  'boundary-minus-180-omitted-ok',
  'boundary-minus-180-001-future',
  'fractional-boundary-plus-180-125-expired',
  'fractional-boundary-minus-180-25-future',
  'fractional-boundary-inside-plus-179-875-ok',
  'fractional-boundary-inside-minus-179-5-ok',
  'explicit-zero-fractional-exact-ok',
  'explicit-zero-drift-expired',
  'override-tolerance-60-at-edge-ok',
  'override-tolerance-60-past-expired',
  'wrong-signature-beats-stale',
  'tampered-body',
  'hex-lookalike-secret-literal-verified',
  'hex-decoded-key-trap-rejected',
  'empty-body-signed',
  'non-json-body-signed',
  'invalid-utf8-body-signed',
  'bom-prefixed-body-signed',
  'canonical-zero-timestamp-ok',
  'missing-workos-signature-header',
  'blank-workos-signature-header',
  'h1-style-semicolon-is-malformed',
  'h1-style-comma-sibling-unsupported',
  'stripe-legacy-v0-only-unsupported',
  'unknown-empty-value-is-malformed',
  'unknown-inner-space-is-malformed',
  'unknown-comma-value-is-malformed',
  'unknown-extra-equals-is-malformed',
  'trailing-comma-empty-segment-is-malformed',
  'segment-without-equals-is-malformed',
  'space-in-key-is-malformed',
  'space-after-equals-is-malformed',
  'duplicate-t-even-equal-is-malformed',
  'leading-zero-t-is-malformed',
  'plus-signed-t-is-malformed',
  'decimal-point-t-is-malformed',
  'negative-t-is-malformed',
  'beyond-safe-t-is-malformed',
  'inner-space-t-is-malformed',
  'empty-value-t-is-malformed',
  'v1-without-t-is-missing-timestamp',
  't-only-is-missing-signature',
  'non-hex-v1-sibling-poisons',
  'short-v1-sibling-poisons',
  'combined-duplicate-header-is-malformed',
];

const DODO_CASES = loadPhase4FixtureFile('dodo-payments.json');
const GITLAB_CASES = loadPhase4FixtureFile('gitlab.json');
const REPLICATE_CASES = loadPhase4FixtureFile('replicate.json');
const WORKOS_CASES = loadPhase4FixtureFile('workos.json');

interface CanonicalGroup {
  readonly label: string;
  readonly cases: readonly FixtureCase[];
  readonly sourceMarker: string;
}

const CANONICAL_GROUPS: readonly CanonicalGroup[] = [
  { label: 'dodo-payments', cases: DODO_CASES, sourceMarker: 'https://docs.dodopayments.com/developer-resources/webhooks' },
  { label: 'gitlab', cases: GITLAB_CASES, sourceMarker: 'https://docs.gitlab.com/user/project/integrations/webhooks/' },
  { label: 'replicate', cases: REPLICATE_CASES, sourceMarker: 'https://replicate.com/docs/topics/webhooks/verify-webhook' },
];

const WORKOS_SOURCE_DOC = 'https://workos.com/docs/events/data-syncing/webhooks';
const WORKOS_SOURCE_SDK_COMMIT = 'ad8bff226e9b37435f0c62390318d4819f76b3d1';

interface CanonicalAnchorHeader {
  readonly v1Values: readonly string[];
  readonly otherTokens: readonly string[];
}

interface WorkosAnchorHeader {
  readonly tText: string;
  readonly v1Values: readonly string[];
}

/**
 * Anchor-side readers for the well-formed subsets of the two phase-4 header
 * grammars. They are not the SDK parsers and never decide failure outcomes;
 * they are only invoked where the fixture expectation is acceptance, a
 * freshness-only failure, or a well-formed but wrong signature.
 */
function readCanonicalHeaderForAnchor(value: string): CanonicalAnchorHeader | null {
  if (value.trim().length === 0) return null;

  const tokens = value.split(/\s+/);

  if (tokens.some((token) => token.length === 0)) return null;

  const v1Values: string[] = [];
  const otherTokens: string[] = [];

  for (const token of tokens) {
    const split = token.indexOf(',');

    if (split <= 0) return null;

    const version = token.slice(0, split);
    const tokenValue = token.slice(split + 1);

    if (!SCHEME_TOKEN.test(version) || tokenValue.length === 0) return null;

    if (version === 'v1') {
      if (!BASE64_TOKEN.test(tokenValue)) return null;

      v1Values.push(tokenValue);
    } else {
      otherTokens.push(token);
    }
  }

  if (v1Values.length === 0) return null;

  return { v1Values, otherTokens };
}

function readWorkosHeaderForAnchor(value: string): WorkosAnchorHeader | null {
  if (value.trim().length === 0) return null;

  const segments = value.split(',').map((segment) => segment.trim());

  if (segments.some((segment) => segment.length === 0)) return null;

  const tValues: string[] = [];
  const v1Values: string[] = [];

  for (const segment of segments) {
    const split = segment.indexOf('=');

    if (split <= 0) return null;

    const key = segment.slice(0, split);
    const fieldValue = segment.slice(split + 1);

    if (fieldValue.length === 0 || fieldValue.includes('=')) return null;

    if (key === 't') {
      tValues.push(fieldValue);
    } else if (key === 'v1') {
      if (!HEX_64.test(fieldValue)) return null;

      v1Values.push(fieldValue.toLowerCase());
    }
  }

  if (tValues.length !== 1 || v1Values.length === 0) return null;

  const [tText] = tValues;

  if (tText === undefined) return null;

  if (!CANONICAL_DECIMAL.test(tText) || !Number.isSafeInteger(Number(tText))) return null;

  return { tText, v1Values };
}

/** Documented canonical recipe: strip an optional whsec_ prefix, base64-decode the rest. */
function decodeCanonicalSecret(secret: string): Uint8Array {
  const encoded = secret.startsWith('whsec_')
    ? secret.slice('whsec_'.length)
    : secret;

  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);

  return bytes;
}

function decodeBase64Token(tokenValue: string): Uint8Array {
  const binary = atob(tokenValue);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);

  return bytes;
}

function canonicalVerifies(fixture: FixtureCase, idText: string, tsText: string, tokenValue: string, bytes: Uint8Array): boolean {
  return fixture.options.secrets.some((secret) =>
    createHmac('sha256', decodeCanonicalSecret(secret)).update(`${idText}.${tsText}.`).update(bytes).digest('base64') === tokenValue);
}

function workosVerifies(fixture: FixtureCase, tText: string, hexValue: string, bytes: Uint8Array): boolean {
  return fixture.options.secrets.some((secret) =>
    createHmac('sha256', secret).update(`${tText}.`).update(bytes).digest('hex') === hexValue.toLowerCase());
}

describe('phase 4 fixture inventory', () => {
  it('loads the four new fixture files with the pinned case counts and ids', () => {
    expect(DODO_CASES.map((fixture) => fixture.id)).toEqual(DODO_CASE_IDS);
    expect(GITLAB_CASES.map((fixture) => fixture.id)).toEqual(GITLAB_CASE_IDS);
    expect(REPLICATE_CASES.map((fixture) => fixture.id)).toEqual(REPLICATE_CASE_IDS);
    expect(WORKOS_CASES.map((fixture) => fixture.id)).toEqual(WORKOS_CASE_IDS);
  });

  it('keeps every case fully local because no published vectors exist for the four', () => {
    const allCases = [...DODO_CASES, ...GITLAB_CASES, ...REPLICATE_CASES, ...WORKOS_CASES];

    expect(allCases.every((fixture) => fixture.provenance.class === 'local')).toBe(true);
    expect(allCases.every((fixture) => !('commit' in fixture.provenance) && !('fetched' in fixture.provenance))).toBe(true);
  });

  it('pins the primary research sources in every provenance string', () => {
    const missingSources = [
      ...CANONICAL_GROUPS.map(({ label, cases, sourceMarker }) => ({ label, cases, sourceMarker })),
      { label: 'workos', cases: WORKOS_CASES, sourceMarker: WORKOS_SOURCE_DOC },
    ].flatMap(({ label, cases, sourceMarker }) => (cases.every((fixture) => fixture.provenance.source.includes(sourceMarker))
      ? []
      : [`${label}: provenance does not cite the primary documentation page`]));

    const workosSdkPins = WORKOS_CASES.every((fixture) => fixture.provenance.source.includes(WORKOS_SOURCE_SDK_COMMIT));

    expect(missingSources).toEqual([]);
    expect(workosSdkPins).toBe(true);
  });

  it('restricts every failure reason to the frozen contract vocabulary', () => {
    for (const fixture of [...DODO_CASES, ...GITLAB_CASES, ...REPLICATE_CASES]) {
      if (fixture.expected.ok) {
        expect(fixture.expected.reason).toBeUndefined();

        continue;
      }

      expect(CANONICAL_REASONS.has(fixture.expected.reason ?? '')).toBe(true);
    }

    for (const fixture of WORKOS_CASES) {
      if (fixture.expected.ok) {
        expect(fixture.expected.reason).toBeUndefined();

        continue;
      }

      expect(WORKOS_REASONS.has(fixture.expected.reason ?? '')).toBe(true);
      expect(fixture.expected.reason).not.toBe('missing-identity');
    }
  });

  it('exercises the canonical-only identity failure in every canonical corpus', () => {
    for (const { cases } of CANONICAL_GROUPS) {
      expect(cases.some((fixture) => fixture.expected.reason === 'missing-identity')).toBe(true);
    }
  });
});

describe('canonical fixture anchors', () => {
  it('recalculates every positive signature from the recorded inputs and pins identity', () => {
    const problems = CANONICAL_GROUPS.flatMap(({ label, cases }) => cases.flatMap((fixture) => {
      if (!fixture.expected.ok) return [];

      const recorded = combinedHeader(fixture, CANONICAL_SIG_HEADER);
      const idText = combinedHeader(fixture, CANONICAL_ID_HEADER);
      const tsText = combinedHeader(fixture, CANONICAL_TS_HEADER);

      if (recorded === undefined || idText === undefined || tsText === undefined) return [`${label}/${fixture.id}: positive case lacks its three headers`];

      const anchorHeader = readCanonicalHeaderForAnchor(recorded);

      if (anchorHeader === null) return [`${label}/${fixture.id}: positive header is outside the well-formed anchor subset`];

      if (anchorHeader.otherTokens.length > 0 && !['v2-with-valid-v1-accepted'].includes(fixture.id)) {
        return [`${label}/${fixture.id}: non-v1 token only documented for the tolerating case`];
      }

      if (!canonicalIdentityWellFormed(idText, tsText)) return [`${label}/${fixture.id}: identity headers fail the canonical grammar`];

      const bytes = fixtureBytes(fixture);

      const unverified = anchorHeader.v1Values.flatMap((tokenValue) => (canonicalVerifies(fixture, idText, tsText, tokenValue, bytes)
        ? []
        : [`${label}/${fixture.id}: v1 token ${tokenValue.slice(0, 12)} does not verify against any configured secret`]));

      const identity = fixture.expected.identity;

      if (identity?.eventId !== idText || identity?.timestamp !== Number(tsText)) {
        return [...unverified, `${label}/${fixture.id}: identity does not match the signed headers`];
      }

      if (identity?.deliveryId !== null || identity?.authenticatedFields.length !== 2
        || identity?.authenticatedFields[0] !== 'eventId' || identity?.authenticatedFields[1] !== 'timestamp') {
        return [...unverified, `${label}/${fixture.id}: identity metadata is not the canonical map`];
      }

      return unverified;
    }));

    expect(problems).toEqual([]);
  });

  it('keeps every configured canonical secret inside the 24-64 byte key window', () => {
    const outOfRange = [...DODO_CASES, ...GITLAB_CASES, ...REPLICATE_CASES].flatMap((fixture) => fixture.options.secrets.flatMap(
      (secret) => {
        const decoded = decodeCanonicalSecret(secret);

        return decoded.byteLength >= 24 && decoded.byteLength <= 64 ? [] : [`${fixture.id}: decoded key length ${decoded.byteLength}`];
      },
    ));

    expect(outOfRange).toEqual([]);
  });

  it('proves every deliberately invalid well-formed signature matches no configured secret', () => {
    const mismatches = CANONICAL_GROUPS.flatMap(({ label, cases }) => cases.flatMap((fixture) => {
      if (fixture.expected.reason !== 'invalid-signature') return [];

      const anchorHeader = readCanonicalHeaderForAnchor(combinedHeader(fixture, CANONICAL_SIG_HEADER) ?? '');
      const idText = combinedHeader(fixture, CANONICAL_ID_HEADER) ?? '';
      const tsText = combinedHeader(fixture, CANONICAL_TS_HEADER) ?? '';

      if (anchorHeader === null || !canonicalIdentityWellFormed(idText, tsText)) {
        return [`${label}/${fixture.id}: invalid-signature fixture is not well-formed`];
      }

      const bytes = fixtureBytes(fixture);
      const tooShort = anchorHeader.v1Values.some((tokenValue) => tokenValue.length !== 44 || decodeBase64Token(tokenValue).byteLength !== 32);

      if (tooShort) return [`${label}/${fixture.id}: invalid-signature token is not 32 encoded bytes`];

      const verified = anchorHeader.v1Values.some((tokenValue) => canonicalVerifies(fixture, idText, tsText, tokenValue, bytes));

      return verified ? [`${label}/${fixture.id}: supposedly invalid signature actually verifies`] : [];
    }));

    expect(mismatches).toEqual([]);
  });

  it('proves the MAC stays valid for every canonical freshness-only failure', () => {
    const unverified = CANONICAL_GROUPS.flatMap(({ label, cases }) => cases.flatMap((fixture) => {
      const freshnessOnly = fixture.expected.reason === 'timestamp-expired' || fixture.expected.reason === 'timestamp-future';

      if (!freshnessOnly) return [];

      const anchorHeader = readCanonicalHeaderForAnchor(combinedHeader(fixture, CANONICAL_SIG_HEADER) ?? '');
      const idText = combinedHeader(fixture, CANONICAL_ID_HEADER) ?? '';
      const tsText = combinedHeader(fixture, CANONICAL_TS_HEADER) ?? '';

      if (anchorHeader === null || !canonicalIdentityWellFormed(idText, tsText)) {
        return [`${label}/${fixture.id}: freshness-only fixture is not well-formed`];
      }

      const verified = anchorHeader.v1Values.some((tokenValue) => canonicalVerifies(fixture, idText, tsText, tokenValue, fixtureBytes(fixture)));

      return verified ? [] : [`${label}/${fixture.id}: freshness-only failure has no valid MAC`];
    }));

    expect(unverified).toEqual([]);
  });

  it('pins the canonical 300-second symmetric boundary with tolerance omitted', () => {
    const boundaries = [
      { id: 'boundary-plus300-omitted-tolerance', drift: 300, ok: true },
      { id: 'boundary-plus301-omitted-tolerance', drift: 301, ok: false },
      { id: 'boundary-minus300-omitted-tolerance', drift: -300, ok: true },
      { id: 'boundary-minus301-omitted-tolerance', drift: -301, ok: false },
    ];

    for (const { cases } of CANONICAL_GROUPS) {
      for (const { id, drift, ok } of boundaries) {
        const fixture = findCase(cases, id);
        const tsText = combinedHeader(fixture, CANONICAL_TS_HEADER) ?? '';

        expect('toleranceSeconds' in fixture.options).toBe(false);
        expect(Number(tsText)).toBe(1700000000);
        expect(fixture.options.now - Number(tsText)).toBe(drift);
        expect(fixture.expected.ok).toBe(ok);

        if (ok) {
          expect(fixture.expected.identity?.timestamp).toBe(1700000000);

          continue;
        }

        expect(fixture.expected.reason).toBe(drift > 0 ? 'timestamp-expired' : 'timestamp-future');
        expect(fixture.expected.identity).toBeUndefined();
      }
    }
  });

  it('pins the explicit zero-width tolerance separately from the omitted default', () => {
    for (const { cases } of CANONICAL_GROUPS) {
      const exact = findCase(cases, 'zero-width-exact-ok');
      const late = findCase(cases, 'zero-width-drift-expired');

      expect(exact.options.toleranceSeconds).toBe(0);
      expect(late.options.toleranceSeconds).toBe(0);
      expect(exact.options.now - 1700000000).toBe(0);
      expect(late.options.now - 1700000000).toBe(1);
      expect(exact.expected.ok).toBe(true);
      expect(exact.expected.identity?.timestamp).toBe(1700000000);
      expect(late.expected.ok).toBe(false);
      expect(late.expected.reason).toBe('timestamp-expired');
      expect(late.expected.identity).toBeUndefined();
    }
  });

  it('checks the MAC before the clock on the wrong-before-stale inputs', () => {
    for (const { cases } of CANONICAL_GROUPS) {
      const fixture = findCase(cases, 'wrong-signature-beats-stale');
      const tsText = combinedHeader(fixture, CANONICAL_TS_HEADER) ?? '';

      expect(fixture.options.now - Number(tsText)).toBe(301);
      expect(fixture.expected.ok).toBe(false);
      expect(fixture.expected.reason).toBe('invalid-signature');
      expect(fixture.expected.identity).toBeUndefined();
    }
  });

  it('keeps the recorded signature untouched while tampering the body or the id', () => {
    for (const { cases } of CANONICAL_GROUPS) {
      const baseline = findCase(cases, 'positive-baseline');
      const bodyTamper = findCase(cases, 'tampered-body');
      const idTamper = findCase(cases, 'tampered-webhook-id');

      expect(bodyTamper.request.bodyBase64).not.toBe(baseline.request.bodyBase64);
      expect(bodyTamper.request.headers).toEqual(baseline.request.headers);
      expect(bodyTamper.expected.reason).toBe('invalid-signature');

      expect(idTamper.request.bodyBase64).toBe(baseline.request.bodyBase64);
      expect(combinedHeader(idTamper, CANONICAL_ID_HEADER)).not.toBe(combinedHeader(baseline, CANONICAL_ID_HEADER));
      expect(combinedHeader(idTamper, CANONICAL_SIG_HEADER)).toBe(combinedHeader(baseline, CANONICAL_SIG_HEADER));
      expect(idTamper.expected.reason).toBe('invalid-signature');
    }
  });

  it('pins the contract grammar outcomes exactly, with no invented alternative codes', () => {
    const outcomes = [
      { id: 'missing-signature-header', reason: 'missing-signature' },
      { id: 'whitespace-only-signature-is-missing', reason: 'missing-signature' },
      { id: 'branded-svix-headers-alone-missing', reason: 'missing-signature' },
      { id: 'malformed-v1-token-is-malformed', reason: 'malformed-signature' },
      { id: 'trailing-comma-token-is-malformed', reason: 'malformed-signature' },
      { id: 'comma-combined-duplicates-fail', reason: 'malformed-signature' },
      { id: 'malformed-sibling-poisons', reason: 'malformed-signature' },
      { id: 'webhook-id-with-dot-is-malformed', reason: 'malformed-signature' },
      { id: 'webhook-id-with-comma-is-malformed', reason: 'malformed-signature' },
      { id: 'zero-padded-timestamp-is-malformed', reason: 'malformed-signature' },
      { id: 'missing-webhook-id-is-missing-identity', reason: 'missing-identity' },
      { id: 'missing-webhook-timestamp-is-missing-timestamp', reason: 'missing-timestamp' },
      { id: 'v2-only-token-is-unsupported-scheme', reason: 'unsupported-scheme' },
    ];

    const acceptedIds = [
      'positive-baseline',
      'positive-extra-unsigned-header-ignored',
      'positive-bare-base64-secret',
      'rotation-both-signatures',
      'v2-with-valid-v1-accepted',
      'empty-body-signed',
      'non-json-body-signed',
      'invalid-utf8-body-signed',
    ];

    const mismatches = CANONICAL_GROUPS.flatMap(({ label, cases }) => outcomes.flatMap(({ id, reason }) => {
      const fixture = findCase(cases, id);

      return fixture.expected.ok || fixture.expected.reason !== reason ? [`${label}/${id}: expected ${reason}`] : [];
    }));

    const unacceptable = CANONICAL_GROUPS.flatMap(({ label, cases }) => acceptedIds.flatMap((id) => {
      const fixture = findCase(cases, id);

      return fixture.expected.ok && fixture.expected.identity !== undefined ? [] : [`${label}/${id}: expected acceptance with identity`];
    }));

    expect(mismatches).toEqual([]);
    expect(unacceptable).toEqual([]);
  });

  it('pins the raw shapes behind the canonical grammar failures', () => {
    for (const { cases } of CANONICAL_GROUPS) {
      expect(combinedHeader(findCase(cases, 'missing-signature-header'), CANONICAL_SIG_HEADER)).toBeUndefined();
      expect((combinedHeader(findCase(cases, 'whitespace-only-signature-is-missing'), CANONICAL_SIG_HEADER) ?? '').trim()).toBe('');

      const malformed = combinedHeader(findCase(cases, 'malformed-v1-token-is-malformed'), CANONICAL_SIG_HEADER) ?? '';

      expect(malformed).toBe('v1,@@@@');

      const trailing = combinedHeader(findCase(cases, 'trailing-comma-token-is-malformed'), CANONICAL_SIG_HEADER) ?? '';

      expect(trailing.endsWith(',')).toBe(true);

      const combined = combinedHeader(findCase(cases, 'comma-combined-duplicates-fail'), CANONICAL_SIG_HEADER) ?? '';

      expect(combined.includes(', ')).toBe(true);

      const poisoned = (combinedHeader(findCase(cases, 'malformed-sibling-poisons'), CANONICAL_SIG_HEADER) ?? '').split(/\s+/);

      expect(poisoned.length).toBe(2);
      expect(poisoned[1]).toBe('v1,@@@@');

      const v2Only = combinedHeader(findCase(cases, 'v2-only-token-is-unsupported-scheme'), CANONICAL_SIG_HEADER) ?? '';

      expect(v2Only.startsWith('v2,')).toBe(true);
      expect(BASE64_TOKEN.test(v2Only.slice(3))).toBe(true);

      const toleratedCase = findCase(cases, 'v2-with-valid-v1-accepted');
      const tolerated = (combinedHeader(toleratedCase, CANONICAL_SIG_HEADER) ?? '').split(/\s+/);

      expect(tolerated.map((token) => token.startsWith('v1,') || token.startsWith('v2,')).every(Boolean)).toBe(true);

      expect(combinedHeader(findCase(cases, 'missing-webhook-id-is-missing-identity'), CANONICAL_ID_HEADER)).toBeUndefined();

      const dotted = combinedHeader(findCase(cases, 'webhook-id-with-dot-is-malformed'), CANONICAL_ID_HEADER) ?? '';

      expect(dotted.includes('.')).toBe(true);

      const commatized = combinedHeader(findCase(cases, 'webhook-id-with-comma-is-malformed'), CANONICAL_ID_HEADER) ?? '';

      expect(commatized.includes(',')).toBe(true);

      expect(combinedHeader(findCase(cases, 'missing-webhook-timestamp-is-missing-timestamp'), CANONICAL_TS_HEADER)).toBeUndefined();

      const padded = combinedHeader(findCase(cases, 'zero-padded-timestamp-is-malformed'), CANONICAL_TS_HEADER) ?? '';

      expect(CANONICAL_DECIMAL.test(padded)).toBe(false);

      const svixOnly = findCase(cases, 'branded-svix-headers-alone-missing');

      expect(combinedHeader(svixOnly, CANONICAL_SIG_HEADER)).toBeUndefined();
      expect(combinedHeader(svixOnly, 'svix-id')).toBeDefined();
    }
  });

  it('tolerates the unknown v2 token only because a valid v1 exists', () => {
    const mismatches = CANONICAL_GROUPS.flatMap(({ cases }) => {
      const fixture = findCase(cases, 'v2-with-valid-v1-accepted');
      const anchorHeader = readCanonicalHeaderForAnchor(combinedHeader(fixture, CANONICAL_SIG_HEADER) ?? '');

      if (anchorHeader === null || anchorHeader.v1Values.length !== 1) return [`${fixture.id}: expected exactly one v1 token`];

      const bytes = fixtureBytes(fixture);
      const v2Token = anchorHeader.otherTokens[0] ?? '';

      if (!v2Token.startsWith('v2,') || canonicalVerifies(fixture, combinedHeader(fixture, CANONICAL_ID_HEADER) ?? '',
        combinedHeader(fixture, CANONICAL_TS_HEADER) ?? '', v2Token.slice(3), bytes)) {
        return [`${fixture.id}: the v2 token must stay unverifiable`];
      }

      return [];
    });

    expect(mismatches).toEqual([]);
  });

  it('signs empty, non-JSON and invalid-UTF-8 bodies over the exact bytes', () => {
    for (const { cases } of CANONICAL_GROUPS) {
      expect(fixtureBytes(findCase(cases, 'empty-body-signed')).length).toBe(0);
      expect(() => JSON.parse(UTF8_LOOSE.decode(fixtureBytes(findCase(cases, 'non-json-body-signed'))))).toThrow();
      expect(() => UTF8_STRICT.decode(fixtureBytes(findCase(cases, 'invalid-utf8-body-signed')))).toThrow();
    }
  });
});

describe('gitlab legacy-token pocket', () => {
  it('ignores the plaintext token when the signing signature verifies', () => {
    const fixture = findCase(GITLAB_CASES, 'legacy-token-ignored-with-valid-signature');

    expect(combinedHeader(fixture, GITLAB_TOKEN_HEADER)).toBe(LEGACY_TOKEN);
    expect(fixture.expected.ok).toBe(true);
    expect(fixture.expected.identity?.eventId).toBe(combinedHeader(fixture, CANONICAL_ID_HEADER));
  });

  it('fails closed without fallback when the signature is invalid but the token matches', () => {
    const accepting = findCase(GITLAB_CASES, 'legacy-token-ignored-with-valid-signature');
    const failing = findCase(GITLAB_CASES, 'legacy-token-no-fallback-on-invalid-signature');

    expect(combinedHeader(failing, GITLAB_TOKEN_HEADER)).toBe(combinedHeader(accepting, GITLAB_TOKEN_HEADER));
    expect(combinedHeader(failing, CANONICAL_SIG_HEADER)).not.toBe(combinedHeader(accepting, CANONICAL_SIG_HEADER));
    expect(failing.expected.ok).toBe(false);
    expect(failing.expected.reason).toBe('invalid-signature');
  });

  it('never accepts token-only deliveries', () => {
    const fixture = findCase(GITLAB_CASES, 'legacy-token-only-is-missing-signature');

    expect(combinedHeader(fixture, CANONICAL_SIG_HEADER)).toBeUndefined();
    expect(combinedHeader(fixture, GITLAB_TOKEN_HEADER)).toBe(LEGACY_TOKEN);
    expect(fixture.expected.ok).toBe(false);
    expect(fixture.expected.reason).toBe('missing-signature');
  });
});

describe('workos fixture anchors', () => {
  it('recalculates every positive signature from the recorded inputs and pins identity', () => {
    const problems = WORKOS_CASES.flatMap((fixture) => {
      if (!fixture.expected.ok) return [];

      const anchorHeader = readWorkosHeaderForAnchor(combinedHeader(fixture, WORKOS_SIG_HEADER) ?? '');

      if (anchorHeader === null) return [`${fixture.id}: positive header is outside the well-formed anchor subset`];

      const verified = anchorHeader.v1Values.every((hexValue) => workosVerifies(fixture, anchorHeader.tText, hexValue, fixtureBytes(fixture)));

      if (!verified) return [`${fixture.id}: recorded token does not verify against any configured secret`];

      const identity = fixture.expected.identity;

      if (identity?.eventId !== null || identity?.deliveryId !== null || identity?.authenticatedFields.length !== 1
        || identity?.authenticatedFields[0] !== 'timestamp') {
        return [`${fixture.id}: identity metadata is not the workos map`];
      }

      return Number(anchorHeader.tText) / 1000 === identity?.timestamp ? [] : [`${fixture.id}: identity timestamp is not Number(t)/1000`];
    });

    expect(problems).toEqual([]);
  });

  it('proves every deliberately invalid well-formed signature matches no configured secret', () => {
    const mismatches = WORKOS_CASES.flatMap((fixture) => {
      if (fixture.expected.reason !== 'invalid-signature') return [];

      const anchorHeader = readWorkosHeaderForAnchor(combinedHeader(fixture, WORKOS_SIG_HEADER) ?? '');

      if (anchorHeader === null) return [`${fixture.id}: invalid-signature fixture is not well-formed`];

      const verified = anchorHeader.v1Values.some((hexValue) => workosVerifies(fixture, anchorHeader.tText, hexValue, fixtureBytes(fixture)));

      return verified ? [`${fixture.id}: supposedly invalid signature actually verifies`] : [];
    });

    expect(mismatches).toEqual([]);
  });

  it('proves the MAC stays valid for every workos freshness-only failure', () => {
    const unverified = WORKOS_CASES.flatMap((fixture) => {
      const freshnessOnly = fixture.expected.reason === 'timestamp-expired' || fixture.expected.reason === 'timestamp-future';

      if (!freshnessOnly) return [];

      const anchorHeader = readWorkosHeaderForAnchor(combinedHeader(fixture, WORKOS_SIG_HEADER) ?? '');

      if (anchorHeader === null) return [`${fixture.id}: freshness-only fixture is not well-formed`];

      const verified = anchorHeader.v1Values.some((hexValue) => workosVerifies(fixture, anchorHeader.tText, hexValue, fixtureBytes(fixture)));

      return verified ? [] : [`${fixture.id}: freshness-only failure has no valid MAC`];
    });

    expect(unverified).toEqual([]);
  });

  it('pins the symmetric 180-second boundary with exact and IEEE-safe comparisons', () => {
    interface WorkosBoundaryCheck {
      readonly id: string;
      readonly ok: boolean;
      readonly reason?: 'timestamp-expired' | 'timestamp-future';
      readonly exact?: number;
      readonly beyondPast?: number;
      readonly beyondFuture?: number;
    }

    const checks: readonly WorkosBoundaryCheck[] = [
      { id: 'boundary-plus-180-omitted-ok', ok: true, exact: 180 },
      { id: 'boundary-plus-180-001-expired', ok: false, reason: 'timestamp-expired', beyondPast: 180 },
      { id: 'boundary-minus-180-omitted-ok', ok: true, exact: -180 },
      { id: 'boundary-minus-180-001-future', ok: false, reason: 'timestamp-future', beyondFuture: 180 },
      { id: 'fractional-boundary-plus-180-125-expired', ok: false, reason: 'timestamp-expired', exact: 180.125 },
      { id: 'fractional-boundary-minus-180-25-future', ok: false, reason: 'timestamp-future', exact: -180.25 },
      { id: 'fractional-boundary-inside-plus-179-875-ok', ok: true, exact: 179.875 },
      { id: 'fractional-boundary-inside-minus-179-5-ok', ok: true, exact: -179.5 },
    ];

    for (const check of checks) {
      const fixture = findCase(WORKOS_CASES, check.id);
      const anchorHeader = readWorkosHeaderForAnchor(combinedHeader(fixture, WORKOS_SIG_HEADER) ?? '');
      const identityTs = Number(anchorHeader?.tText ?? '') / 1000;

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

  it('pins the explicit zero-width fractional match and the one-tick drift', () => {
    const exact = findCase(WORKOS_CASES, 'explicit-zero-fractional-exact-ok');
    const exactHeader = readWorkosHeaderForAnchor(combinedHeader(exact, WORKOS_SIG_HEADER) ?? '');
    const exactIdentity = Number(exactHeader?.tText ?? '') / 1000;

    expect(exactHeader?.tText).toBe('1700000000125');
    expect(exact.options.toleranceSeconds).toBe(0);
    expect(exact.options.now).toBe(exactIdentity);
    expect(exactIdentity).toBe(1700000000.125);
    expect(exact.expected.ok).toBe(true);
    expect(exact.expected.identity?.timestamp).toBe(1700000000.125);

    const late = findCase(WORKOS_CASES, 'explicit-zero-drift-expired');

    expect(late.options.toleranceSeconds).toBe(0);
    expect(late.options.now - 1700000000).toBe(0.125);
    expect(late.expected.ok).toBe(false);
    expect(late.expected.reason).toBe('timestamp-expired');
    expect(late.expected.identity).toBeUndefined();
  });

  it('pins the explicit tolerance override at and past its edge', () => {
    const atEdge = findCase(WORKOS_CASES, 'override-tolerance-60-at-edge-ok');
    const pastEdge = findCase(WORKOS_CASES, 'override-tolerance-60-past-expired');

    expect(atEdge.options.toleranceSeconds).toBe(60);
    expect(pastEdge.options.toleranceSeconds).toBe(60);
    expect(atEdge.options.now - 1700000000).toBe(60);
    expect(pastEdge.options.now - 1700000000).toBe(61);
    expect(atEdge.expected.ok).toBe(true);
    expect(pastEdge.expected.ok).toBe(false);
    expect(pastEdge.expected.reason).toBe('timestamp-expired');
  });

  it('checks the MAC before the clock on the workos wrong-before-stale input', () => {
    const fixture = findCase(WORKOS_CASES, 'wrong-signature-beats-stale');

    expect(fixture.options.now - 1700000000).toBe(181);
    expect(fixture.expected.ok).toBe(false);
    expect(fixture.expected.reason).toBe('invalid-signature');
  });

  it('pins the hex-lookalike secret so literal decoding stays documented', () => {
    const literal = findCase(WORKOS_CASES, 'hex-lookalike-secret-literal-verified');
    const configured = literal.options.secrets[0] ?? '';

    expect(HEX_64.test(configured)).toBe(true);
    expect(literal.expected.ok).toBe(true);

    const trap = findCase(WORKOS_CASES, 'hex-decoded-key-trap-rejected');

    expect(trap.expected.ok).toBe(false);
    expect(trap.expected.reason).toBe('invalid-signature');
    expect(trap.options.secrets).toEqual(literal.options.secrets);

    const trapHeader = readWorkosHeaderForAnchor(combinedHeader(trap, WORKOS_SIG_HEADER) ?? '');

    const decodedKeyDigest = createHmac('sha256', Buffer.from(configured, 'hex'))
      .update(`${trapHeader?.tText}.`)
      .update(fixtureBytes(trap))
      .digest('hex');

    expect(trapHeader?.v1Values).toEqual([decodedKeyDigest]);
  });

  it('keeps the recorded signature untouched while tampering the body', () => {
    const baseline = findCase(WORKOS_CASES, 'positive-baseline');
    const tampered = findCase(WORKOS_CASES, 'tampered-body');

    expect(tampered.request.bodyBase64).not.toBe(baseline.request.bodyBase64);
    expect(tampered.request.headers).toEqual(baseline.request.headers);
    expect(tampered.expected.reason).toBe('invalid-signature');
  });

  it('pins the repeated-v1 accept-set and duplicate-t failure shapes', () => {
    for (const id of ['rotation-repeated-v1-distinct-keys', 'rotation-repeated-v1-same-value']) {
      const fixture = findCase(WORKOS_CASES, id);
      const anchorHeader = readWorkosHeaderForAnchor(combinedHeader(fixture, WORKOS_SIG_HEADER) ?? '');

      expect(anchorHeader?.v1Values.length).toBe(2);
      expect(fixture.expected.ok).toBe(true);
    }

    const duplicated = findCase(WORKOS_CASES, 'duplicate-t-even-equal-is-malformed');

    const duplicatedSegments = (combinedHeader(duplicated, WORKOS_SIG_HEADER) ?? '')
      .split(',')
      .map((segment) => segment.trim())
      .filter((segment) => segment.startsWith('t='));

    expect(duplicatedSegments.length).toBe(2);
    expect(duplicatedSegments.every((segment) => segment === duplicatedSegments[0])).toBe(true);
    expect(duplicated.expected.reason).toBe('malformed-signature');
  });

  it('pins the workos grammar outcomes exactly, with no invented alternative codes', () => {
    const outcomes = [
      { id: 'missing-workos-signature-header', reason: 'missing-signature' },
      { id: 'blank-workos-signature-header', reason: 'missing-signature' },
      { id: 't-only-is-missing-signature', reason: 'missing-signature' },
      { id: 'v1-without-t-is-missing-timestamp', reason: 'missing-timestamp' },
      { id: 'h1-style-semicolon-is-malformed', reason: 'malformed-signature' },
      { id: 'h1-style-comma-sibling-unsupported', reason: 'unsupported-scheme' },
      { id: 'stripe-legacy-v0-only-unsupported', reason: 'unsupported-scheme' },
      { id: 'unknown-empty-value-is-malformed', reason: 'malformed-signature' },
      { id: 'unknown-inner-space-is-malformed', reason: 'malformed-signature' },
      { id: 'unknown-comma-value-is-malformed', reason: 'malformed-signature' },
      { id: 'unknown-extra-equals-is-malformed', reason: 'malformed-signature' },
      { id: 'trailing-comma-empty-segment-is-malformed', reason: 'malformed-signature' },
      { id: 'segment-without-equals-is-malformed', reason: 'malformed-signature' },
      { id: 'space-in-key-is-malformed', reason: 'malformed-signature' },
      { id: 'space-after-equals-is-malformed', reason: 'malformed-signature' },
      { id: 'duplicate-t-even-equal-is-malformed', reason: 'malformed-signature' },
      { id: 'leading-zero-t-is-malformed', reason: 'malformed-signature' },
      { id: 'plus-signed-t-is-malformed', reason: 'malformed-signature' },
      { id: 'decimal-point-t-is-malformed', reason: 'malformed-signature' },
      { id: 'negative-t-is-malformed', reason: 'malformed-signature' },
      { id: 'beyond-safe-t-is-malformed', reason: 'malformed-signature' },
      { id: 'inner-space-t-is-malformed', reason: 'malformed-signature' },
      { id: 'empty-value-t-is-malformed', reason: 'malformed-signature' },
      { id: 'non-hex-v1-sibling-poisons', reason: 'malformed-signature' },
      { id: 'short-v1-sibling-poisons', reason: 'malformed-signature' },
      { id: 'combined-duplicate-header-is-malformed', reason: 'malformed-signature' },
    ];

    const acceptedIds = [
      'positive-unknown-v2-field-accepted',
      'positive-unknown-v0-sibling-accepted',
      'positive-outer-whitespace-accepted',
      'positive-field-order-independent',
      'rotation-repeated-v1-distinct-keys',
      'rotation-repeated-v1-same-value',
    ];

    const mismatches = outcomes.flatMap(({ id, reason }) => {
      const fixture = findCase(WORKOS_CASES, id);

      return fixture.expected.ok || fixture.expected.reason !== reason ? [`${id}: expected ${reason}`] : [];
    });

    const unacceptable = acceptedIds.flatMap((id) => {
      const fixture = findCase(WORKOS_CASES, id);

      return fixture.expected.ok && fixture.expected.identity !== undefined ? [] : [`${id}: expected acceptance with identity`];
    });

    expect(mismatches).toEqual([]);
    expect(unacceptable).toEqual([]);
  });

  it('pins the raw shapes behind the workos structure failures', () => {
    interface HeaderFragmentProbe {
      readonly id: string;
      readonly mode: 'prefix' | 'suffix' | 'includes' | 'exact';
      readonly fragment: string;
    }

    const probes: readonly HeaderFragmentProbe[] = [
      { id: 't-only-is-missing-signature', mode: 'exact', fragment: 't=1700000000000' },
      { id: 'h1-style-semicolon-is-malformed', mode: 'includes', fragment: 'ts=1700000500;h1=' },
      { id: 'h1-style-comma-sibling-unsupported', mode: 'includes', fragment: `,h1=` },
      { id: 'stripe-legacy-v0-only-unsupported', mode: 'includes', fragment: 'v0=' },
      { id: 'unknown-empty-value-is-malformed', mode: 'suffix', fragment: ',v2=' },
      { id: 'unknown-inner-space-is-malformed', mode: 'includes', fragment: ',v2=a b' },
      { id: 'unknown-comma-value-is-malformed', mode: 'includes', fragment: ',v2=a,b' },
      { id: 'unknown-extra-equals-is-malformed', mode: 'includes', fragment: ',v2=a=b' },
      { id: 'trailing-comma-empty-segment-is-malformed', mode: 'suffix', fragment: ',' },
      { id: 'segment-without-equals-is-malformed', mode: 'includes', fragment: ',notafield' },
      { id: 'space-in-key-is-malformed', mode: 'prefix', fragment: 't =' },
      { id: 'space-after-equals-is-malformed', mode: 'prefix', fragment: 'v1= ' },
      { id: 'leading-zero-t-is-malformed', mode: 'prefix', fragment: 't=0' },
      { id: 'plus-signed-t-is-malformed', mode: 'prefix', fragment: 't=+' },
      { id: 'decimal-point-t-is-malformed', mode: 'prefix', fragment: 't=1700000000000.5' },
      { id: 'negative-t-is-malformed', mode: 'prefix', fragment: 't=-1' },
      { id: 'beyond-safe-t-is-malformed', mode: 'prefix', fragment: 't=9007199254740993' },
      { id: 'inner-space-t-is-malformed', mode: 'prefix', fragment: 't=17000 00000000' },
      { id: 'empty-value-t-is-malformed', mode: 'prefix', fragment: 't=,' },
      { id: 'v1-without-t-is-missing-timestamp', mode: 'prefix', fragment: 'v1=' },
    ];

    const problems = probes.flatMap((probe) => {
      const actual = combinedHeader(findCase(WORKOS_CASES, probe.id), WORKOS_SIG_HEADER) ?? '';

      const matched = probe.mode === 'exact'
        ? actual === probe.fragment
        : probe.mode === 'prefix'
          ? actual.startsWith(probe.fragment)
          : probe.mode === 'suffix'
            ? actual.endsWith(probe.fragment)
            : actual.includes(probe.fragment);

      return matched ? [] : [`${probe.id}: probe ${probe.mode} '${probe.fragment}' failed against '${actual.slice(0, 40)}'`];
    });

    const malformedSiblings = [
      { id: 'non-hex-v1-sibling-poisons', expectedLength: 64, expectedHex: false },
      { id: 'short-v1-sibling-poisons', expectedLength: 62, expectedHex: true },
    ].flatMap(({ id, expectedLength, expectedHex }) => {
      const tokens = (combinedHeader(findCase(WORKOS_CASES, id), WORKOS_SIG_HEADER) ?? '')
        .split(',')
        .map((segment) => segment.trim())
        .flatMap((segment) => (segment.startsWith('v1=') ? [segment.slice(3)] : []));

      if (tokens.length !== 2) return [`${id}: expected two v1 tokens`];

      return tokens[1]?.length === expectedLength && HEX_CHARS.test(tokens[1] ?? '') === expectedHex ? [] : [`${id}: sibling shape changed`];
    });

    const combinedDuplicates = (combinedHeader(findCase(WORKOS_CASES, 'combined-duplicate-header-is-malformed'), WORKOS_SIG_HEADER) ?? '')
      .split(',')
      .map((segment) => segment.trim())
      .filter((segment) => segment.startsWith('t='))
      .map((segment) => segment.slice(2));

    expect(problems).toEqual([]);
    expect(malformedSiblings).toEqual([]);
    expect(combinedDuplicates.length).toBe(2);
    expect(combinedDuplicates[0]).not.toBe(combinedDuplicates[1]);
  });

  it('holds the canonical zero timestamp on its original text', () => {
    const fixture = findCase(WORKOS_CASES, 'canonical-zero-timestamp-ok');
    const anchorHeader = readWorkosHeaderForAnchor(combinedHeader(fixture, WORKOS_SIG_HEADER) ?? '');

    expect(anchorHeader?.tText).toBe('0');
    expect('toleranceSeconds' in fixture.options).toBe(false);
    expect(fixture.options.now).toBe(0);
    expect(fixture.expected.ok).toBe(true);
    expect(fixture.expected.identity?.timestamp).toBe(0);
  });

  it('signs empty, non-JSON, invalid-UTF-8 and BOM bodies over the exact bytes', () => {
    expect(fixtureBytes(findCase(WORKOS_CASES, 'empty-body-signed')).length).toBe(0);
    expect(() => JSON.parse(UTF8_LOOSE.decode(fixtureBytes(findCase(WORKOS_CASES, 'non-json-body-signed'))))).toThrow();
    expect(() => UTF8_STRICT.decode(fixtureBytes(findCase(WORKOS_CASES, 'invalid-utf8-body-signed')))).toThrow();

    const bomBytes = fixtureBytes(findCase(WORKOS_CASES, 'bom-prefixed-body-signed'));

    expect(Array.from(bomBytes.slice(0, 3))).toEqual([0xef, 0xbb, 0xbf]);
  });
});

/** Canonical identity-header grammar probe shared by the anchor loops. */
function canonicalIdentityWellFormed(idText: string, tsText: string): boolean {
  if (idText.length === 0 || tsText.length === 0) return false;

  if (idText.includes('.') || idText.includes(',') || idText.includes(' ')) return false;

  return CANONICAL_DECIMAL.test(tsText) && Number.isSafeInteger(Number(tsText));
}
