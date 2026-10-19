import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { combinedHeader, fixtureBytes, isUnsignedOrNull } from '../verification/helpers.js';
import type { FixtureCase } from '../verification/helpers.js';

/**
 * Stage A anchor suite for the three phase-3 fixture files. It never imports
 * provider modules or verification entry points: the new provider IDs are not
 * registered yet, and these tests validate the fixture data itself against the
 * frozen phase-3 contract using an independent node:crypto re-derivation.
 */

interface Phase3FixtureFile {
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
function isFixtureFile(value: unknown): value is Phase3FixtureFile {
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

function loadPhase3FixtureFile(fileName: string): readonly FixtureCase[] {
  const raw = readFileSync(new URL(`../fixtures/${fileName}`, import.meta.url), 'utf8');
  const parsed: unknown = JSON.parse(raw);

  if (!isFixtureFile(parsed)) throw new Error(`Phase 3 fixture file ${fileName} is malformed`);

  return parsed.cases;
}

function findCase(cases: readonly FixtureCase[], id: string): FixtureCase {
  const found = cases.find((fixture) => fixture.id === id);

  if (found === undefined) throw new Error(`Fixture case not found: ${id}`);

  return found;
}

function hmacHex(secret: string, bytes: Uint8Array): string {
  return createHmac('sha256', secret).update(bytes).digest('hex');
}

const HEX_64 = /^[0-9a-f]{64}$/i;
const CANONICAL_DECIMAL = /^(?:0|[1-9]\d*)$/;

const UTF8_LOOSE = new TextDecoder('utf-8');
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true });

interface PaddleAnchorHeader {
  readonly tsText: string;
  readonly h1Values: readonly string[];
}

/**
 * Anchor-side reader for the well-formed subset of the contract's Paddle-Signature
 * grammar. It is not the SDK parser and never decides failure outcomes; it is only
 * invoked on fixtures whose expectation is acceptance or a well-formed-but-wrong
 * signature. Unknown non-ts/h1 segments are structurally ignorable per the contract.
 */
function readPaddleHeaderForAnchor(value: string): PaddleAnchorHeader | null {
  const segments = value.split(';').map((segment) => segment.trim());

  if (segments.some((segment) => segment.length === 0)) return null;

  const tsValues: string[] = [];
  const h1Values: string[] = [];

  for (const segment of segments) {
    const split = segment.indexOf('=');

    if (split <= 0) return null;

    const key = segment.slice(0, split);
    const fieldValue = segment.slice(split + 1);

    if (key === 'ts') tsValues.push(fieldValue);

    if (key === 'h1') h1Values.push(fieldValue);
  }

  if (tsValues.length !== 1 || h1Values.length === 0) return null;

  const [tsText] = tsValues;

  if (tsText === undefined) return null;

  if (!CANONICAL_DECIMAL.test(tsText) || !Number.isSafeInteger(Number(tsText))) return null;

  if (!h1Values.every((h1) => HEX_64.test(h1))) return null;

  return { tsText, h1Values };
}

const PADDLE_SDK_COMMIT = '651261beddfc65ba5f861729dca17044cbeffb5f';

const RAZORPAY_CASE_IDS = [
  'signed-body-with-unsigned-event-id',
  'signed-body-without-event-id',
  'whitespace-only-event-id-is-null',
  'padded-event-id-preserved-without-trim',
  'tampered-event-id-ignored',
  'uppercase-hex-accepted',
  'empty-body-signed',
  'invalid-utf8-body-signed',
  'non-json-body-signed',
  'old-secret-retry-accepted',
  'missing-signature-header',
  'whitespace-only-signature-is-missing',
  'empty-signature-header-is-missing',
  'comma-combined-duplicate-signature',
  'prefixed-signature-is-malformed',
  'space-listed-signatures-are-malformed',
  'odd-length-hex-is-malformed',
  'non-hex-digest-is-malformed',
  'short-31-byte-digest-is-malformed',
  'wrong-well-formed-signature',
];

const PADDLE_CASE_IDS = [
  'published-vector-p1',
  'published-vector-p2-duplicate-identical-h1-and-unknown-h2',
  'published-bytes-at-default-plus5',
  'published-bytes-at-default-plus6',
  'published-bytes-at-default-minus5',
  'published-bytes-at-default-minus6',
  'explicit-zero-at-exact-ts',
  'explicit-zero-one-second-late',
  'wrong-signature-beats-stale',
  'h2-only-is-unsupported-scheme',
  'ts-only-is-missing-signature',
  'h1-without-ts-is-missing-timestamp',
  'missing-paddle-signature-header',
  'blank-paddle-signature-header',
  'duplicate-ts-is-malformed',
  'plus-signed-ts-is-malformed',
  'zero-padded-ts-is-malformed',
  'decimal-point-ts-is-malformed',
  'negative-ts-is-malformed',
  'beyond-safe-integer-ts-is-malformed',
  'inner-space-ts-is-malformed',
  'malformed-second-h1-poisons-accept-set',
  'odd-length-single-h1-is-malformed',
  'distinct-key-h1-accept-set',
  'unknown-field-h2-accepted',
  'unknown-field-double-equals-malformed',
  'unknown-field-inner-space-malformed',
  'unknown-field-empty-value-malformed',
  'unknown-field-comma-value-malformed',
  'empty-segment-is-malformed',
  'segment-without-equals-is-malformed',
  'outer-whitespace-segments-accepted',
  'comma-combined-h1-is-malformed',
];

const LEMON_CASE_IDS = [
  'signed-body-with-event-name-header',
  'signed-body-minimal-headers',
  'uppercase-hex-accepted',
  'empty-body-signed',
  'invalid-utf8-body-signed',
  'non-json-body-signed',
  'wrong-well-formed-signature',
  'missing-signature-header',
  'whitespace-only-signature-is-missing',
  'empty-signature-header-is-missing',
  'comma-combined-duplicate-signature',
  'odd-length-hex-is-malformed',
  'non-hex-digest-is-malformed',
  'short-31-byte-digest-is-malformed',
  'prefixed-signature-is-malformed',
];

/** Frozen contract failure vocabulary for the two single-hex-token providers. */
const SINGLE_TOKEN_REASONS = new Set(['missing-signature', 'malformed-signature', 'invalid-signature']);

/** Frozen contract failure vocabulary for Paddle, which also has an authenticated ts. */
const PADDLE_REASONS = new Set([...SINGLE_TOKEN_REASONS, 'unsupported-scheme', 'missing-timestamp', 'timestamp-expired', 'timestamp-future']);

const razorpayCases = loadPhase3FixtureFile('razorpay.json');
const paddleCases = loadPhase3FixtureFile('paddle.json');
const lemonCases = loadPhase3FixtureFile('lemon-squeezy.json');

describe('phase 3 fixture inventory', () => {
  it('loads the three new fixture files with the pinned case counts and ids', () => {
    expect(razorpayCases.length).toBe(20);
    expect(paddleCases.length).toBe(33);
    expect(lemonCases.length).toBe(15);

    expect(razorpayCases.map((fixture) => fixture.id)).toEqual(RAZORPAY_CASE_IDS);
    expect(paddleCases.map((fixture) => fixture.id)).toEqual(PADDLE_CASE_IDS);
    expect(lemonCases.map((fixture) => fixture.id)).toEqual(LEMON_CASE_IDS);
  });

  it('keeps razorpay and lemon squeezy fully synthetic because no published vectors exist', () => {
    expect(razorpayCases.every((fixture) => fixture.provenance.class === 'local')).toBe(true);
    expect(lemonCases.every((fixture) => fixture.provenance.class === 'local')).toBe(true);
  });

  it('pins the paddle published vectors to the official SDK commit and fetch date', () => {
    const referenceCases = paddleCases.flatMap((fixture) => (fixture.provenance.class === 'reference' ? [fixture] : []));

    expect(referenceCases.map((fixture) => fixture.id)).toEqual([
      'published-vector-p1',
      'published-vector-p2-duplicate-identical-h1-and-unknown-h2',
    ]);
    expect(referenceCases.map((fixture) => fixture.provenance.commit)).toEqual([PADDLE_SDK_COMMIT, PADDLE_SDK_COMMIT]);
    expect(referenceCases.map((fixture) => fixture.provenance.fetched)).toEqual(['2026-10-19', '2026-10-19']);
  });

  it('restricts every failure reason to the frozen contract vocabulary', () => {
    for (const fixture of [...razorpayCases, ...paddleCases, ...lemonCases]) {
      if (fixture.expected.ok) {
        expect(fixture.expected.reason).toBeUndefined();

        continue;
      }

      expect(fixture.expected.reason).toBeDefined();

      const allowed = paddleCases.includes(fixture) ? PADDLE_REASONS : SINGLE_TOKEN_REASONS;

      expect(allowed.has(fixture.expected.reason ?? '')).toBe(true);
    }
  });
});

describe('razorpay fixture anchors', () => {
  const SIGNATURE_HEADER = 'x-razorpay-signature';
  const EVENT_ID_HEADER = 'x-razorpay-event-id';

  it('recalculates every positive HMAC from the recorded inputs', () => {
    const unmatched = razorpayCases.flatMap((fixture) => {
      if (!fixture.expected.ok) return [];

      const recorded = combinedHeader(fixture, SIGNATURE_HEADER);

      if (recorded === undefined) return [`${fixture.id}: positive case has no recorded signature`];

      const bytes = fixtureBytes(fixture);
      const matched = fixture.options.secrets.some((secret) => hmacHex(secret, bytes) === recorded.toLowerCase());

      return matched ? [] : [`${fixture.id}: recorded signature does not match any configured secret`];
    });

    expect(unmatched).toEqual([]);
  });

  it('proves every deliberately invalid well-formed signature matches no configured secret', () => {
    const mismatches = razorpayCases.flatMap((fixture) => {
      if (fixture.expected.reason !== 'invalid-signature') return [];

      const recorded = combinedHeader(fixture, SIGNATURE_HEADER) ?? '';

      if (!HEX_64.test(recorded)) return [`${fixture.id}: invalid-signature fixture is not well-formed 64-hex`];

      const bytes = fixtureBytes(fixture);
      const matched = fixture.options.secrets.some((secret) => hmacHex(secret, bytes) === recorded.toLowerCase());

      return matched ? [`${fixture.id}: supposedly invalid signature actually verifies`] : [];
    });

    expect(mismatches).toEqual([]);
  });

  it('pins the contract failure shapes for the single-token grammar', () => {
    const comma = combinedHeader(findCase(razorpayCases, 'comma-combined-duplicate-signature'), SIGNATURE_HEADER) ?? '';
    const prefix = combinedHeader(findCase(razorpayCases, 'prefixed-signature-is-malformed'), SIGNATURE_HEADER) ?? '';
    const list = combinedHeader(findCase(razorpayCases, 'space-listed-signatures-are-malformed'), SIGNATURE_HEADER) ?? '';
    const odd = combinedHeader(findCase(razorpayCases, 'odd-length-hex-is-malformed'), SIGNATURE_HEADER) ?? '';
    const nonHex = combinedHeader(findCase(razorpayCases, 'non-hex-digest-is-malformed'), SIGNATURE_HEADER) ?? '';
    const shortDigest = combinedHeader(findCase(razorpayCases, 'short-31-byte-digest-is-malformed'), SIGNATURE_HEADER) ?? '';

    expect(comma).toContain(',');
    expect(prefix.startsWith('sha256=')).toBe(true);
    expect(list.includes(' ')).toBe(true);
    expect(odd.length % 2).toBe(1);
    expect(nonHex).toMatch(/[g-z]/i);
    expect(shortDigest.length).toBe(62);
  });

  it('pins the missing-signature shapes', () => {
    expect(combinedHeader(findCase(razorpayCases, 'missing-signature-header'), SIGNATURE_HEADER)).toBeUndefined();
    expect((combinedHeader(findCase(razorpayCases, 'whitespace-only-signature-is-missing'), SIGNATURE_HEADER) ?? '').trim()).toBe('');
    expect(combinedHeader(findCase(razorpayCases, 'empty-signature-header-is-missing'), SIGNATURE_HEADER)).toBe('');
  });

  it('pins razorpay identity: null delivery and timestamp, empty authenticated fields', () => {
    for (const fixture of razorpayCases) {
      if (!fixture.expected.ok) continue;

      const identity = fixture.expected.identity;

      expect(identity?.deliveryId).toBeNull();
      expect(identity?.timestamp).toBeNull();
      expect(identity?.authenticatedFields).toEqual([]);
      expect(identity?.eventId === null || isUnsignedOrNull(identity?.eventId ?? null)).toBe(true);
    }
  });

  it('covers the unsigned event-id sentinels across absent, whitespace, padded and tampered values', () => {
    const withEventId = findCase(razorpayCases, 'signed-body-with-unsigned-event-id');
    const withoutEventId = findCase(razorpayCases, 'signed-body-without-event-id');
    const whitespaceEventId = findCase(razorpayCases, 'whitespace-only-event-id-is-null');
    const paddedEventId = findCase(razorpayCases, 'padded-event-id-preserved-without-trim');
    const tamperedEventId = findCase(razorpayCases, 'tampered-event-id-ignored');

    expect(isUnsignedOrNull(withEventId.expected.identity?.eventId ?? null)).toBe(true);
    expect(combinedHeader(withEventId, EVENT_ID_HEADER)).toBe('evt_glm_razorpay_stage_a_001');

    expect(withoutEventId.expected.identity?.eventId).toBeNull();
    expect(combinedHeader(withoutEventId, EVENT_ID_HEADER)).toBeUndefined();

    expect(whitespaceEventId.expected.identity?.eventId).toBeNull();
    expect(combinedHeader(whitespaceEventId, EVENT_ID_HEADER)).toBe('   ');

    expect(isUnsignedOrNull(paddedEventId.expected.identity?.eventId ?? null)).toBe(true);
    expect(combinedHeader(paddedEventId, EVENT_ID_HEADER)).not.toBe(combinedHeader(paddedEventId, EVENT_ID_HEADER)?.trim());

    expect(isUnsignedOrNull(tamperedEventId.expected.identity?.eventId ?? null)).toBe(true);
    expect(combinedHeader(tamperedEventId, EVENT_ID_HEADER)).toBe('evt_forged_by_attacker');
    expect(tamperedEventId.request.bodyBase64).toBe(withEventId.request.bodyBase64);
    expect(combinedHeader(tamperedEventId, SIGNATURE_HEADER)).toBe(combinedHeader(withEventId, SIGNATURE_HEADER));
    expect(tamperedEventId.expected.ok).toBe(true);
  });
});

describe('lemon squeezy fixture anchors', () => {
  const SIGNATURE_HEADER = 'x-signature';

  it('recalculates every positive HMAC from the recorded inputs', () => {
    const unmatched = lemonCases.flatMap((fixture) => {
      if (!fixture.expected.ok) return [];

      const recorded = combinedHeader(fixture, SIGNATURE_HEADER);

      if (recorded === undefined) return [`${fixture.id}: positive case has no recorded signature`];

      const bytes = fixtureBytes(fixture);
      const matched = fixture.options.secrets.some((secret) => hmacHex(secret, bytes) === recorded.toLowerCase());

      return matched ? [] : [`${fixture.id}: recorded signature does not match any configured secret`];
    });

    expect(unmatched).toEqual([]);
  });

  it('proves every deliberately invalid well-formed signature matches no configured secret', () => {
    const mismatches = lemonCases.flatMap((fixture) => {
      if (fixture.expected.reason !== 'invalid-signature') return [];

      const recorded = combinedHeader(fixture, SIGNATURE_HEADER) ?? '';

      if (!HEX_64.test(recorded)) return [`${fixture.id}: invalid-signature fixture is not well-formed 64-hex`];

      const bytes = fixtureBytes(fixture);
      const matched = fixture.options.secrets.some((secret) => hmacHex(secret, bytes) === recorded.toLowerCase());

      return matched ? [`${fixture.id}: supposedly invalid signature actually verifies`] : [];
    });

    expect(mismatches).toEqual([]);
  });

  it('keeps every positive identity field null with empty authenticated fields', () => {
    for (const fixture of lemonCases) {
      if (!fixture.expected.ok) continue;

      const identity = fixture.expected.identity;

      expect(identity?.deliveryId).toBeNull();
      expect(identity?.eventId).toBeNull();
      expect(identity?.timestamp).toBeNull();
      expect(identity?.authenticatedFields).toEqual([]);
    }
  });

  it('pins the missing-signature shapes', () => {
    expect(combinedHeader(findCase(lemonCases, 'missing-signature-header'), SIGNATURE_HEADER)).toBeUndefined();
    expect((combinedHeader(findCase(lemonCases, 'whitespace-only-signature-is-missing'), SIGNATURE_HEADER) ?? '').trim()).toBe('');
    expect(combinedHeader(findCase(lemonCases, 'empty-signature-header-is-missing'), SIGNATURE_HEADER)).toBe('');
  });
});

describe('exact raw byte anchors', () => {
  it('signs empty bodies over zero bytes', () => {
    expect(fixtureBytes(findCase(razorpayCases, 'empty-body-signed')).length).toBe(0);
    expect(fixtureBytes(findCase(lemonCases, 'empty-body-signed')).length).toBe(0);
  });

  it('signs non-JSON bodies without requiring JSON', () => {
    expect(() => JSON.parse(UTF8_LOOSE.decode(fixtureBytes(findCase(razorpayCases, 'non-json-body-signed'))))).toThrow();
    expect(() => JSON.parse(UTF8_LOOSE.decode(fixtureBytes(findCase(lemonCases, 'non-json-body-signed'))))).toThrow();
  });

  it('signs invalid UTF-8 bodies over the exact bytes', () => {
    expect(() => UTF8_STRICT.decode(fixtureBytes(findCase(razorpayCases, 'invalid-utf8-body-signed')))).toThrow();
    expect(() => UTF8_STRICT.decode(fixtureBytes(findCase(lemonCases, 'invalid-utf8-body-signed')))).toThrow();
  });
});

describe('paddle fixture anchors', () => {
  const SIGNATURE_HEADER = 'paddle-signature';
  const PUBLISHED_TS = 1698796800;
  const SYNTHETIC_TS = 1700000500;

  it('pins the published vector bytes and header text exactly', () => {
    const published1 = findCase(paddleCases, 'published-vector-p1');
    const published2 = findCase(paddleCases, 'published-vector-p2-duplicate-identical-h1-and-unknown-h2');

    expect(UTF8_LOOSE.decode(fixtureBytes(published1))).toBe('{"data": ["1", "2"]}');
    expect(UTF8_LOOSE.decode(fixtureBytes(published2))).toBe('{"data": "value"}');
    expect(combinedHeader(published1, SIGNATURE_HEADER)).toBe(
      'ts=1698796800;h1=a300428748dce5c70e4da19bffd60769591ea969c99dea3105d0ec9612cf43f9',
    );
    expect(combinedHeader(published2, SIGNATURE_HEADER)).toBe(
      'ts=1698796800;h1=28981e941fae76e53db32f3d2a83cb69db41476595e84e1970a1b5d98f62b261;h1=28981e941fae76e53db32f3d2a83cb69db41476595e84e1970a1b5d98f62b261;h2=RANDOM_HASH',
    );
  });

  it('recalculates positive and freshness-only h1 values over exact ts colon raw body bytes', () => {
    const problems = paddleCases.flatMap((fixture) => {
      const freshnessOnly = fixture.expected.reason === 'timestamp-expired'
        || fixture.expected.reason === 'timestamp-future';

      if (!fixture.expected.ok && !freshnessOnly) return [];

      const anchorHeader = readPaddleHeaderForAnchor(combinedHeader(fixture, SIGNATURE_HEADER) ?? '');

      if (anchorHeader === null) return [`${fixture.id}: positive header is outside the well-formed anchor subset`];

      if (fixture.expected.ok && Number(anchorHeader.tsText) !== fixture.expected.identity?.timestamp) {
        return [`${fixture.id}: identity timestamp does not equal the authenticated ts`];
      }

      const bytes = fixtureBytes(fixture);
      const prefix = `${anchorHeader.tsText}:`;

      const unverified = anchorHeader.h1Values.flatMap((h1) => {
        const digest = (secret: string): string => createHmac('sha256', secret).update(prefix).update(bytes).digest('hex');
        const matched = fixture.options.secrets.some((secret) => digest(secret) === h1.toLowerCase());

        return matched ? [] : [`${fixture.id}: h1 ${h1.slice(0, 12)} does not verify against any configured secret`];
      });

      return unverified;
    });

    expect(problems).toEqual([]);
  });

  it('proves the wrong-signature-before-stale input really exceeds five seconds of drift', () => {
    const wrongBeforeStale = findCase(paddleCases, 'wrong-signature-beats-stale');
    const anchorHeader = readPaddleHeaderForAnchor(combinedHeader(wrongBeforeStale, SIGNATURE_HEADER) ?? '');

    expect(anchorHeader).not.toBeNull();
    expect(anchorHeader?.h1Values.length).toBe(1);

    const drift = wrongBeforeStale.options.now - Number(anchorHeader?.tsText ?? 0);

    expect(drift).toBeGreaterThan(5);
    expect(wrongBeforeStale.expected.reason).toBe('invalid-signature');

    const bytes = fixtureBytes(wrongBeforeStale);

    const digest = (secret: string): string =>
      createHmac('sha256', secret).update(`${anchorHeader?.tsText ?? ''}:`).update(bytes).digest('hex');

    const matched = wrongBeforeStale.options.secrets.some((secret) => digest(secret) === anchorHeader?.h1Values[0]?.toLowerCase());

    expect(matched).toBe(false);
  });

  it('pins the default-tolerance boundary expectations with toleranceSeconds omitted', () => {
    const boundaries = [
      { id: 'published-bytes-at-default-plus5', drift: 5, ok: true },
      { id: 'published-bytes-at-default-plus6', drift: 6, ok: false },
      { id: 'published-bytes-at-default-minus5', drift: -5, ok: true },
      { id: 'published-bytes-at-default-minus6', drift: -6, ok: false },
    ];

    for (const { id, drift, ok } of boundaries) {
      const fixture = findCase(paddleCases, id);

      expect('toleranceSeconds' in fixture.options).toBe(false);
      expect(fixture.options.now - PUBLISHED_TS).toBe(drift);
      expect(fixture.expected.ok).toBe(ok);

      if (ok) {
        expect(fixture.expected.identity?.timestamp).toBe(PUBLISHED_TS);

        continue;
      }

      expect(fixture.expected.reason).toBe(drift > 0 ? 'timestamp-expired' : 'timestamp-future');
      expect(fixture.expected.identity).toBeUndefined();
    }
  });

  it('pins the explicit zero-width tolerance expectations separately', () => {
    const exact = findCase(paddleCases, 'explicit-zero-at-exact-ts');
    const late = findCase(paddleCases, 'explicit-zero-one-second-late');

    expect(exact.options.toleranceSeconds).toBe(0);
    expect(late.options.toleranceSeconds).toBe(0);
    expect(exact.options.now - SYNTHETIC_TS).toBe(0);
    expect(late.options.now - SYNTHETIC_TS).toBe(1);
    expect(exact.expected.ok).toBe(true);
    expect(exact.expected.identity?.timestamp).toBe(SYNTHETIC_TS);
    expect(late.expected.ok).toBe(false);
    expect(late.expected.reason).toBe('timestamp-expired');
  });

  it('pins the contract grammar outcomes exactly, with no invented alternative codes', () => {
    const outcomes = [
      { id: 'h2-only-is-unsupported-scheme', reason: 'unsupported-scheme' },
      { id: 'ts-only-is-missing-signature', reason: 'missing-signature' },
      { id: 'h1-without-ts-is-missing-timestamp', reason: 'missing-timestamp' },
      { id: 'missing-paddle-signature-header', reason: 'missing-signature' },
      { id: 'blank-paddle-signature-header', reason: 'missing-signature' },
      { id: 'duplicate-ts-is-malformed', reason: 'malformed-signature' },
      { id: 'plus-signed-ts-is-malformed', reason: 'malformed-signature' },
      { id: 'zero-padded-ts-is-malformed', reason: 'malformed-signature' },
      { id: 'decimal-point-ts-is-malformed', reason: 'malformed-signature' },
      { id: 'negative-ts-is-malformed', reason: 'malformed-signature' },
      { id: 'beyond-safe-integer-ts-is-malformed', reason: 'malformed-signature' },
      { id: 'inner-space-ts-is-malformed', reason: 'malformed-signature' },
      { id: 'malformed-second-h1-poisons-accept-set', reason: 'malformed-signature' },
      { id: 'odd-length-single-h1-is-malformed', reason: 'malformed-signature' },
      { id: 'unknown-field-double-equals-malformed', reason: 'malformed-signature' },
      { id: 'unknown-field-inner-space-malformed', reason: 'malformed-signature' },
      { id: 'unknown-field-empty-value-malformed', reason: 'malformed-signature' },
      { id: 'unknown-field-comma-value-malformed', reason: 'malformed-signature' },
      { id: 'empty-segment-is-malformed', reason: 'malformed-signature' },
      { id: 'segment-without-equals-is-malformed', reason: 'malformed-signature' },
      { id: 'comma-combined-h1-is-malformed', reason: 'malformed-signature' },
    ];

    const mismatches = outcomes.flatMap(({ id, reason }) => {
      const fixture = findCase(paddleCases, id);

      return fixture.expected.ok || fixture.expected.reason !== reason ? [`${id}: expected ${reason}`] : [];
    });

    const acceptedIds = ['unknown-field-h2-accepted', 'outer-whitespace-segments-accepted', 'distinct-key-h1-accept-set'];

    const unacceptable = acceptedIds.flatMap((id) => {
      const fixture = findCase(paddleCases, id);

      return fixture.expected.ok && fixture.expected.identity !== undefined ? [] : [`${id}: expected acceptance with identity`];
    });

    expect(mismatches).toEqual([]);
    expect(unacceptable).toEqual([]);
  });

  it('documents the poisoning and length markers behind the paddle grammar failures', () => {
    const poisonedHeader = combinedHeader(findCase(paddleCases, 'malformed-second-h1-poisons-accept-set'), SIGNATURE_HEADER) ?? '';
    const poisonedSegments = poisonedHeader.split(';').map((segment) => segment.trim());
    const poisonedValues = poisonedSegments.flatMap((segment) => (segment.startsWith('h1=') ? [segment.slice(3)] : []));

    expect(poisonedValues.length).toBe(2);
    expect(poisonedValues[1]?.length).toBe(64);
    expect(HEX_64.test(poisonedValues[1] ?? '')).toBe(false);

    const oddHeader = combinedHeader(findCase(paddleCases, 'odd-length-single-h1-is-malformed'), SIGNATURE_HEADER) ?? '';
    const oddValues = oddHeader.split(';').map((segment) => segment.trim()).flatMap((segment) => (segment.startsWith('h1=') ? [segment.slice(3)] : []));

    expect(oddValues.length).toBe(1);
    expect(oddValues[0]?.length).toBe(63);
  });
});
