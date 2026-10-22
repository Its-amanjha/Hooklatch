import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { combinedHeader, fixtureBytes, isFixtureFile } from '../verification/helpers.js';

/**
 * Phase 8 Stage A anchor suite for the Linear fixture corpus. It never imports
 * provider modules, the Provider union, or verification entry points: Linear
 * stays unregistered at this base (18 providers) and these tests validate
 * fixture data only. Only the three permitted pure helpers are shared.
 *
 * Every positive and rotation MAC is re-derived with node:crypto from the
 * recorded header text and an independent hand-rolled Base64 decoder over the
 * exact body bytes. Deliberately invalid well-formed signatures are proven to
 * match no configured secret; grammar failures keep their exact contract
 * reasons; the all-null identity map is pinned for every positive. A fresh
 * outcome model implements the frozen receiver contract (record view versus
 * WHATWG Headers trimming) and must agree with the pinned outcomes in both
 * views. Owned corpus guards are stricter than the shared file validator:
 * Linear accepts no providerOptions/tolerance/maxBody options, positive rows
 * pin the all-null identity, and every negative carries exactly one reason
 * from the frozen three-reason vocabulary. Guard negatives deliberately
 * exercise distinct inner clauses rather than the outer envelope; in-memory
 * mutation controls distinguish inventory, model, override and guard-rejected
 * detection classes. Data/crypto consistency here never proves public
 * provider support.
 */

interface LinearProvenanceMirror {
  class: 'local' | 'reference';
  source: string;
  commit?: string;
  fetched?: string;
}

interface LinearIdentityMirror {
  deliveryId: string | number | null;
  eventId: string | number | null;
  timestamp: number | null;
  authenticatedFields: string[];
}

interface LinearExpectedMirror {
  ok: boolean;
  reason?: string;
  identity?: LinearIdentityMirror;
}

interface LinearOptionsMirror {
  secrets: string[];
  now: number;
}

/** Index-signature mirror of request headers; mutable typing exists only for the in-memory mutation controls. */
interface LinearHeadersMirror {
  [name: string]: string | string[];
}

interface LinearRequestMirror {
  bodyBase64: string;
  headers: LinearHeadersMirror;
}

interface LinearCaseMirror {
  id: string;
  provenance: LinearProvenanceMirror;
  request: LinearRequestMirror;
  options: LinearOptionsMirror;
  expected: LinearExpectedMirror;
  webHeadersExpected?: LinearExpectedMirror;
  notes?: string;
}

type LinearHeaderView = 'record' | 'web';

type LinearReason = 'missing-signature' | 'malformed-signature' | 'invalid-signature';

/** The only identity linear may pin: everything unauthenticated. */
type LinearPositiveIdentity = {
  readonly deliveryId: null;
  readonly eventId: null;
  readonly timestamp: null;
  readonly authenticatedFields: readonly string[];
};

type LinearOutcome =
  | { readonly ok: true; readonly identity: LinearPositiveIdentity }
  | { readonly ok: false; readonly reason: LinearReason };

const LINEAR_URL = new URL('../fixtures/linear.json', import.meta.url);

const LINEAR_SIG_HEADER = 'linear-signature';

const LINEAR_REASONS: ReadonlySet<string> = new Set(['missing-signature', 'malformed-signature', 'invalid-signature']);
const FORBIDDEN_REASON_FAMILIES = ['timestamp-expired', 'timestamp-future', 'timestamp-missing', 'identity-missing'];

const HEX_64 = /^[0-9a-f]{64}$/i;
const LOWER_HEX_32 = /^[0-9a-f]{32}$/;
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;
const LOWER_HEX_63 = /^[0-9a-f]{63}$/;
const LOWER_HEX_65 = /^[0-9a-f]{65}$/;
const BASE64_STD_TOKEN = /^[A-Za-z0-9+/]+={0,2}$/;
const HEADER_TOKEN = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/;
const ASCII_PRINTABLE = /^[\x20-\x7e]*$/;
const NONHEX_SENTINEL_CHAR = 'g';
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const MAIN_SECRET = 'hooklatch_stage_8_linear_secret';
const OLD_SECRET = 'hooklatch_stage_8_linear_old_secret';
const NEW_SECRET = 'hooklatch_stage_8_linear_new_secret';
const WRONG_KEY_SECRET = 'hooklatch_stage_8_linear_wrong_key';
const WHITESPACE_SECRET = '   ';
const NONASCII_SECRET = 'hooklatch_stage_8_linéar_sécret_λ';
const UNTRIMMED_SECRET = '  hooklatch_stage_8_surrounded_secret  ';
const NEVER_CONFIGURED_SECRET = 'hooklatch_stage_8_newkey_never_configured';

const DELIVERY_ID = 'e2b9d5a1-7c34-4f2e-a1b0-8f9c2d3e4a60';

const PROVENANCE_MARKERS = [
  'notes/phase-8/contract.md',
  'linear.app/developers/webhooks',
  'github.com/linear/linear webhooks client.ts',
  '4d9cdbf0beb1d1da1824deb5ff3cd458c71380c9',
  'receiver policy',
  'no vendor-published vector was used',
  'node:crypto recomputation',
  'not public HTTP support',
];

const OVERRIDE_IDS = [
  'signature-outer-whitespace-is-malformed-record-view',
  'signature-trailing-whitespace-is-headers-trim-accepts',
] as const;

const LINEAR_CASE_IDS = [
  'positive-baseline',
  'positive-uppercase-hex-accepted',
  'positive-request-header-casing-variant',
  'positive-whitespace-only-secret-literal',
  'positive-nonascii-secret-literal',
  'positive-untrimmed-secret-literal',
  'positive-empty-body-signed',
  'positive-non-json-body-signed',
  'positive-binary-body-signed',
  'positive-invalid-utf8-body-signed',
  'positive-nul-byte-body-signed',
  'positive-old-body-timestamp-with-valid-mac',
  'positive-future-body-timestamp-with-valid-mac',
  'rotation-both-secrets-accept-old',
  'positive-unsigned-context-headers-ignored',
  'positive-alien-signature-header-ignored',
  'missing-signature-header',
  'alien-signature-header-cannot-rescue',
  'blank-signature-is-missing',
  'tampered-body-invalid-signature',
  'wrong-key-valid-grammar',
  'rotation-old-secret-after-removal',
  'signature-inner-whitespace-is-malformed',
  'signature-led-prefix-is-malformed',
  'standard-webhooks-token-is-malformed',
  'hex-63-characters-are-malformed',
  'hex-65-characters-are-malformed',
  'non-hex-character-is-malformed',
  'comma-combined-duplicates-are-malformed',
  'signature-outer-whitespace-is-malformed-record-view',
  'signature-trailing-whitespace-is-headers-trim-accepts',
] as const;

// ------------------------------------------------------------------ guards
// Every runtime typeof stays inside a type-guard function per house rules.

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isLinearReason(value: unknown): value is LinearReason {
  return isString(value) && LINEAR_REASONS.has(value);
}

function isHeaderName(value: unknown): value is string {
  return isString(value) && value.length > 0 && HEADER_TOKEN.test(value);
}

function isHeaderValue(value: unknown): value is string | string[] {
  if (isString(value)) return value.length > 0 && ASCII_PRINTABLE.test(value);

  if (Array.isArray(value)) {
    return value.length > 0 && value.every((item: unknown): item is string => isString(item) && item.length > 0 && ASCII_PRINTABLE.test(item));
  }

  return false;
}

function isProvenance(value: unknown): value is LinearProvenanceMirror {
  if (typeof value !== 'object' || value === null) return false;

  if (!Object.keys(value).every((key) => key === 'class' || key === 'source' || key === 'commit' || key === 'fetched')) return false;

  if (!('class' in value) || (value.class !== 'local' && value.class !== 'reference')) return false;

  if (!('source' in value) || !isString(value.source) || value.source.length === 0) return false;

  if ('commit' in value && !isString(value.commit)) return false;

  return !('fetched' in value) || isString(value.fetched);
}

function isIdentity(value: unknown): value is LinearIdentityMirror {
  if (typeof value !== 'object' || value === null) return false;

  if (!('deliveryId' in value) || (value.deliveryId !== null && !isString(value.deliveryId) && typeof value.deliveryId !== 'number')) return false;

  if (!('eventId' in value) || (value.eventId !== null && !isString(value.eventId) && typeof value.eventId !== 'number')) return false;

  if (!('timestamp' in value) || (value.timestamp !== null && typeof value.timestamp !== 'number')) return false;

  return 'authenticatedFields' in value && Array.isArray(value.authenticatedFields) && value.authenticatedFields.every((item: unknown): item is string => isString(item));
}

/** All-null body-only identity map: deliveryId/eventId/timestamp null and no authenticated fields. */
function isStrictLinearIdentity(value: unknown): value is LinearIdentityMirror {
  if (!isIdentity(value)) return false;

  return value.deliveryId === null && value.eventId === null && value.timestamp === null && value.authenticatedFields.length === 0;
}

/**
 * Contract-shaped outcome guard: positive rows pin the all-null identity and
 * never carry a reason; negative rows carry exactly one reason from the frozen
 * vocabulary and never an identity map.
 */
function isOutcome(value: unknown): value is LinearExpectedMirror {
  if (typeof value !== 'object' || value === null) return false;

  if (!Object.keys(value).every((key) => key === 'ok' || key === 'reason' || key === 'identity')) return false;

  if (!('ok' in value) || typeof value.ok !== 'boolean') return false;

  if (value.ok) {
    if ('reason' in value) return false;

    return 'identity' in value && isStrictLinearIdentity(value.identity);
  }

  if (!('reason' in value) || !isLinearReason(value.reason)) return false;

  return !('identity' in value);
}

/** Linear accepts NO configuration beyond rotation; any options key outside {secrets, now} is forbidden. */
function isOptions(value: unknown): value is LinearOptionsMirror {
  if (typeof value !== 'object' || value === null) return false;

  if (!Object.keys(value).every((key) => key === 'secrets' || key === 'now')) return false;

  if ('providerOptions' in value || 'toleranceSeconds' in value || 'maxBodyBytes' in value) return false;

  if (!('secrets' in value) || !Array.isArray(value.secrets) || value.secrets.length === 0 || !value.secrets.every((item: unknown): item is string => isString(item) && item.length > 0)) return false;

  return 'now' in value && typeof value.now === 'number';
}

function isRequest(value: unknown): value is LinearRequestMirror {
  if (typeof value !== 'object' || value === null) return false;

  if (!Object.keys(value).every((key) => key === 'bodyBase64' || key === 'headers')) return false;

  if (!('bodyBase64' in value) || !isString(value.bodyBase64)) return false;

  if (!('headers' in value) || typeof value.headers !== 'object' || value.headers === null || Array.isArray(value.headers)) return false;

  return Object.entries(value.headers).every(([name, headerValue]) => isHeaderName(name) && isHeaderValue(headerValue));
}

function isCase(value: unknown): value is LinearCaseMirror {
  if (typeof value !== 'object' || value === null) return false;

  if (!Object.keys(value).every((key) => key === 'id' || key === 'provenance' || key === 'request' || key === 'options' || key === 'expected' || key === 'webHeadersExpected' || key === 'notes')) return false;

  if (!('id' in value) || !isString(value.id) || value.id.length === 0) return false;

  if (!('provenance' in value) || !isProvenance(value.provenance)) return false;

  if (!('request' in value) || !isRequest(value.request)) return false;

  if (!('options' in value) || !isOptions(value.options)) return false;

  if (!('expected' in value) || !isOutcome(value.expected)) return false;

  if ('webHeadersExpected' in value && value.webHeadersExpected !== undefined && !isOutcome(value.webHeadersExpected)) return false;

  return !('notes' in value) || isString(value.notes);
}

/** Re-validates a mutated domain-typed sequence without discarding it into an unknown-parameter guard. */
function isGuardedCaseSequence(cases: readonly LinearCaseMirror[]): boolean {
  if (cases.length === 0) return false;

  const ids: string[] = [];

  for (const case_ of cases) {
    if (!isCase(case_)) return false;

    ids.push(case_.id);
  }

  return new Set(ids).size === ids.length;
}

// ------------------------------------------------------------------ loading
function linearRawText(): string {
  return readFileSync(LINEAR_URL, 'utf8');
}

/** Own file-level guard over every element and id uniqueness; typeof stays inside the guard per house rules. */
function isLinearFixtureFile(value: unknown): value is { readonly cases: LinearCaseMirror[] } {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;

  if (!('cases' in value) || !Array.isArray(value.cases) || value.cases.length === 0) return false;

  const ids: string[] = [];

  for (const entry of value.cases) {
    if (!isCase(entry)) return false;

    ids.push(entry.id);
  }

  return new Set(ids).size === ids.length;
}

function loadLinearCases(): LinearCaseMirror[] {
  const file: unknown = JSON.parse(linearRawText());

  if (!isLinearFixtureFile(file)) throw new Error('Phase 8 linear fixture file fails the owned corpus guard');

  return [...file.cases];
}

const LINEAR_CASES = loadLinearCases();

function findLinearCase(id: string): LinearCaseMirror {
  const found = LINEAR_CASES.find((case_) => case_.id === id);

  if (found === undefined) throw new Error(`Fixture case not found: ${id}`);

  return found;
}

function cloneCase(id: string): LinearCaseMirror {
  return structuredClone(findLinearCase(id));
}

// ------------------------------------------------------------------ byte tools
const UTF8_ENCODER = new TextEncoder();
const UTF8_LOOSE = new TextDecoder('utf-8');
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true });

/**
 * Independent canonical Base64 decoder: no atob, verifies block structure,
 * charset, padding position and canonical pad bits for every block.
 */
function independentBase64Bytes(value: string): Uint8Array {
  const bytes: number[] = [];

  for (let index = 0; index < value.length; index += 4) {
    const block = value.slice(index, index + 4);
    const isFinalBlock = index + 4 === value.length;
    const padCount = block.endsWith('==') ? 2 : block.endsWith('=') ? 1 : 0;

    if (padCount > 0 && !isFinalBlock) throw new Error(`non-final base64 block contains padding: ${value}`);

    const charCount = 4 - padCount;
    let bits = 0;
    let bitCount = 0;

    for (let offset = 0; offset < charCount; offset += 1) {
      const sextet = BASE64_ALPHABET.indexOf(block.charAt(offset));

      if (sextet < 0) throw new Error(`non-base64 character in body: ${value}`);

      bits = (bits << 6) | sextet;
      bitCount += 6;
    }

    if (padCount > 0 && (bits & ((1 << padCount * 2) - 1)) !== 0) throw new Error(`noncanonical base64 pad bits in body: ${value}`);

    while (bitCount >= 8) {
      bitCount -= 8;
      bytes.push((bits >> bitCount) & 0xff);
    }
  }

  return new Uint8Array(bytes);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;

  for (let index = 0; index < left.length; index += 1) if (left[index] !== right[index]) return false;

  return true;
}

/** 64-hex text to 32 digest bytes; callers prove the hex grammar before calling. */
function hexDigestBytes(text: string): Uint8Array {
  const bytes = new Uint8Array(32);

  for (let index = 0; index < 32; index += 1) bytes[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);

  return bytes;
}

function encodedBodyBytes(case_: LinearCaseMirror): Uint8Array {
  return fixtureBytes(case_);
}

function digestHexFor(secret: string, bodyBytes: Uint8Array): string {
  return createHmac('sha256', UTF8_ENCODER.encode(secret)).update(bodyBytes).digest('hex');
}

// ------------------------------------------------------------------ outcome model
function headerMapOf(case_: LinearCaseMirror, view: LinearHeaderView): Map<string, string> {
  const map = new Map<string, string>();

  for (const [name, value] of Object.entries(case_.request.headers)) {
    const text = Array.isArray(value) ? value.join(', ') : value;

    map.set(name.toLowerCase(), view === 'web' ? text.trim() : text);
  }

  return map;
}

const POSITIVE_IDENTITY: LinearPositiveIdentity = {
  deliveryId: null,
  eventId: null,
  timestamp: null,
  authenticatedFields: [],
};

/**
 * Fresh model of the frozen receiver contract: one case-insensitive configured
 * header, trim-blank means missing, the raw record text must already be
 * exactly 64 hex characters (outer whitespace stays malformed outside the
 * WHATWG trim), then HMAC-SHA256 over exact body bytes against every
 * configured literal UTF-8 secret. Identity is never extracted.
 */
function linearOutcome(case_: LinearCaseMirror, view: LinearHeaderView): LinearOutcome {
  const headers = headerMapOf(case_, view);
  const raw = headers.get(LINEAR_SIG_HEADER);

  if (raw === undefined || raw.trim() === '') return { ok: false, reason: 'missing-signature' };

  if (!HEX_64.test(raw)) return { ok: false, reason: 'malformed-signature' };

  const bodyBytes = encodedBodyBytes(case_);

  for (const secret of case_.options.secrets) {
    const digest = createHmac('sha256', UTF8_ENCODER.encode(secret)).update(bodyBytes).digest();

    if (sameBytes(hexDigestBytes(raw), digest)) return { ok: true, identity: POSITIVE_IDENTITY };
  }

  return { ok: false, reason: 'invalid-signature' };
}

function outcomeSignature(outcome: LinearOutcome): string {
  return outcome.ok ? 'ok:true:all-null-identity' : `ok:false:${outcome.reason}`;
}

/** Maps a guarded mirror outcome onto the model outcome shape; guarded rows cannot hit the throws. */
function outcomeFromMirror(expected: LinearExpectedMirror): LinearOutcome {
  if (expected.ok) {
    if (!isStrictLinearIdentity(expected.identity)) throw new Error(`guarded positive row lacks the all-null identity map: ${expected.identity === undefined ? 'no identity key' : 'improper shape'}`);

    return { ok: true, identity: POSITIVE_IDENTITY };
  }

  if (!isLinearReason(expected.reason)) throw new Error('guarded negative row lacks a vocabulary reason');

  return { ok: false, reason: expected.reason };
}

// ------------------------------------------------------------------ defect checker
function linearCaseDefects(case_: LinearCaseMirror): string[] {
  const defects: string[] = [];

  if (case_.provenance.class !== 'local') defects.push(`${case_.id}: provenance class must be local in this corpus`);

  for (const marker of PROVENANCE_MARKERS) {
    if (!case_.provenance.source.includes(marker)) defects.push(`${case_.id}: provenance misses '${marker}'`);
  }

  const recordOutcome = linearOutcome(case_, 'record');
  const webOutcome = linearOutcome(case_, 'web');
  const pinnedRecord = outcomeFromMirror(case_.expected);
  const pinnedWeb = outcomeFromMirror(case_.webHeadersExpected ?? case_.expected);

  if (outcomeSignature(recordOutcome) !== outcomeSignature(pinnedRecord)) {
    defects.push(`${case_.id}: record view mismatch: model ${outcomeSignature(recordOutcome)} vs pinned ${outcomeSignature(pinnedRecord)}`);
  }

  if (outcomeSignature(webOutcome) !== outcomeSignature(pinnedWeb)) {
    defects.push(`${case_.id}: web view mismatch: model ${outcomeSignature(webOutcome)} vs pinned ${outcomeSignature(pinnedWeb)}`);
  }

  const declared = case_.webHeadersExpected !== undefined;
  const material = outcomeSignature(recordOutcome) !== outcomeSignature(webOutcome);

  if (declared !== material) {
    defects.push(
      declared
        ? `${case_.id}: webHeadersExpected declared without a material view difference`
        : `${case_.id}: material view difference without a declared override`,
    );
  }

  return defects;
}

function linearInventoryDefects(cases: readonly LinearCaseMirror[]): string[] {
  const defects: string[] = [];
  const actual = cases.map((case_) => case_.id);

  if (actual.join('|') !== LINEAR_CASE_IDS.join('|')) defects.push(`inventory mismatch: actual ${actual.join('|')} vs pinned ${LINEAR_CASE_IDS.join('|')}`);

  const seen = new Set<string>();

  for (const id of actual) {
    if (seen.has(id)) defects.push(`duplicate id: ${id}`);
    seen.add(id);
  }

  return defects;
}

function linearCorpusDefects(cases: readonly LinearCaseMirror[]): string[] {
  return [...linearInventoryDefects(cases), ...cases.flatMap((case_) => linearCaseDefects(case_))];
}

/**
 * Fresh parse per mutation: JSON text is reguarded before and after the
 * mutation, so a mutation either fails an owned guard hard ("guard-rejected")
 * or reaches the inventory/model/override defect layer. Exceptions remain
 * visible; runners never suppress them.
 */
function linearDefectsAfterMutation(mutator: (cases: LinearCaseMirror[]) => void): string[] {
  const file: unknown = JSON.parse(linearRawText());

  if (!isLinearFixtureFile(file)) return ['guard-rejected: fixture file fails the corpus guard before the mutation'];

  const cases: LinearCaseMirror[] = [...file.cases];

  mutator(cases);

  if (!isGuardedCaseSequence(cases)) return ['guard-rejected: mutated corpus fails the corpus guard'];

  return linearCorpusDefects(cases);
}

// ------------------------------------------------------------------ recomputation helpers
function bodyBytesOf(case_: LinearCaseMirror): Uint8Array {
  return independentBase64Bytes(case_.request.bodyBase64);
}

function recordedSignatureOf(id: string, name: string = LINEAR_SIG_HEADER): string {
  return combinedHeader(findLinearCase(id), name) ?? '';
}

/** Shape guard for the pinned timestamp bodies; typeof stays inside the guard per house rules. */
function isSyntheticTimestampBody(value: unknown): value is { readonly createdAt: string } {
  if (typeof value !== 'object' || value === null) return false;

  return 'createdAt' in value && isString(value.createdAt);
}

/** Reads the pinned createdAt text of a decoded synthetic timestamp body. */
function bodyCreatedAtText(case_: LinearCaseMirror): string {
  const parsed: unknown = JSON.parse(UTF8_LOOSE.decode(independentBase64Bytes(case_.request.bodyBase64)));

  if (!isSyntheticTimestampBody(parsed)) throw new Error('body is not the expected synthetic timestamp body');

  return parsed.createdAt;
}

describe('phase 8 linear fixture inventory', () => {
  it('loads the linear fixture file with the exact pinned inventory in file order', () => {
    expect(LINEAR_CASES.map((case_) => case_.id)).toEqual([...LINEAR_CASE_IDS]);
    expect(LINEAR_CASES).toHaveLength(LINEAR_CASE_IDS.length);
  });

  it('passes the shared validator and the owned stricter guard on fresh parses', () => {
    const file: unknown = JSON.parse(linearRawText());

    expect(isFixtureFile(file)).toBe(true);
    expect(isLinearFixtureFile(file)).toBe(true);
  });

  it('keeps every case locally generated rather than claiming reference-vector provenance', () => {
    expect(LINEAR_CASES.every((case_) => case_.provenance.class === 'local')).toBe(true);
    expect(LINEAR_CASES.every((case_) => !('commit' in case_.provenance) && !('fetched' in case_.provenance))).toBe(true);
  });

  it('pins the primary research sources in every provenance string', () => {
    const problems = LINEAR_CASES.flatMap((case_) => PROVENANCE_MARKERS
      .flatMap((marker) => (case_.provenance.source.includes(marker) ? [] : [`${case_.id}: provenance misses '${marker}'`])));

    expect(problems).toEqual([]);
  });

  it('restricts every failure reason to the frozen three-reason vocabulary', () => {
    const problems = LINEAR_CASES.flatMap((case_) => {
      if (case_.expected.ok) return case_.expected.reason === undefined ? [] : [`${case_.id}: ok case carries a reason`];

      return LINEAR_REASONS.has(case_.expected.reason ?? '') ? [] : [`${case_.id}: reason '${case_.expected.reason}' outside vocabulary`];
    });

    expect(problems).toEqual([]);
  });

  it('never invents freshness, missing-timestamp or identity families in the body-only corpus', () => {
    const leaks = LINEAR_CASES.flatMap((case_) => (FORBIDDEN_REASON_FAMILIES.includes(case_.expected.reason ?? '') ? [case_.id] : []));

    expect(leaks).toEqual([]);
    expect(LINEAR_CASES.every((case_) => case_.expected.ok || LINEAR_REASONS.has(case_.expected.reason ?? ''))).toBe(true);
  });

  it('counts sixteen positives, fifteen negatives with three missing, three invalid and nine malformed, and two override rows', () => {
    const positives = LINEAR_CASES.filter((case_) => case_.expected.ok);
    const negatives = LINEAR_CASES.filter((case_) => !case_.expected.ok);
    const overrides = LINEAR_CASES.filter((case_) => case_.webHeadersExpected !== undefined);
    const missing = negatives.filter((case_) => case_.expected.reason === 'missing-signature');
    const invalid = negatives.filter((case_) => case_.expected.reason === 'invalid-signature');
    const malformed = negatives.filter((case_) => case_.expected.reason === 'malformed-signature');

    expect(positives).toHaveLength(16);
    expect(negatives).toHaveLength(15);
    expect(overrides).toHaveLength(2);
    expect(missing).toHaveLength(3);
    expect(invalid).toHaveLength(3);
    expect(malformed).toHaveLength(9);
  });
});

describe('fresh linear outcome model over record and WHATWG views', () => {
  it('agrees with every pinned outcome across the corpus in both views, including provenance', () => {
    expect(linearCorpusDefects(LINEAR_CASES)).toEqual([]);
  });

  it('declares exactly the two whitespace rows as materially different overrides', () => {
    const declared = LINEAR_CASES.flatMap((case_) => (case_.webHeadersExpected !== undefined ? [case_.id] : []));

    expect(declared).toEqual([...OVERRIDE_IDS]);

    for (const id of OVERRIDE_IDS) {
      const case_ = findLinearCase(id);

      expect(case_.expected.ok).toBe(false);
      expect(case_.expected.reason).toBe('malformed-signature');
      expect(case_.webHeadersExpected?.ok).toBe(true);
      expect(isStrictLinearIdentity(case_.webHeadersExpected?.identity)).toBe(true);

      const recordText = recordedSignatureOf(id);

      expect(recordText.startsWith(' ') || recordText.endsWith(' ')).toBe(true);
      expect(recordText.trim()).toMatch(LOWER_HEX_64);
      expect(linearOutcome(case_, 'web').ok).toBe(true);
    }
  });

  it('classifies trim-blank values as missing in both views without a declared override', () => {
    const blank = findLinearCase('blank-signature-is-missing');

    expect(headerMapOf(blank, 'record').get(LINEAR_SIG_HEADER)).toBe('   ');
    expect(linearOutcome(blank, 'record')).toEqual({ ok: false, reason: 'missing-signature' });
    expect(linearOutcome(blank, 'web')).toEqual({ ok: false, reason: 'missing-signature' });
    expect(blank.webHeadersExpected).toBeUndefined();
  });

  it('keeps every WHATWG-trimmed outcome identical to the record except for declared trim rows', () => {
    const differing = LINEAR_CASES
      .flatMap((case_) => (outcomeSignature(linearOutcome(case_, 'record')) !== outcomeSignature(linearOutcome(case_, 'web')) ? [case_.id] : []));

    expect(differing).toEqual([...OVERRIDE_IDS]);
  });
});

describe('records every positive against configured secrets with node:crypto', () => {
  it('recomputes the baseline digest over the independent decoded body', () => {
    const baseline = cloneCase('positive-baseline');
    const body = bodyBytesOf(baseline);
    const recorded = recordedSignatureOf('positive-baseline');

    expect(HEX_64.test(recorded)).toBe(true);
    expect(recorded).toBe(digestHexFor(MAIN_SECRET, body));
    expect(sameBytes(body, encodedBodyBytes(baseline))).toBe(true);
  });

  it('accepts the uppercase header by case-insensitive hex semantics alone', () => {
    const recorded = recordedSignatureOf('positive-uppercase-hex-accepted');
    const baselineRecorded = recordedSignatureOf('positive-baseline');

    expect(recorded).toBe(digestHexFor(MAIN_SECRET, bodyBytesOf(cloneCase('positive-uppercase-hex-accepted'))).toUpperCase());
    expect(recorded.toLowerCase()).toBe(baselineRecorded);
  });

  it('recomputes all three literal-secret rows exactly, including the trimmed-key contrast', () => {
    const whitespaceRecorded = recordedSignatureOf('positive-whitespace-only-secret-literal');
    const nonasciiRecorded = recordedSignatureOf('positive-nonascii-secret-literal');
    const untrimmedRecorded = recordedSignatureOf('positive-untrimmed-secret-literal');
    const baselineRecorded = recordedSignatureOf('positive-baseline');

    expect(whitespaceRecorded).toBe(digestHexFor(WHITESPACE_SECRET, bodyBytesOf(cloneCase('positive-whitespace-only-secret-literal'))));
    expect(findLinearCase('positive-whitespace-only-secret-literal').options.secrets).toEqual([WHITESPACE_SECRET]);

    expect(nonasciiRecorded).toBe(digestHexFor(NONASCII_SECRET, bodyBytesOf(cloneCase('positive-nonascii-secret-literal'))));

    const body = bodyBytesOf(cloneCase('positive-untrimmed-secret-literal'));

    expect(untrimmedRecorded).toBe(digestHexFor(UNTRIMMED_SECRET, body));
    expect(untrimmedRecorded).not.toBe(digestHexFor(UNTRIMMED_SECRET.trim(), body));
    expect(untrimmedRecorded).not.toBe(baselineRecorded);
  });

  it('verifies the rotation accept row with the old secret and rejects it after removal', () => {
    const acceptCase = findLinearCase('rotation-both-secrets-accept-old');
    const removalCase = findLinearCase('rotation-old-secret-after-removal');
    const acceptRecorded = recordedSignatureOf('rotation-both-secrets-accept-old');
    const removalRecorded = recordedSignatureOf('rotation-old-secret-after-removal');

    expect(acceptCase.options.secrets).toEqual([OLD_SECRET, NEW_SECRET]);
    expect(acceptCase.expected.ok).toBe(true);
    expect(acceptRecorded).toBe(digestHexFor(OLD_SECRET, bodyBytesOf(cloneCase('rotation-both-secrets-accept-old'))));

    expect(removalRecorded).toBe(acceptRecorded);
    expect(removalCase.options.secrets).toEqual([NEW_SECRET]);
    expect(removalCase.expected).toEqual({ ok: false, reason: 'invalid-signature' });
    expect(removalRecorded).not.toBe(digestHexFor(NEW_SECRET, bodyBytesOf(cloneCase('rotation-old-secret-after-removal'))));
    expect(removalRecorded).not.toBe(digestHexFor(MAIN_SECRET, bodyBytesOf(cloneCase('rotation-old-secret-after-removal'))));
    expect(linearOutcome(removalCase, 'record')).toEqual({ ok: false, reason: 'invalid-signature' });
  });

  it('proves deliberately invalid well-formed signatures match no configured secret', () => {
    const mismatches = LINEAR_CASES.flatMap((case_) => {
      if (case_.expected.reason !== 'invalid-signature') return [];

      const recorded = recordedSignatureOf(case_.id);

      if (!HEX_64.test(recorded)) return [`${case_.id}: invalid-signature fixture is not well-formed`];

      return case_.options.secrets.some((secret) => digestHexFor(secret, bodyBytesOf(cloneCase(case_.id))) === recorded)
        ? [`${case_.id}: supposedly invalid signature actually verifies`]
        : [];
    });

    expect(mismatches).toEqual([]);

    const wrongKeyRecorded = recordedSignatureOf('wrong-key-valid-grammar');

    expect(wrongKeyRecorded).toMatch(LOWER_HEX_64);
    expect(wrongKeyRecorded).toBe(digestHexFor(WRONG_KEY_SECRET, bodyBytesOf(cloneCase('wrong-key-valid-grammar'))));
    expect(linearOutcome(findLinearCase('wrong-key-valid-grammar'), 'record')).toEqual({ ok: false, reason: 'invalid-signature' });
  });

  it('signs empty, non-JSON, invalid-UTF-8, binary and NUL bodies over the exact bytes', () => {
    const emptyBytes = bodyBytesOf(cloneCase('positive-empty-body-signed'));

    expect(emptyBytes.length).toBe(0);
    expect(() => JSON.parse(UTF8_LOOSE.decode(bodyBytesOf(cloneCase('positive-non-json-body-signed'))))).toThrow();
    expect(() => UTF8_STRICT.decode(bodyBytesOf(cloneCase('positive-invalid-utf8-body-signed')))).toThrow();
    expect(() => UTF8_STRICT.decode(bodyBytesOf(cloneCase('positive-binary-body-signed')))).toThrow();
    expect([...bodyBytesOf(cloneCase('positive-nul-byte-body-signed'))]).toEqual([0x00, 0x01, 0x02]);
    expect(() => UTF8_STRICT.decode(bodyBytesOf(cloneCase('positive-nul-byte-body-signed')))).not.toThrow();

    for (const id of ['positive-empty-body-signed', 'positive-non-json-body-signed', 'positive-binary-body-signed', 'positive-invalid-utf8-body-signed', 'positive-nul-byte-body-signed']) {
      const recorded = recordedSignatureOf(id);

      expect(linearOutcome(findLinearCase(id), 'record').ok).toBe(true);
      expect(recorded).toBe(digestHexFor(MAIN_SECRET, bodyBytesOf(cloneCase(id))));
    }
  });

  it('proves the tampered row keeps the original MAC while the stored body diverges', () => {
    const baselineRecorded = recordedSignatureOf('positive-baseline');
    const tamperedRecorded = recordedSignatureOf('tampered-body-invalid-signature');

    expect(tamperedRecorded).toBe(baselineRecorded);
    expect(tamperedRecorded).toBe(digestHexFor(MAIN_SECRET, bodyBytesOf(cloneCase('positive-baseline'))));
    expect(tamperedRecorded).not.toBe(digestHexFor(MAIN_SECRET, bodyBytesOf(cloneCase('tampered-body-invalid-signature'))));
    expect(findLinearCase('tampered-body-invalid-signature').request.bodyBase64).not.toBe(findLinearCase('positive-baseline').request.bodyBase64);
    expect(findLinearCase('tampered-body-invalid-signature').expected).toEqual({ ok: false, reason: 'invalid-signature' });
  });

  it('keeps old and future body timestamps authenticated because linear has no freshness', () => {
    const oldCase = findLinearCase('positive-old-body-timestamp-with-valid-mac');
    const futureCase = findLinearCase('positive-future-body-timestamp-with-valid-mac');

    expect(oldCase.expected.ok).toBe(true);
    expect(futureCase.expected.ok).toBe(true);
    expect(bodyCreatedAtText(oldCase)).toBe('2020-01-01T00:00:00.000Z');
    expect(bodyCreatedAtText(futureCase)).toBe('2029-12-31T23:59:59.000Z');
    expect(recordedSignatureOf('positive-old-body-timestamp-with-valid-mac', 'linear-timestamp')).toBe('1600000000');
    expect(recordedSignatureOf('positive-future-body-timestamp-with-valid-mac', 'linear-timestamp')).toBe('1900000000');
    expect(recordedSignatureOf('positive-old-body-timestamp-with-valid-mac')).toBe(digestHexFor(MAIN_SECRET, bodyBytesOf(oldCase)));
    expect(recordedSignatureOf('positive-future-body-timestamp-with-valid-mac')).toBe(digestHexFor(MAIN_SECRET, bodyBytesOf(futureCase)));
    expect(bodyBytesOf(oldCase).length).toBeGreaterThan(0);
  });
});

describe('identity stays unauthenticated and unsigned context is ignored', () => {
  it('pins the all-null identity map with empty authenticated fields on every positive', () => {
    const problems = LINEAR_CASES.flatMap((case_) => {
      if (!case_.expected.ok) return [];

      return isStrictLinearIdentity(case_.expected.identity) ? [] : [`${case_.id}: positive identity is not the all-null body-only map`];
    });

    expect(problems).toEqual([]);
  });

  it('shows delivery/event/timestamp context headers present but never entering identity', () => {
    const contextCase = findLinearCase('positive-unsigned-context-headers-ignored');
    const casingCase = findLinearCase('positive-request-header-casing-variant');

    expect(recordedSignatureOf('positive-unsigned-context-headers-ignored', 'linear-delivery')).toBe(DELIVERY_ID);
    expect(recordedSignatureOf('positive-unsigned-context-headers-ignored', 'Linear-Event')).toBe('IssueCreated');
    expect(recordedSignatureOf('positive-unsigned-context-headers-ignored', 'linear-timestamp')).toBe('1700000100');
    expect(contextCase.expected.ok).toBe(true);
    expect(isStrictLinearIdentity(contextCase.expected.identity)).toBe(true);

    expect(recordedSignatureOf('positive-request-header-casing-variant')).toBe(recordedSignatureOf('positive-baseline'));
    expect(recordedSignatureOf('positive-request-header-casing-variant', 'linear-delivery')).toBe(DELIVERY_ID);
    expect(casingCase.expected.ok).toBe(true);
  });

  it('never derives identity from body or context in any row', () => {
    const leaks = LINEAR_CASES.flatMap((case_) => {
      if (!case_.expected.ok || case_.expected.identity === undefined) return [];

      const identity = case_.expected.identity;

      return identity.deliveryId !== null || identity.eventId !== null || identity.timestamp !== null || identity.authenticatedFields.length !== 0
        ? [`${case_.id}: identity escaped the all-null map`]
        : [];
    });

    expect(leaks).toEqual([]);
  });
});

describe('alien headers never rescue linear-signature', () => {
  it('cannot authenticate a real MAC recorded under an alien header name', () => {
    const rescueCase = findLinearCase('alien-signature-header-cannot-rescue');
    const alienRecorded = recordedSignatureOf('alien-signature-header-cannot-rescue', 'x-webhook-signature');

    expect(recordedSignatureOf('alien-signature-header-cannot-rescue')).toBe('');
    expect(alienRecorded).toBe(digestHexFor(MAIN_SECRET, bodyBytesOf(cloneCase('alien-signature-header-cannot-rescue'))));
    expect(rescueCase.expected).toEqual({ ok: false, reason: 'missing-signature' });
    expect(linearOutcome(rescueCase, 'record')).toEqual({ ok: false, reason: 'missing-signature' });
    expect(linearOutcome(rescueCase, 'web')).toEqual({ ok: false, reason: 'missing-signature' });
  });

  it('ignores alien signature-family headers while the configured header authenticates', () => {
    const decoyRecorded = recordedSignatureOf('positive-alien-signature-header-ignored', 'x-standard-webhooks-signature');

    expect(decoyRecorded.startsWith('v1,')).toBe(true);
    expect(decoyRecorded.slice(3)).toHaveLength(40);
    expect(decoyRecorded).not.toBe(recordedSignatureOf('positive-alien-signature-header-ignored'));
    expect(findLinearCase('positive-alien-signature-header-ignored').expected.ok).toBe(true);
    expect(isStrictLinearIdentity(findLinearCase('positive-alien-signature-header-ignored').expected.identity)).toBe(true);
  });
});

describe('pins the raw shapes behind the missing and malformed families', () => {
  it('records the missing family exactly', () => {
    expect(recordedSignatureOf('missing-signature-header')).toBe('');
    expect(recordedSignatureOf('missing-signature-header', 'linear-delivery')).toBeDefined();

    const blank = recordedSignatureOf('blank-signature-is-missing');

    expect(blank).toBe('   ');
    expect(blank.trim()).toBe('');
  });

  it('records every malformed grammar text verbatim, with real MACs where the sub-values carry them', () => {
    const prefix = recordedSignatureOf('signature-led-prefix-is-malformed');

    expect(prefix.startsWith('sha256=')).toBe(true);
    expect(prefix.slice('sha256='.length)).toMatch(LOWER_HEX_64);
    expect(prefix.slice('sha256='.length)).toBe(recordedSignatureOf('positive-baseline'));

    const listToken = recordedSignatureOf('standard-webhooks-token-is-malformed');

    expect(listToken.startsWith('v1,')).toBe(true);
    expect(listToken.slice(3)).toHaveLength(44);
    expect(listToken.slice(3)).toMatch(BASE64_STD_TOKEN);

    const leading = recordedSignatureOf('signature-outer-whitespace-is-malformed-record-view');

    expect(leading.startsWith(' ')).toBe(true);
    expect(leading.trim()).toMatch(LOWER_HEX_64);

    const inner = recordedSignatureOf('signature-inner-whitespace-is-malformed');
    const innerParts = inner.split(' ');

    expect(innerParts).toHaveLength(2);
    expect(innerParts.map((part) => LOWER_HEX_32.test(part)).every(Boolean)).toBe(true);
    expect(innerParts.join('')).toHaveLength(64);

    const commaValue = recordedSignatureOf('comma-combined-duplicates-are-malformed');
    const commaHalves = commaValue.split(', ');

    expect(commaHalves).toHaveLength(2);
    expect(commaHalves[0]).toBe(commaHalves[1]);
    expect(commaHalves[0]).toMatch(LOWER_HEX_64);

    const trailing = recordedSignatureOf('signature-trailing-whitespace-is-headers-trim-accepts');

    expect(trailing.endsWith(' ')).toBe(true);
    expect(trailing.trim()).toMatch(LOWER_HEX_64);

    expect(recordedSignatureOf('hex-63-characters-are-malformed')).toMatch(LOWER_HEX_63);
    expect(recordedSignatureOf('hex-65-characters-are-malformed')).toMatch(LOWER_HEX_65);

    const nonhex = recordedSignatureOf('non-hex-character-is-malformed');

    expect(nonhex).toHaveLength(64);
    expect(nonhex.charAt(0)).toBe(NONHEX_SENTINEL_CHAR);
    expect(nonhex.slice(1)).toMatch(LOWER_HEX_63);
  });

  it('keeps the WHATWG trim scope honest for this corpus', () => {
    const problems = LINEAR_CASES.flatMap((case_) => Object.entries(case_.request.headers).flatMap(([name, value]) => {
      const texts = Array.isArray(value) ? value : [value];

      return texts.every((text) => ASCII_PRINTABLE.test(text)) ? [] : [`${case_.id}: header ${name} leaves the ASCII-printable trim-comparability scope`];
    }));

    expect(problems).toEqual([]);
  });
});

describe('owned corpus guard negatives exercise distinct real clauses', () => {
  function probedClone(id: string): LinearCaseMirror {
    return structuredClone(findLinearCase(id));
  }

  function guardAccepts(case_: LinearCaseMirror): boolean {
    return isGuardedCaseSequence([case_]);
  }

  it('rejects a non-token header name instead of failing the outer envelope only', () => {
    const case_ = probedClone('positive-baseline');

    expect(guardAccepts(case_)).toBe(true);

    case_.request.headers = { 'bad header name': case_.request.headers[LINEAR_SIG_HEADER] ?? 'v' };

    expect(guardAccepts(case_)).toBe(false);
  });

  it('rejects a header value outside the string/array-of-strings shape', () => {
    const case_ = probedClone('positive-baseline');

    Object.defineProperty(case_.request.headers, LINEAR_SIG_HEADER, { value: 1700000100, enumerable: true, writable: true, configurable: true });

    expect(guardAccepts(case_)).toBe(false);
  });

  it('rejects an empty string inside an array-valued header', () => {
    const case_ = probedClone('positive-baseline');

    case_.request.headers[LINEAR_SIG_HEADER] = ['valid-digest-text', ''];

    expect(guardAccepts(case_)).toBe(false);
  });

  it('rejects an empty secret entry', () => {
    const case_ = probedClone('positive-baseline');

    case_.options.secrets = [''];

    expect(guardAccepts(case_)).toBe(false);
  });

  it('rejects a non-string secret entry', () => {
    const case_ = probedClone('positive-baseline');

    Object.defineProperty(case_.options, 'secrets', { value: [42], enumerable: true, writable: true, configurable: true });

    expect(guardAccepts(case_)).toBe(false);
  });

  it('rejects a non-numeric now field', () => {
    const case_ = probedClone('positive-baseline');

    Object.defineProperty(case_.options, 'now', { value: '1700000100', enumerable: true, writable: true, configurable: true });

    expect(guardAccepts(case_)).toBe(false);
  });

  it('rejects providerOptions, toleranceSeconds and maxBodyBytes keys linear must never accept', () => {
    const withForeignOptions = probedClone('positive-baseline');
    const withForeignTolerance = probedClone('positive-whitespace-only-secret-literal');
    const withForeignBodyLimit = probedClone('positive-empty-body-signed');

    Object.defineProperty(withForeignOptions.options, 'providerOptions', { value: { mode: 'body' }, enumerable: true, writable: true, configurable: true });
    Object.defineProperty(withForeignTolerance.options, 'toleranceSeconds', { value: 90, enumerable: true, writable: true, configurable: true });
    Object.defineProperty(withForeignBodyLimit.options, 'maxBodyBytes', { value: 1024, enumerable: true, writable: true, configurable: true });

    expect(guardAccepts(withForeignOptions)).toBe(false);
    expect(guardAccepts(withForeignTolerance)).toBe(false);
    expect(guardAccepts(withForeignBodyLimit)).toBe(false);
  });

  it('rejects a positive row losing its all-null identity or gaining a reason', () => {
    const withoutIdentity = probedClone('positive-baseline');

    delete withoutIdentity.expected.identity;

    expect(guardAccepts(withoutIdentity)).toBe(false);

    const withReason = probedClone('positive-baseline');

    Object.defineProperty(withReason.expected, 'reason', { value: 'invalid-signature', enumerable: true, writable: true, configurable: true });

    expect(guardAccepts(withReason)).toBe(false);
  });

  it('rejects a negative row carrying an identity map', () => {
    const withIdentity = probedClone('missing-signature-header');

    Object.defineProperty(withIdentity.expected, 'identity', { value: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] }, enumerable: true, writable: true, configurable: true });

    expect(guardAccepts(withIdentity)).toBe(false);
  });

  it('rejects a reason outside the frozen vocabulary', () => {
    const stale = probedClone('missing-signature-header');

    Object.defineProperty(stale.expected, 'reason', { value: 'timestamp-expired', enumerable: true, writable: true, configurable: true });

    expect(guardAccepts(stale)).toBe(false);
  });

  it('flags a non-local provenance class through the defect layer', () => {
    const referenceClone = probedClone('positive-baseline');

    referenceClone.provenance.class = 'reference';

    const defects = linearCorpusDefects([referenceClone]).filter((defect) => !defect.startsWith('inventory mismatch'));

    expect(defects.some((defect) => defect.startsWith('positive-baseline: provenance class must be local'))).toBe(true);
  });
});

/** Locates a row in the freshly parsed-and-mutated corpus; a lost id is a mutation-control failure. */
function mutatedCaseById(cases: readonly LinearCaseMirror[], id: string): LinearCaseMirror {
  const found = cases.find((entry) => entry.id === id);

  if (found === undefined) throw new Error(`mutated corpus lost the id: ${id}`);

  return found;
}

describe('mutation controls on a cloned corpus', () => {
  it('renaming an id breaks the exact inventory', () => {
    const defects = linearDefectsAfterMutation((cases) => {
      mutatedCaseById(cases, 'positive-baseline').id = 'mutated-linear-id';
    });

    expect(defects.some((defect) => defect.startsWith('inventory mismatch'))).toBe(true);
  });

  it('removing a row breaks the exact inventory', () => {
    const defects = linearDefectsAfterMutation((cases) => {
      cases.splice(4, 1);
    });

    expect(defects.filter((defect) => defect.startsWith('inventory mismatch')).length).toBeGreaterThan(0);
  });

  it('flipping one signature hex character is detected as a record-view mismatch', () => {
    const defects = linearDefectsAfterMutation((cases) => {
      const case_ = mutatedCaseById(cases, 'positive-baseline');
      const existing: unknown = case_.request.headers[LINEAR_SIG_HEADER];
      const text = isString(existing) ? existing : '';

      case_.request.headers[LINEAR_SIG_HEADER] = text.replace(/^./, text.startsWith('9') ? 'a' : '9');
    });

    expect(defects.some((defect) => defect.startsWith('positive-baseline: record view mismatch'))).toBe(true);
  });

  it('flipping one body byte is detected without changing the signature shape', () => {
    const defects = linearDefectsAfterMutation((cases) => {
      const case_ = mutatedCaseById(cases, 'positive-baseline');

      case_.request.bodyBase64 = `Q${case_.request.bodyBase64.slice(1)}`;
    });

    expect(defects.some((defect) => defect.startsWith('positive-baseline: record view mismatch'))).toBe(true);
  });

  it('changing a secret without re-signing is detected', () => {
    const defects = linearDefectsAfterMutation((cases) => {
      const case_ = mutatedCaseById(cases, 'positive-baseline');

      case_.options.secrets = [NEVER_CONFIGURED_SECRET];
    });

    expect(defects.some((defect) => defect.startsWith('positive-baseline: record view mismatch'))).toBe(true);
  });

  it('flipping the verdict with a reason is detected by the model comparison', () => {
    const defects = linearDefectsAfterMutation((cases) => {
      const case_ = mutatedCaseById(cases, 'positive-baseline');

      case_.expected.ok = false;
      case_.expected.reason = 'invalid-signature';
      delete case_.expected.identity;
    });

    expect(defects.some((defect) => defect.startsWith('positive-baseline: record view mismatch'))).toBe(true);
  });

  it('swapping a missing failure to invalid-signature is detected', () => {
    const defects = linearDefectsAfterMutation((cases) => {
      const case_ = mutatedCaseById(cases, 'missing-signature-header');

      case_.expected.reason = 'invalid-signature';
    });

    expect(defects.some((defect) => defect.includes('missing-signature-header') && defect.includes('record view mismatch'))).toBe(true);
  });

  it('removing a material webHeadersExpected override is detected', () => {
    const defects = linearDefectsAfterMutation((cases) => {
      const case_ = mutatedCaseById(cases, 'signature-outer-whitespace-is-malformed-record-view');

      delete case_.webHeadersExpected;
    });

    expect(defects.some((defect) => defect.startsWith('signature-outer-whitespace-is-malformed-record-view'))).toBe(true);
  });

  it('adding a providerOptions key linear never accepts is guard-rejected', () => {
    const defects = linearDefectsAfterMutation((cases) => {
      const case_ = mutatedCaseById(cases, 'positive-baseline');

      Object.defineProperty(case_.options, 'providerOptions', { value: { mode: 'body' }, enumerable: true, writable: true, configurable: true });
    });

    expect(defects.some((defect) => defect.startsWith('guard-rejected'))).toBe(true);
  });

  it('adding a toleranceSeconds key linear never accepts is guard-rejected', () => {
    const defects = linearDefectsAfterMutation((cases) => {
      const case_ = mutatedCaseById(cases, 'positive-baseline');

      Object.defineProperty(case_.options, 'toleranceSeconds', { value: 90, enumerable: true, writable: true, configurable: true });
    });

    expect(defects.some((defect) => defect.startsWith('guard-rejected'))).toBe(true);
  });

  it('emptying a secret is guard-rejected', () => {
    const defects = linearDefectsAfterMutation((cases) => {
      const case_ = mutatedCaseById(cases, 'positive-whitespace-only-secret-literal');

      case_.options.secrets = [''];
    });

    expect(defects.some((defect) => defect.startsWith('guard-rejected'))).toBe(true);
  });
});
