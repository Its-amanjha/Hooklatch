import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';

/**
 * Phase 7 GLM Stage A anchor suite for the Grafana and Polar fixture corpora
 * plus the separate setup-invalid options file. It never imports provider
 * modules, the Provider union, verification entry points, or the shared
 * fixture loader/config builders: the new provider ids stay unregistered at
 * this base (16 providers) and these tests validate fixture data only.
 *
 * Every positive and freshness-only signature/token is re-derived with
 * node:crypto from the recorded ACTUAL header text and exact body bytes for
 * both header representations (record preserves outer whitespace; the WHATWG
 * Headers view trims it). Deliberately invalid well-formed signatures are
 * proven to match no configured secret. Grammar failures keep their exact
 * contract reasons and order. Exact inventories and in-memory mutation
 * controls mirror the four false-pass classes reproduced by the phase-6
 * coordinator review. Data/crypto consistency proves fixture semantics only,
 * never public runtime support: at this base these providers are not
 * registered and Stage B wiring is pending. All vectors are class `local`;
 * there is no complete published vector for these modes.
 */

// ----------------------------------------------------------------- corpus types
interface FixtureIdentity {
  readonly deliveryId: string | number | null;
  readonly eventId: string | number | null;
  readonly timestamp: number | null;
  readonly authenticatedFields: readonly string[];
}

interface FixtureOutcome {
  readonly ok: boolean;
  readonly reason?: string;
  readonly identity?: FixtureIdentity;
}

interface GpFixtureCase {
  readonly id: string;
  readonly provenance: {
    readonly class: string;
    readonly source: string;
  };
  readonly request: {
    readonly bodyBase64: string;
    readonly headers: Readonly<Record<string, string | readonly string[]>>;
  };
  readonly options: {
    readonly secrets: readonly string[];
    readonly now: number;
    readonly toleranceSeconds?: number;
    readonly providerOptions?: unknown;
  };
  readonly expected: FixtureOutcome;
  readonly webHeadersExpected?: FixtureOutcome;
}

interface InvalidOptionsRow {
  readonly id: string;
  readonly provider: string;
  readonly providerOptions?: unknown;
  readonly secrets: readonly unknown[];
  readonly expectedError: string;
}

type HeaderView = 'record' | 'web';

type OutcomePair =
  | { readonly ok: true; readonly identity: FixtureIdentity }
  | { readonly ok: false; readonly reason: string };

interface MutableGpCase {
  id: string;
  request: { bodyBase64: string; headers: Record<string, string | readonly string[]> };
  options: { secrets: unknown[]; now: number; providerOptions?: unknown };
  expected: { ok: boolean; reason?: string; identity?: FixtureIdentity };
  webHeadersExpected?: { ok: boolean; reason?: string; identity?: FixtureIdentity };
}

interface MutableIoRow {
  id: string;
  provider: string;
  providerOptions?: unknown;
  secrets: unknown[];
  expectedError: string;
}

// ----------------------------------------------------------------- guards
function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isNumber(value: unknown): value is number {
  return typeof value === 'number';
}

function isStringArray(value: readonly unknown[]): value is readonly string[] {
  return value.length > 0 && value.every((item: unknown): item is string => isString(item));
}

/** RFC 9110 field-name token, mirroring the core header-name grammar. */
const HEADER_NAME_TOKEN = /^[!#$%&'*+.^_`|~\da-z-]+$/i;
const CONTROL_TEXT = /[\r\n\0]/;

function isHeaderNameToken(value: string): boolean {
  return HEADER_NAME_TOKEN.test(value);
}

function isHeaderValue(value: unknown): value is string | readonly string[] {
  if (isString(value)) return !CONTROL_TEXT.test(value);

  if (Array.isArray(value)) {
    return value.length > 0 && value.every(
      (item: unknown): item is string => isString(item) && !CONTROL_TEXT.test(item),
    );
  }

  return false;
}

function isIdentityValue(value: unknown): value is string | number | null {
  return value === null || typeof value === 'string' || typeof value === 'number';
}

function isFixtureIdentity(value: unknown): value is FixtureIdentity {
  if (typeof value !== 'object' || value === null) return false;

  if (!('deliveryId' in value) || !('eventId' in value) || !('timestamp' in value) || !('authenticatedFields' in value)) return false;

  if (!isIdentityValue(value.deliveryId) || !isIdentityValue(value.eventId)) return false;

  if (!(value.timestamp === null || typeof value.timestamp === 'number')) return false;

  if (!Array.isArray(value.authenticatedFields)) return false;

  return value.authenticatedFields.every((item: unknown): item is string => isString(item));
}

function isFixtureOutcome(value: unknown): value is FixtureOutcome {
  if (typeof value !== 'object' || value === null) return false;

  if (!('ok' in value) || typeof value.ok !== 'boolean') return false;

  if ('reason' in value) {
    const reason: unknown = value.reason;

    if (reason !== undefined && typeof reason !== 'string') return false;
  }

  if ('identity' in value) {
    const identity: unknown = value.identity;

    if (identity !== undefined && !isFixtureIdentity(identity)) return false;
  }

  return true;
}

function isGpFixtureCase(value: unknown): value is GpFixtureCase {
  if (typeof value !== 'object' || value === null) return false;

  if (!('id' in value) || typeof value.id !== 'string' || value.id.length === 0) return false;

  if (!('provenance' in value) || typeof value.provenance !== 'object' || value.provenance === null) return false;

  if (!('class' in value.provenance) || (value.provenance.class !== 'local' && value.provenance.class !== 'reference')) return false;

  if (!('source' in value.provenance) || typeof value.provenance.source !== 'string' || value.provenance.source.length === 0) return false;

  if (!('request' in value) || typeof value.request !== 'object' || value.request === null) return false;

  if (!('bodyBase64' in value.request) || typeof value.request.bodyBase64 !== 'string') return false;

  if (!('headers' in value.request) || typeof value.request.headers !== 'object' || value.request.headers === null) return false;

  for (const [name, headerValue] of Object.entries(value.request.headers)) {
    if (!isHeaderNameToken(name)) return false;

    if (!isHeaderValue(headerValue)) return false;
  }

  if (!('options' in value) || typeof value.options !== 'object' || value.options === null) return false;

  if (!('secrets' in value.options) || !Array.isArray(value.options.secrets)) return false;

  if (!isStringArray(value.options.secrets)) return false;

  if (value.options.secrets.some((secret) => secret.length === 0)) return false;

  if (!('now' in value.options) || typeof value.options.now !== 'number') return false;

  if ('toleranceSeconds' in value.options) {
    const tolerance: unknown = value.options.toleranceSeconds;

    if (typeof tolerance !== 'number' || tolerance < 0) return false;
  }

  if ('providerOptions' in value.options) {
    const providerOptions: unknown = value.options.providerOptions;

    if (typeof providerOptions !== 'object' || providerOptions === null || Array.isArray(providerOptions)) return false;
  }

  if (!('expected' in value) || !isFixtureOutcome(value.expected)) return false;

  if ('webHeadersExpected' in value) {
    const webHeadersExpected: unknown = value.webHeadersExpected;

    if (webHeadersExpected !== undefined && !isFixtureOutcome(webHeadersExpected)) return false;
  }

  return true;
}

interface GpFixtureFile {
  readonly cases: readonly GpFixtureCase[];
}

function isGpCaseArray(value: unknown): value is readonly GpFixtureCase[] {
  if (!Array.isArray(value) || value.length === 0) return false;

  return value.every((entry: unknown): entry is GpFixtureCase => isGpFixtureCase(entry));
}

function isGpFixtureFile(value: unknown): value is GpFixtureFile {
  if (typeof value !== 'object' || value === null || !('cases' in value) || !Array.isArray(value.cases)) return false;

  return value.cases.length > 0 && value.cases.every((entry: unknown): entry is GpFixtureCase => isGpFixtureCase(entry));
}

function isInvalidOptionsRow(value: unknown): value is InvalidOptionsRow {
  if (typeof value !== 'object' || value === null) return false;

  if (!('id' in value) || typeof value.id !== 'string' || value.id.length === 0) return false;

  if (!('provider' in value) || (value.provider !== 'grafana' && value.provider !== 'polar')) return false;

  if (!('secrets' in value) || !Array.isArray(value.secrets) || value.secrets.length === 0) return false;

  const entries = value.secrets;

  const allStringOrNumber = entries.every(
    (item: unknown): item is string | number => isString(item) || isNumber(item),
  );

  if (!allStringOrNumber) return false;

  if (!('expectedError' in value) || (value.expectedError !== 'invalid-options' && value.expectedError !== 'invalid-secret')) return false;

  return true;
}

// ----------------------------------------------------------------- loading
const GRAFANA_JSON_URL = new URL('../fixtures/grafana.json', import.meta.url);
const POLAR_JSON_URL = new URL('../fixtures/polar.json', import.meta.url);
const INVALID_OPTIONS_JSON_URL = new URL('./invalid-options.json', import.meta.url);

function requireCases(url: URL, label: string): readonly GpFixtureCase[] {
  const parsed: unknown = JSON.parse(readFileSync(url, 'utf8'));

  if (!isGpFixtureFile(parsed)) throw new Error(`${label} fixture file is malformed`);

  const cases: readonly GpFixtureCase[] = parsed.cases;
  const ids = cases.map((entry) => entry.id);

  if (new Set(ids).size !== ids.length) throw new Error(`${label} fixture ids are not unique`);

  return cases;
}

interface InvalidOptionsFile {
  readonly schemaVersion: 1;
  readonly cases: readonly InvalidOptionsRow[];
}

function isInvalidOptionsFile(value: unknown): value is InvalidOptionsFile {
  if (typeof value !== 'object' || value === null) return false;

  if (!('schemaVersion' in value) || value.schemaVersion !== 1) return false;

  if (!('cases' in value) || !Array.isArray(value.cases)) return false;

  return value.cases.every((row: unknown): row is InvalidOptionsRow => isInvalidOptionsRow(row));
}

function requireInvalidRows(): readonly InvalidOptionsRow[] {
  const parsed: unknown = JSON.parse(readFileSync(INVALID_OPTIONS_JSON_URL, 'utf8'));

  if (!isInvalidOptionsFile(parsed)) throw new Error('invalid-options file is malformed');

  const rows: readonly InvalidOptionsRow[] = parsed.cases;
  const ids = rows.map((row) => row.id);

  if (new Set(ids).size !== ids.length) throw new Error('invalid-options ids are not unique');

  return rows;
}

// ----------------------------------------------------------------- exact inventories
const GRAFANA_CASE_IDS = [
  'positive-body-default-header',
  'positive-uppercase-hex-accepted',
  'positive-custom-header-and-decoy-default',
  'positive-config-casing-is-lookup-only',
  'positive-request-header-casing-variant',
  'positive-unsigned-context-headers-present',
  'positive-empty-body-signed',
  'positive-non-json-body-signed',
  'positive-invalid-utf8-body-signed',
  'body-mode-ignores-timestamp-header',
  'rotation-both-secrets-accept-old',
  'rotation-old-secret-after-removal',
  'tampered-body-invalid-signature',
  'wrong-key-valid-grammar',
  'missing-signature-header',
  'blank-signature-is-missing',
  'signature-inner-whitespace-is-malformed',
  'signature-led-prefix-is-malformed',
  'hex-63-characters-are-malformed',
  'hex-65-characters-are-malformed',
  'non-hex-character-is-malformed',
  'standard-webhooks-token-is-malformed',
  'comma-combined-duplicates-are-malformed',
  'signature-outer-whitespace-is-malformed-record-view',
  'signature-trailing-whitespace-is-headers-trim-accepts',
  'positive-timestamped-default-header',
  'positive-timestamped-custom-headers',
  'timestamped-zero-timestamp-canonical-but-expired',
  'timestamped-docs-casing-config',
  'rotation-both-secrets-accept-old-timestamped',
  'timestamped-missing-timestamp-header',
  'timestamped-blank-timestamp-is-missing',
  'timestamped-noncanonical-leading-zero',
  'timestamped-negative-timestamp-is-malformed',
  'timestamped-fractional-timestamp-is-malformed',
  'timestamped-comma-joined-timestamp-malformed',
  'timestamped-missing-signature-beats-timestamp-missing',
  'timestamped-custom-header-absent-no-default-fallback',
  'timestamped-body-layout-signature-no-downgrade',
  'body-mode-timestamped-layout-signature-no-upgrade',
  'tampered-signed-timestamp-text',
  'wrong-signature-beats-stale',
  'boundary-plus300-ok',
  'boundary-plus301-future',
  'boundary-minus300-ok',
  'boundary-minus301-expired',
  'tolerance-zero-same-second-ok',
  'tolerance-zero-old-expired',
  'tolerance-zero-future',
  'timestamped-timestamp-outer-whitespace-is-headers-trim-accepts',
] as const;

const POLAR_CASE_IDS = [
  'positive-current-baseline',
  'positive-request-casing-variants',
  'positive-legacy-literal-key',
  'positive-legacy-keeps-whsec-prefix-literal',
  'positive-multi-token-space-list',
  'positive-trailing-whitespace-tolerated',
  'rotation-both-secrets-accept-old',
  'rotation-old-secret-after-removal',
  'positive-unsigned-extra-header-ignored',
  'positive-empty-body-signed',
  'positive-non-json-body-signed',
  'positive-invalid-utf8-body-signed',
  'id-with-dot-is-malformed',
  'id-with-comma-is-malformed',
  'missing-identity-header',
  'missing-timestamp-header',
  'timestamp-leading-zero-is-malformed',
  'blank-signature-is-missing',
  'missing-signature-header',
  'bare-value-without-comma-is-malformed',
  'trailing-comma-token-is-malformed',
  'unknown-scheme-only-is-unsupported',
  'malformed-token-fails-closed-despite-valid',
  'comma-combined-duplicates-are-malformed',
  'wrong-key-valid-grammar',
  'tampered-body-invalid-signature',
  'tampered-signed-timestamp-text',
  'wrong-signature-beats-stale',
  'legacy-signed-is-not-rescued-under-current',
  'current-signed-is-not-rescued-under-legacy-mode',
  'svix-family-cannot-repair-canonical-fields',
  'svix-alias-does-not-rescue-canonical-mismatch',
  'boundary-plus300-ok',
  'boundary-plus301-future',
  'boundary-minus300-ok',
  'boundary-minus301-expired',
  'tolerance-zero-same-second-ok',
  'tolerance-zero-old-expired',
  'tolerance-zero-future',
  'timestamp-outer-whitespace-is-headers-trim-accepts',
] as const;

const INVALID_OPTIONS_IDS = [
  'grafana-provider-options-absent-is-invalid',
  'grafana-provider-options-null-is-not-an-object',
  'grafana-mode-is-required',
  'grafana-unknown-mode-is-invalid',
  'grafana-body-rejects-own-timestamp-header',
  'grafana-timestamped-requires-timestamp-header',
  'grafana-explicit-empty-signature-header',
  'grafana-explicit-null-signature-header',
  'grafana-reserved-signature-header-is-rejected',
  'grafana-reserved-timestamp-header-is-rejected',
  'grafana-colliding-names-are-invalid',
  'grafana-signature-header-not-a-token',
  'grafana-unexpected-own-key-is-rejected',
  'grafana-secret-entry-beats-invalid-mode',
  'polar-secret-entry-beats-invalid-mode',
  'polar-non-string-secret-entry-is-invalid-secret',
  'polar-unknown-secret-mode-is-invalid',
  'polar-null-secret-mode-is-invalid',
  'polar-options-null-is-not-an-object',
  'polar-unexpected-own-key-is-rejected',
  'polar-non-base64-secret-under-current',
  'polar-too-short-canonical-key',
  'polar-mixed-era-list-decodes-per-mode',
  'polar-invalid-config-beats-bad-current-secret',
] as const;

const GRAFANA_REASONS = new Set<string>([
  'missing-signature',
  'malformed-signature',
  'missing-timestamp',
  'invalid-signature',
  'timestamp-expired',
  'timestamp-future',
]);

const POLAR_REASONS = new Set<string>([
  'missing-signature',
  'malformed-signature',
  'unsupported-scheme',
  'missing-identity',
  'missing-timestamp',
  'invalid-signature',
  'timestamp-expired',
  'timestamp-future',
]);

// ----------------------------------------------------------------- byte helpers (independent)
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function base64Table(): Map<string, number> {
  const table = new Map<string, number>();

  for (let index = 0; index < BASE64_ALPHABET.length; index += 1) {
    table.set(BASE64_ALPHABET.charAt(index), index);
  }

  return table;
}

const utf8Bytes = (value: string): Uint8Array => new TextEncoder().encode(value);

function bodyBytesOf(case_: GpFixtureCase): Uint8Array {
  const base64 = case_.request.bodyBase64;

  if (base64.length === 0) return new Uint8Array(0);
  const table = base64Table();
  let buffer = 0;
  let bits = 0;
  const chunks: number[] = [];

  for (const symbol of base64.replace(/=+$/, '')) {
    const mapped = table.get(symbol);

    if (mapped === undefined) throw new Error(`fixture body is not canonical base64: ${case_.id}`);
    buffer = (buffer << 6) | mapped;
    bits += 6;

    if (bits >= 8) {
      bits -= 8;
      chunks.push((buffer >> bits) & 0xff);
    }
  }

  return new Uint8Array(chunks);
}

function hexToBytes(value: string): Uint8Array | null {
  if (value.length % 2 !== 0) return null;

  if (!/^[0-9a-f]+$/i.test(value)) return null;
  const bytes = new Uint8Array(value.length / 2);

  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }

  return bytes;
}

function canonicalBase64Bytes(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return null;
  const unpadded = value.replace(/=+$/, '');

  if (unpadded.length % 4 === 1) return null;
  const padded = `${unpadded}${'='.repeat((4 - unpadded.length % 4) % 4)}`;

  if (value.includes('=') && value !== padded) return null;
  const table = base64Table();
  let buffer = 0;
  let bits = 0;
  const chunks: number[] = [];

  for (const symbol of unpadded) {
    const mapped = table.get(symbol);

    if (mapped === undefined) return null;
    buffer = (buffer << 6) | mapped;
    bits += 6;

    if (bits >= 8) {
      bits -= 8;
      chunks.push((buffer >> bits) & 0xff);
    }
  }

  const remainder = bits % 8;

  if (remainder !== 0 && (buffer & ((1 << remainder) - 1)) !== 0) return null;

  return new Uint8Array(chunks);
}

function decodeBase64Signature(value: string): Uint8Array | null {
  const bytes = canonicalBase64Bytes(value);

  return bytes !== null && bytes.byteLength === 32 ? bytes : null;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;

  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }

  return true;
}

function hmacBits(keyBytes: Uint8Array, content: Uint8Array): Uint8Array {
  return createHmac('sha256', keyBytes).update(content).digest();
}

// ----------------------------------------------------------------- header probes
function recordHeader(case_: GpFixtureCase, name: string): string {
  const value: unknown = case_.request.headers[name];

  if (isString(value)) return value;

  if (Array.isArray(value) && isStringArray(value)) return value.join(', ');

  return '';
}

function firstSecret(case_: GpFixtureCase): string {
  const secret: unknown = case_.options.secrets[0];

  if (!isString(secret) || secret.length === 0) {
    throw new Error(`fixture case has no usable first secret: ${case_.id}`);
  }

  return secret;
}

// ----------------------------------------------------------------- provider settings guards
interface GrafanaProviderSettings {
  readonly mode?: unknown;
  readonly signatureHeader?: unknown;
  readonly timestampHeader?: unknown;
}

interface PolarProviderSettings {
  readonly secretMode?: unknown;
}

function isGrafanaProviderSettings(value: unknown): value is GrafanaProviderSettings {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;

  return Object.keys(value).every((key) => GRAFANA_ALLOWED_KEYS.has(key));
}

function isPolarProviderSettings(value: unknown): value is PolarProviderSettings {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;

  return Object.keys(value).every((key) => POLAR_ALLOWED_KEYS.has(key));
}

// ----------------------------------------------------------------- fresh model: grafana
const GRAFANA_RESERVED_NAMES = new Set<string>([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'upgrade',
  'trailer',
  'te',
  'proxy-authorization',
  'proxy-authenticate',
  'authorization',
  'cookie',
  'set-cookie',
]);

const GRAFANA_ALLOWED_KEYS = new Set<string>(['mode', 'signatureHeader', 'timestampHeader']);
const GRAFANA_DEFAULT_SIGNATURE = 'x-grafana-alerting-signature';

interface ValidGrafanaConfig {
  readonly mode: 'body' | 'timestamped';
  readonly signature: string;
  readonly timestamp: string;
}

function grafanaConfigModel(case_: GpFixtureCase): ValidGrafanaConfig | null {
  const providerOptions: unknown = case_.options.providerOptions;

  if (!isGrafanaProviderSettings(providerOptions)) return null;

  for (const [key, value] of Object.entries(providerOptions)) {
    if (key !== 'mode' && value === null) return null;
  }

  const mode: unknown = providerOptions.mode;

  if (!isString(mode) || (mode !== 'body' && mode !== 'timestamped')) return null;

  let signature = GRAFANA_DEFAULT_SIGNATURE;

  if (providerOptions.signatureHeader !== undefined) {
    const configured: unknown = providerOptions.signatureHeader;

    if (!isString(configured) || configured.length === 0 || !isHeaderNameToken(configured)) return null;

    if (GRAFANA_RESERVED_NAMES.has(configured.toLowerCase())) return null;

    signature = configured.toLowerCase();
  }

  let timestamp = '';

  if (mode === 'body' && Object.hasOwn(providerOptions, 'timestampHeader')) return null;

  if (mode === 'timestamped') {
    if (providerOptions.timestampHeader === undefined) return null;

    const configured: unknown = providerOptions.timestampHeader;

    if (!isString(configured) || configured.length === 0 || !isHeaderNameToken(configured)) return null;

    if (GRAFANA_RESERVED_NAMES.has(configured.toLowerCase())) return null;

    timestamp = configured.toLowerCase();

    if (timestamp === signature) return null;
  }

  return { mode, signature, timestamp };
}

const CANONICAL_SECONDS = /^(?:0|[1-9]\d*)$/;

function canonicalSeconds(value: string): number | null {
  if (!CANONICAL_SECONDS.test(value)) return null;
  const numeric = Number(value);

  if (!Number.isSafeInteger(numeric) || numeric < 0) return null;

  return numeric;
}

function failedPair(reason: string): OutcomePair {
  return { ok: false, reason };
}

function outcomeSignature(pair: OutcomePair): string {
  if (pair.ok) {
    return JSON.stringify({
      ok: true,
      deliveryId: pair.identity.deliveryId,
      eventId: pair.identity.eventId,
      timestamp: pair.identity.timestamp,
      fields: [...pair.identity.authenticatedFields],
    });
  }

  return JSON.stringify({ ok: false, reason: pair.reason });
}

function tryExpectedPairOf(outcome: FixtureOutcome): OutcomePair | null {
  if (outcome.ok) {
    return outcome.identity === undefined
      ? null
      : { ok: true, identity: outcome.identity };
  }

  return outcome.reason === undefined || outcome.reason.length === 0
    ? null
    : { ok: false, reason: outcome.reason };
}

const DEFAULT_TOLERANCE = 300;

function grafanaOutcome(case_: GpFixtureCase, view: HeaderView): OutcomePair {
  const config = grafanaConfigModel(case_);

  if (config === null) return failedPair('#setup:invalid-options');
  const headers = headerMapOf(case_, view);
  const rawSignature = headers.get(config.signature);

  if (rawSignature === undefined || rawSignature.trim().length === 0) {
    return failedPair('missing-signature');
  }

  const signatureBytes = hexToBytes(rawSignature);

  if (signatureBytes === null || signatureBytes.byteLength !== 32) {
    return failedPair('malformed-signature');
  }

  const body = bodyBytesOf(case_);
  let content: Uint8Array = body;
  let timestampSeconds: number | null = null;

  if (config.mode === 'timestamped') {
    const rawTimestamp = headers.get(config.timestamp);

    if (rawTimestamp === undefined || rawTimestamp.trim().length === 0) {
      return failedPair('missing-timestamp');
    }

    const seconds = canonicalSeconds(rawTimestamp);

    if (seconds === null) {
      return failedPair('malformed-signature');
    }

    timestampSeconds = seconds;
    const stamp = utf8Bytes(`${rawTimestamp}:`);
    content = new Uint8Array([...stamp, ...body]);
  }

  let matched = false;

  for (const secret of case_.options.secrets) {
    if (sameBytes(hmacBits(utf8Bytes(secret), content), signatureBytes)) matched = true;
  }

  if (!matched) return failedPair('invalid-signature');

  if (config.mode === 'timestamped' && timestampSeconds !== null) {
    const tolerance = case_.options.toleranceSeconds ?? DEFAULT_TOLERANCE;
    const age = case_.options.now - timestampSeconds;

    if (age > tolerance) return failedPair('timestamp-expired');

    if (age < -tolerance) return failedPair('timestamp-future');

    return {
      ok: true,
      identity: {
        deliveryId: null,
        eventId: null,
        timestamp: timestampSeconds,
        authenticatedFields: ['timestamp'],
      },
    };
  }

  return {
    ok: true,
    identity: {
      deliveryId: null,
      eventId: null,
      timestamp: null,
      authenticatedFields: [],
    },
  };
}

// ----------------------------------------------------------------- fresh model: polar
const POLAR_NAMES = {
  id: 'webhook-id',
  timestamp: 'webhook-timestamp',
  signature: 'webhook-signature',
};

const POLAR_PREFIX = 'whsec_';
const POLAR_ALLOWED_KEYS = new Set<string>(['secretMode']);
const SCHEME_TOKEN = /^[A-Za-z0-9_-]+$/;

function polarSecretMode(case_: GpFixtureCase): 'current' | 'legacy' | null {
  const providerOptions: unknown = case_.options.providerOptions;

  if (providerOptions === undefined) return 'current';

  if (!isPolarProviderSettings(providerOptions)) return null;

  const secretMode: unknown = providerOptions.secretMode;

  if (secretMode !== undefined) {
    if (!isString(secretMode)) return null;

    if (secretMode !== 'current' && secretMode !== 'legacy') return null;
  }

  return secretMode === 'legacy' ? 'legacy' : 'current';
}

function polarKeyBytes(secret: string, mode: 'current' | 'legacy'): Uint8Array | null {
  if (secret.length === 0) return null;

  if (mode === 'legacy') return utf8Bytes(secret);
  const encoded = secret.startsWith(POLAR_PREFIX) ? secret.slice(POLAR_PREFIX.length) : secret;
  const bytes = canonicalBase64Bytes(encoded);

  if (bytes === null || bytes.byteLength < 24 || bytes.byteLength > 64) return null;

  return bytes;
}

function polarOutcome(case_: GpFixtureCase, view: HeaderView): OutcomePair {
  const mode = polarSecretMode(case_);

  if (mode === null) return failedPair('#setup:invalid-options');
  const headers = headerMapOf(case_, view);
  const rawSignature = headers.get(POLAR_NAMES.signature);

  if (rawSignature === undefined || rawSignature.trim().length === 0) {
    return failedPair('missing-signature');
  }

  const signatures: Uint8Array[] = [];
  let unknownSchemes = 0;

  for (const piece of rawSignature.split(/\s+/)) {
    if (piece.length === 0) continue;
    const separator = piece.indexOf(',');

    if (separator <= 0 || separator === piece.length - 1) {
      return failedPair('malformed-signature');
    }

    const version = piece.slice(0, separator);
    const value = piece.slice(separator + 1);

    if (!SCHEME_TOKEN.test(version) || /[,\s]/.test(value)) {
      return failedPair('malformed-signature');
    }

    if (version === 'v1') {
      const decoded = decodeBase64Signature(value);

      if (decoded === null) return failedPair('malformed-signature');
      signatures.push(decoded);
    } else {
      unknownSchemes += 1;
    }
  }

  if (signatures.length === 0) {
    if (unknownSchemes > 0) return failedPair('unsupported-scheme');

    return failedPair('missing-signature');
  }

  const id = headers.get(POLAR_NAMES.id);

  if (id === undefined || id.length === 0) return failedPair('missing-identity');

  if (id.includes('.') || id.includes(',')) return failedPair('malformed-signature');
  const timestampText = headers.get(POLAR_NAMES.timestamp);

  if (timestampText === undefined || timestampText.length === 0) return failedPair('missing-timestamp');
  const seconds = canonicalSeconds(timestampText);

  if (seconds === null) return failedPair('malformed-signature');

  const decodedKeys: Uint8Array[] = [];

  for (const secret of case_.options.secrets) {
    const key = polarKeyBytes(secret, mode);

    if (key === null) return failedPair('#setup:invalid-secret');
    decodedKeys.push(key);
  }

  const content = new Uint8Array([...utf8Bytes(`${id}.${timestampText}.`), ...bodyBytesOf(case_)]);
  let matched = false;

  for (const key of decodedKeys) {
    for (const signature of signatures) {
      if (sameBytes(hmacBits(key, content), signature)) matched = true;
    }
  }

  if (!matched) return failedPair('invalid-signature');

  const tolerance = case_.options.toleranceSeconds ?? DEFAULT_TOLERANCE;
  const age = case_.options.now - seconds;

  if (age > tolerance) return failedPair('timestamp-expired');

  if (age < -tolerance) return failedPair('timestamp-future');

  return {
    ok: true,
    identity: {
      deliveryId: null,
      eventId: id,
      timestamp: seconds,
      authenticatedFields: ['eventId', 'timestamp'],
    },
  };
}

// ----------------------------------------------------------------- corpus defect detection
function sortedCopy(values: readonly string[]): string[] {
  const copy = [...values];
  copy.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));

  return copy;
}

function gpCaseDefects(case_: GpFixtureCase, provider: 'grafana' | 'polar'): string[] {
  const defects: string[] = [];

  if (case_.provenance.class !== 'local') {
    defects.push(`${case_.id}: Stage A vectors must be provenance class local`);
  }

  const model = provider === 'grafana' ? grafanaOutcome : polarOutcome;
  const recordOutcome: OutcomePair = model(case_, 'record');
  const webOutcome: OutcomePair = model(case_, 'web');
  const expectedRecord = tryExpectedPairOf(case_.expected);
  const expectedWeb = tryExpectedPairOf(case_.webHeadersExpected ?? case_.expected);

  if (case_.webHeadersExpected !== undefined && outcomeSignature(recordOutcome) === outcomeSignature(webOutcome)) {
    defects.push(`${case_.id}: webHeadersExpected declared without a material view difference`);
  }

  if (expectedRecord === null) {
    defects.push(`${case_.id}: expected shape invalid for the pair model`);
  } else if (outcomeSignature(recordOutcome) !== outcomeSignature(expectedRecord)) {
    defects.push(`${case_.id}: record view mismatch (model ${outcomeSignature(recordOutcome)}, expected ${outcomeSignature(expectedRecord)})`);
  }

  if (expectedWeb === null) {
    defects.push(`${case_.id}: webHeadersExpected shape invalid for the pair model`);
  } else if (outcomeSignature(webOutcome) !== outcomeSignature(expectedWeb)) {
    defects.push(`${case_.id}: web view mismatch (model ${outcomeSignature(webOutcome)}, expected ${outcomeSignature(expectedWeb)})`);
  }

  if (!case_.expected.ok) {
    const reason = case_.expected.reason ?? '';
    const vocabulary = provider === 'grafana' ? GRAFANA_REASONS : POLAR_REASONS;

    if (!vocabulary.has(reason)) defects.push(`${case_.id}: reason "${reason}" outside the ${provider} vocabulary`);
  }

  return defects;
}

function gpCorpusDefects(cases: readonly GpFixtureCase[], provider: 'grafana' | 'polar', expectedIds: readonly string[]): string[] {
  const defects: string[] = [];
  const actualIds = sortedCopy(cases.map((entry) => entry.id));
  const expectedSorted = sortedCopy(expectedIds);

  if (JSON.stringify(actualIds) !== JSON.stringify(expectedSorted)) {
    defects.push('inventory mismatch; exact ids do not match the recorded list');
  }

  for (const case_ of cases) defects.push(...gpCaseDefects(case_, provider));

  return defects;
}

// ----------------------------------------------------------------- invalid-options order model
function invalidRowOutcome(row: InvalidOptionsRow): 'invalid-options' | 'invalid-secret' | 'valid' {
  const hasBrokenEntry = row.secrets.some((secret) => !isString(secret) || secret.length === 0);

  if (hasBrokenEntry) return 'invalid-secret';

  const providerOptions: unknown = row.providerOptions;

  if (row.provider === 'grafana') {
    if (!isGrafanaProviderSettings(providerOptions)) return 'invalid-options';

    for (const [key, value] of Object.entries(providerOptions)) {
      if (key !== 'mode' && value === null) return 'invalid-options';
    }

    const mode: unknown = providerOptions.mode;

    if (!isString(mode) || (mode !== 'body' && mode !== 'timestamped')) return 'invalid-options';

    if (mode === 'body' && providerOptions.timestampHeader !== undefined) return 'invalid-options';

    let signature = GRAFANA_DEFAULT_SIGNATURE;

    if (providerOptions.signatureHeader !== undefined) {
      const configured: unknown = providerOptions.signatureHeader;

      if (!isString(configured) || configured.length === 0 || !isHeaderNameToken(configured)) return 'invalid-options';

      if (GRAFANA_RESERVED_NAMES.has(configured.toLowerCase())) return 'invalid-options';

      signature = configured;
    }

    if (mode === 'timestamped') {
      if (providerOptions.timestampHeader === undefined) return 'invalid-options';

      const configured: unknown = providerOptions.timestampHeader;

      if (!isString(configured) || configured.length === 0 || !isHeaderNameToken(configured)) return 'invalid-options';

      if (GRAFANA_RESERVED_NAMES.has(configured.toLowerCase())) return 'invalid-options';

      if (signature.toLowerCase() === configured.toLowerCase()) return 'invalid-options';
    }

    return 'valid';
  }

  let configuredSecretMode: unknown;

  if (providerOptions !== undefined) {
    if (!isPolarProviderSettings(providerOptions)) return 'invalid-options';

    configuredSecretMode = providerOptions.secretMode;

    if (configuredSecretMode !== undefined) {
      if (!isString(configuredSecretMode)) return 'invalid-options';

      if (configuredSecretMode !== 'current' && configuredSecretMode !== 'legacy') return 'invalid-options';
    }
  }

  const mode = configuredSecretMode === 'legacy' ? 'legacy' : 'current';

  for (const secret of row.secrets) {
    if (!isString(secret)) return 'invalid-secret';

    if (polarKeyBytes(secret, mode) === null) return 'invalid-secret';
  }

  return 'valid';
}

function invalidRowDefects(row: InvalidOptionsRow): string[] {
  const defects: string[] = [];
  const computed = invalidRowOutcome(row);

  if (computed !== row.expectedError) {
    defects.push(`${row.id}: order-model outcome ${computed} but recorded ${row.expectedError}`);
  }

  return defects;
}

function invalidCorpusDefects(rows: readonly InvalidOptionsRow[], expectedIds: readonly string[]): string[] {
  const defects: string[] = [];
  const actualIds = sortedCopy(rows.map((entry) => entry.id));
  const expectedSorted = sortedCopy(expectedIds);

  if (JSON.stringify(actualIds) !== JSON.stringify(expectedSorted)) {
    defects.push('inventory mismatch; exact ids do not match the recorded list');
  }

  for (const row of rows) defects.push(...invalidRowDefects(row));

  return defects;
}

// ----------------------------------------------------------------- header gathering (shared)
function headerMapOf(case_: GpFixtureCase, view: HeaderView): Map<string, string> {
  const map = new Map<string, string>();

  for (const [name, value] of Object.entries(case_.request.headers)) {
    const text = isString(value) ? value : value.join(', ');
    map.set(name.toLowerCase(), view === 'web' ? text.trim() : text);
  }

  return map;
}

// ----------------------------------------------------------------- mutation controls
interface MutableGpEnvelope {
  cases: MutableGpCase[];
}

function isMutableGpEnvelope(value: unknown): value is MutableGpEnvelope {
  if (typeof value !== 'object' || value === null || !('cases' in value) || !Array.isArray(value.cases)) return false;

  return value.cases.every(
    (entry: unknown): entry is MutableGpCase =>
      typeof entry === 'object'
      && entry !== null
      && !Array.isArray(entry)
      && 'id' in entry
      && typeof entry.id === 'string'
      && 'request' in entry
      && typeof entry.request === 'object'
      && entry.request !== null
      && 'bodyBase64' in entry.request
      && typeof entry.request.bodyBase64 === 'string'
      && 'headers' in entry.request
      && typeof entry.request.headers === 'object'
      && entry.request.headers !== null
      && 'options' in entry
      && typeof entry.options === 'object'
      && entry.options !== null
      && 'secrets' in entry.options
      && Array.isArray(entry.options.secrets)
      && 'now' in entry.options
      && typeof entry.options.now === 'number'
      && 'expected' in entry
      && typeof entry.expected === 'object'
      && entry.expected !== null
      && 'ok' in entry.expected
      && typeof entry.expected.ok === 'boolean',
  );
}

interface MutableIoEnvelope {
  cases: MutableIoRow[];
}

function isMutableIoEnvelope(value: unknown): value is MutableIoEnvelope {
  if (typeof value !== 'object' || value === null || !('cases' in value) || !Array.isArray(value.cases)) return false;

  return value.cases.every(
    (row: unknown): row is MutableIoRow =>
      typeof row === 'object'
      && row !== null
      && !Array.isArray(row)
      && 'id' in row
      && typeof row.id === 'string'
      && 'provider' in row
      && typeof row.provider === 'string'
      && 'secrets' in row
      && Array.isArray(row.secrets)
      && 'expectedError' in row
      && typeof row.expectedError === 'string',
  );
}

function cloneGpCases(rawText: string): MutableGpCase[] {
  const parsed: unknown = JSON.parse(rawText);

  if (!isMutableGpEnvelope(parsed)) throw new Error('mutation clone lost its array shape');

  return parsed.cases;
}

function cloneIoRows(): MutableIoRow[] {
  const parsed: unknown = JSON.parse(readFileSync(INVALID_OPTIONS_JSON_URL, 'utf8'));

  if (!isMutableIoEnvelope(parsed)) throw new Error('invalid-options mutation clone lost its array shape');

  return parsed.cases;
}

function gpCaseById(cases: MutableGpCase[], id: string): MutableGpCase {
  for (const case_ of cases) {
    if (case_.id === id) return case_;
  }

  throw new Error(`mutation target case missing: ${id}`);
}

function ioRowById(rows: MutableIoRow[], id: string): MutableIoRow {
  for (const row of rows) {
    if (row.id === id) return row;
  }

  throw new Error(`mutation target row missing: ${id}`);
}

const GRAFANA_RAW_TEXT = readFileSync(GRAFANA_JSON_URL, 'utf8');
const POLAR_RAW_TEXT = readFileSync(POLAR_JSON_URL, 'utf8');

function gpDefectsAfterMutation(
  rawText: string,
  provider: 'grafana' | 'polar',
  expectedIds: readonly string[],
  mutate: (cases: MutableGpCase[]) => void,
): string[] {
  const cases = cloneGpCases(rawText);
  mutate(cases);

  const reevaluated: unknown = JSON.parse(JSON.stringify(cases));

  if (!isGpCaseArray(reevaluated)) {
    return ['guard-rejected: mutated fixture file no longer satisfies the owned guard'];
  }

  return gpCorpusDefects(reevaluated, provider, expectedIds);
}

function isIoRowArray(value: unknown): value is readonly InvalidOptionsRow[] {
  if (!Array.isArray(value) || value.length === 0) return false;

  return value.every((row: unknown): row is InvalidOptionsRow => isInvalidOptionsRow(row));
}

function ioDefectsAfterMutation(mutate: (rows: MutableIoRow[]) => void): string[] {
  const rows = cloneIoRows();
  mutate(rows);

  const reevaluated: unknown = JSON.parse(JSON.stringify(rows));

  if (!isIoRowArray(reevaluated)) {
    return ['guard-rejected: mutated invalid-options file no longer satisfies the owned guard'];
  }

  return invalidCorpusDefects(reevaluated, INVALID_OPTIONS_IDS);
}

// ----------------------------------------------------------------- loaded corpora
const GRAFANA_CASES = requireCases(GRAFANA_JSON_URL, 'grafana');
const POLAR_CASES = requireCases(POLAR_JSON_URL, 'polar');
const INVALID_ROWS = requireInvalidRows();

function loadedCaseById(cases: readonly GpFixtureCase[], id: string): GpFixtureCase {
  for (const case_ of cases) {
    if (case_.id === id) return case_;
  }

  throw new Error(`fixture case not found: ${id}`);
}

// ----------------------------------------------------------------- tests
describe('phase-7 corpora load through the owned guards and agree with the fresh model', () => {
  it('grafana corpus is defect-free against the anchor model in both header views', () => {
    expect(gpCorpusDefects(GRAFANA_CASES, 'grafana', GRAFANA_CASE_IDS)).toEqual([]);
  });

  it('polar corpus is defect-free against the anchor model in both header views', () => {
    expect(gpCorpusDefects(POLAR_CASES, 'polar', POLAR_CASE_IDS)).toEqual([]);
  });

  it('invalid-options rows agree with the frozen setup order and the exact inventory', () => {
    expect(invalidCorpusDefects(INVALID_ROWS, INVALID_OPTIONS_IDS)).toEqual([]);
  });
});

describe('independent MAC recomputation from actual headers and exact bytes', () => {
  it('grafana body-mode baseline recomputes to the recorded header by hand-rolled pipeline', () => {
    const case_ = loadedCaseById(GRAFANA_CASES, 'positive-body-default-header');
    const body = bodyBytesOf(case_);
    expect(body.byteLength).toBeGreaterThan(0);

    const recomputed = createHmac('sha256', utf8Bytes(firstSecret(case_)))
      .update(body)
      .digest('hex');

    expect(recordHeader(case_, GRAFANA_DEFAULT_SIGNATURE)).toBe(recomputed);
    expect(grafanaOutcome(case_, 'record')).toEqual(tryExpectedPairOf(case_.expected));
  });

  it('grafana timestamped baseline recomputes as UTF8(timestamp:)+body', () => {
    const case_ = loadedCaseById(GRAFANA_CASES, 'positive-timestamped-default-header');
    const stamp = utf8Bytes(`${recordHeader(case_, 'x-grafana-alerting-timestamp')}:`);
    const body = bodyBytesOf(case_);

    const recomputed = createHmac('sha256', utf8Bytes(firstSecret(case_)))
      .update(new Uint8Array([...stamp, ...body]))
      .digest('hex');

    expect(recordHeader(case_, GRAFANA_DEFAULT_SIGNATURE)).toBe(recomputed);
  });

  it('polar current baseline recomputes from the decoded whsec_ payload (39-byte key)', () => {
    const case_ = loadedCaseById(POLAR_CASES, 'positive-current-baseline');
    const encoded = firstSecret(case_).slice(POLAR_PREFIX.length);
    const key = canonicalBase64Bytes(encoded);

    if (key === null) throw new Error('polar current baseline secret must decode canonically');
    expect(key.byteLength).toBe(39);

    const content = new Uint8Array([
      ...utf8Bytes(`${recordHeader(case_, POLAR_NAMES.id)}.${recordHeader(case_, POLAR_NAMES.timestamp)}.`),
      ...bodyBytesOf(case_),
    ]);

    const recomputed = createHmac('sha256', key)
      .update(content)
      .digest('base64');

    expect(`v1,${recomputed}`).toBe(recordHeader(case_, POLAR_NAMES.signature));
  });

  it('polar legacy baseline recomputes with the complete literal secret', () => {
    const case_ = loadedCaseById(POLAR_CASES, 'positive-legacy-literal-key');

    const content = new Uint8Array([
      ...utf8Bytes(`${recordHeader(case_, POLAR_NAMES.id)}.${recordHeader(case_, POLAR_NAMES.timestamp)}.`),
      ...bodyBytesOf(case_),
    ]);

    const recomputed = createHmac('sha256', utf8Bytes(firstSecret(case_)))
      .update(content)
      .digest('base64');

    expect(`v1,${recomputed}`).toBe(recordHeader(case_, POLAR_NAMES.signature));
  });

  it('every configured key misses the wrong-key digests on both providers', () => {
    const grafanaCase = loadedCaseById(GRAFANA_CASES, 'wrong-key-valid-grammar');
    const grafanaSig = hexToBytes(recordHeader(grafanaCase, GRAFANA_DEFAULT_SIGNATURE));

    if (grafanaSig === null) throw new Error('grafana wrong-key digest must decode');
    const grafanaContent = bodyBytesOf(grafanaCase);

    for (const secret of grafanaCase.options.secrets) {
      expect(sameBytes(hmacBits(utf8Bytes(secret), grafanaContent), grafanaSig)).toBe(false);
    }

    const polarCase = loadedCaseById(POLAR_CASES, 'wrong-key-valid-grammar');
    const polarToken = recordHeader(polarCase, POLAR_NAMES.signature);
    const polarSig = decodeBase64Signature(polarToken.slice('v1,'.length));

    if (polarSig === null) throw new Error('polar wrong-key digest must decode');

    const polarContent = new Uint8Array([
      ...utf8Bytes(`${recordHeader(polarCase, POLAR_NAMES.id)}.${recordHeader(polarCase, POLAR_NAMES.timestamp)}.`),
      ...bodyBytesOf(polarCase),
    ]);

    for (const secret of polarCase.options.secrets) {
      const key = polarKeyBytes(secret, 'current');

      if (key === null) throw new Error('polar wrong-key probe examined an undecodable key');
      expect(sameBytes(hmacBits(key, polarContent), polarSig)).toBe(false);
    }
  });

  it('canonical zero seconds is grammar-valid in grafana but rejected by the freshness window', () => {
    const case_ = loadedCaseById(GRAFANA_CASES, 'timestamped-zero-timestamp-canonical-but-expired');
    const stamp = utf8Bytes(`${recordHeader(case_, 'x-grafana-alerting-timestamp')}:`);
    const body = bodyBytesOf(case_);

    const recomputed = createHmac('sha256', utf8Bytes(firstSecret(case_)))
      .update(new Uint8Array([...stamp, ...body]))
      .digest('hex');

    expect(recordHeader(case_, GRAFANA_DEFAULT_SIGNATURE)).toBe(recomputed);
    expect(grafanaOutcome(case_, 'record')).toEqual({ ok: false, reason: 'timestamp-expired' });
  });
});

describe('identity fields are pinned per layout', () => {
  it('grafana body mode keeps every identity field unauthenticated', () => {
    for (const case_ of GRAFANA_CASES) {
      if (!case_.expected.ok) continue;
      const config = grafanaConfigModel(case_);

      if (config === null || config.mode !== 'body') continue;
      expect(case_.id).toBeDefined();
      expect(case_.expected.identity?.deliveryId).toBe(null);
      expect(case_.expected.identity?.eventId).toBe(null);
      expect(case_.expected.identity?.timestamp).toBe(null);
      expect(case_.expected.identity?.authenticatedFields).toEqual([]);
    }
  });

  it('grafana timestamped mode authenticates only the timestamp', () => {
    for (const case_ of GRAFANA_CASES) {
      if (!case_.expected.ok) continue;
      const config = grafanaConfigModel(case_);

      if (config === null || config.mode !== 'timestamped') continue;
      expect(case_.expected.identity?.deliveryId).toBe(null);
      expect(case_.expected.identity?.eventId).toBe(null);
      expect(case_.expected.identity?.timestamp).toBe(Number(recordHeader(case_, config.timestamp)));
      expect(case_.expected.identity?.authenticatedFields).toEqual(['timestamp']);
    }
  });

  it('polar pins webhook-id and timestamp, never a business id', () => {
    for (const case_ of POLAR_CASES) {
      if (!case_.expected.ok) continue;
      const recordMap = headerMapOf(case_, 'record');
      expect(case_.expected.identity?.deliveryId).toBe(null);
      expect(case_.expected.identity?.eventId).toBe(recordMap.get(POLAR_NAMES.id) ?? '');
      expect(case_.expected.identity?.timestamp).toBe(Number(recordMap.get(POLAR_NAMES.timestamp) ?? ''));
      expect(case_.expected.identity?.authenticatedFields).toEqual(['eventId', 'timestamp']);
    }
  });
});

describe('webHeadersExpected overrides are materially different rows only', () => {
  const OVERRIDE_IDS = new Set([
    'signature-outer-whitespace-is-malformed-record-view',
    'signature-trailing-whitespace-is-headers-trim-accepts',
    'timestamped-timestamp-outer-whitespace-is-headers-trim-accepts',
    'timestamp-outer-whitespace-is-headers-trim-accepts',
  ]);

  it('the four trim-boundary rows record record-malformed/Headers-accepts and nothing else overrides', () => {
    for (const id of ['signature-outer-whitespace-is-malformed-record-view', 'signature-trailing-whitespace-is-headers-trim-accepts', 'timestamped-timestamp-outer-whitespace-is-headers-trim-accepts']) {
      const grafanaCase = loadedCaseById(GRAFANA_CASES, id);
      expect(grafanaCase.expected.ok).toBe(false);
      expect(grafanaCase.webHeadersExpected?.ok).toBe(true);
    }

    const polarCase = loadedCaseById(POLAR_CASES, 'timestamp-outer-whitespace-is-headers-trim-accepts');
    expect(polarCase.expected.ok).toBe(false);
    expect(polarCase.webHeadersExpected?.ok).toBe(true);

    for (const case_ of [...GRAFANA_CASES, ...POLAR_CASES]) {
      if (case_.webHeadersExpected !== undefined && !OVERRIDE_IDS.has(case_.id)) {
        throw new Error(`undeclared webHeadersExpected row: ${case_.id}`);
      }

      if (case_.webHeadersExpected === undefined && OVERRIDE_IDS.has(case_.id)) {
        throw new Error(`declared override row is missing its field: ${case_.id}`);
      }
    }
  });
});

describe('wrong layout never downgrades and unselected headers never rescue', () => {
  it('timestamped config rejects a body-layout digest and body config rejects a timestamped-layout digest', () => {
    const downgraded = loadedCaseById(GRAFANA_CASES, 'timestamped-body-layout-signature-no-downgrade');
    expect(grafanaOutcome(downgraded, 'record')).toEqual({ ok: false, reason: 'invalid-signature' });
    const upgraded = loadedCaseById(GRAFANA_CASES, 'body-mode-timestamped-layout-signature-no-upgrade');
    expect(grafanaOutcome(upgraded, 'record')).toEqual({ ok: false, reason: 'invalid-signature' });
  });

  it('missing custom signature header stays missing even when the default name carries a valid digest', () => {
    const case_ = loadedCaseById(GRAFANA_CASES, 'timestamped-custom-header-absent-no-default-fallback');
    expect(grafanaOutcome(case_, 'record')).toEqual({ ok: false, reason: 'missing-signature' });
    expect(recordHeader(case_, GRAFANA_DEFAULT_SIGNATURE).length).toBeGreaterThan(0);
    expect(recordHeader(case_, 'x-acme-signature')).toBe('');
  });

  it('only the configured canonical header participates for polar', () => {
    const rescued = loadedCaseById(POLAR_CASES, 'svix-alias-does-not-rescue-canonical-mismatch');
    expect(polarOutcome(rescued, 'record')).toEqual({ ok: false, reason: 'invalid-signature' });
    const aliased = loadedCaseById(POLAR_CASES, 'svix-family-cannot-repair-canonical-fields');
    expect(polarOutcome(aliased, 'record')).toEqual({ ok: false, reason: 'missing-signature' });
  });

  it('polar cross-era secrets never rescue the other mode', () => {
    const underCurrent = loadedCaseById(POLAR_CASES, 'legacy-signed-is-not-rescued-under-current');
    expect(polarOutcome(underCurrent, 'record')).toEqual({ ok: false, reason: 'invalid-signature' });
    const underLegacy = loadedCaseById(POLAR_CASES, 'current-signed-is-not-rescued-under-legacy-mode');
    expect(polarOutcome(underLegacy, 'record')).toEqual({ ok: false, reason: 'invalid-signature' });
  });
});

describe('mutation controls: the checker notices each changed attribute', () => {
  it('renaming a case id is detected (inventory control)', () => {
    const grafana = gpDefectsAfterMutation(GRAFANA_RAW_TEXT, 'grafana', GRAFANA_CASE_IDS, (cases) => {
      gpCaseById(cases, 'positive-body-default-header').id = 'positive-body-reheader';
    });

    expect(grafana.filter((defect) => defect.startsWith('inventory mismatch')).length).toBeGreaterThan(0);

    const polar = gpDefectsAfterMutation(POLAR_RAW_TEXT, 'polar', POLAR_CASE_IDS, (cases) => {
      gpCaseById(cases, 'positive-current-baseline').id = 'positive-current-baseline-mutated';
    });

    expect(polar.filter((defect) => defect.startsWith('inventory mismatch')).length).toBeGreaterThan(0);
  });

  it('removing a case is detected (inventory control)', () => {
    const grafana = gpDefectsAfterMutation(GRAFANA_RAW_TEXT, 'grafana', GRAFANA_CASE_IDS, (cases) => {
      const at = cases.findIndex((entry) => entry.id === 'blank-signature-is-missing');

      if (at >= 0) cases.splice(at, 1);
    });

    expect(grafana.filter((defect) => defect.startsWith('inventory mismatch')).length).toBeGreaterThan(0);

    const polar = gpDefectsAfterMutation(POLAR_RAW_TEXT, 'polar', POLAR_CASE_IDS, (cases) => {
      const at = cases.findIndex((entry) => entry.id === 'malformed-token-fails-closed-despite-valid');

      if (at >= 0) cases.splice(at, 1);
    });

    expect(polar.filter((defect) => defect.startsWith('inventory mismatch')).length).toBeGreaterThan(0);
  });

  it('flipping grafana body mode to timestamped is detected as invalid configuration', () => {
    const defects = gpDefectsAfterMutation(GRAFANA_RAW_TEXT, 'grafana', GRAFANA_CASE_IDS, (cases) => {
      gpCaseById(cases, 'positive-body-default-header').options.providerOptions = { mode: 'timestamped' };
    });

    expect(defects.length).toBeGreaterThan(0);
    expect(defects.some((defect) => defect.startsWith('positive-body-default-header'))).toBe(true);
  });

  it('renaming the configured custom signature header is detected', () => {
    const defects = gpDefectsAfterMutation(GRAFANA_RAW_TEXT, 'grafana', GRAFANA_CASE_IDS, (cases) => {
      gpCaseById(cases, 'positive-custom-header-and-decoy-default').options.providerOptions = {
        mode: 'body',
        signatureHeader: 'x-acme-other',
      };
    });

    expect(defects.some((defect) => defect.startsWith('positive-custom-header-and-decoy-default'))).toBe(true);
  });

  it('flipping the polar key recipe from current to legacy is detected', () => {
    const defects = gpDefectsAfterMutation(POLAR_RAW_TEXT, 'polar', POLAR_CASE_IDS, (cases) => {
      gpCaseById(cases, 'positive-current-baseline').options.providerOptions = { secretMode: 'legacy' };
    });

    expect(defects.some((defect) => defect.startsWith('positive-current-baseline'))).toBe(true);
  });

  it('flipping one signature hex character is detected', () => {
    const defects = gpDefectsAfterMutation(GRAFANA_RAW_TEXT, 'grafana', GRAFANA_CASE_IDS, (cases) => {
      const case_ = gpCaseById(cases, 'positive-body-default-header');
      const existing: unknown = case_.request.headers[GRAFANA_DEFAULT_SIGNATURE];
      const text = isString(existing) ? existing : '';
      case_.request.headers[GRAFANA_DEFAULT_SIGNATURE] = text.replace(/^./, text.startsWith('d') ? 'e' : 'd');
    });

    expect(defects.some((defect) => defect.startsWith('positive-body-default-header'))).toBe(true);
  });

  it('flipping one body byte is detected', () => {
    const defects = gpDefectsAfterMutation(GRAFANA_RAW_TEXT, 'grafana', GRAFANA_CASE_IDS, (cases) => {
      const case_ = gpCaseById(cases, 'positive-body-default-header');
      case_.request.bodyBase64 = `Q${case_.request.bodyBase64.slice(1)}`;
    });

    expect(defects.some((defect) => defect.startsWith('positive-body-default-header'))).toBe(true);
  });

  it('mutating the webhook-id header value is detected (phase-6 review analog)', () => {
    const defects = gpDefectsAfterMutation(POLAR_RAW_TEXT, 'polar', POLAR_CASE_IDS, (cases) => {
      gpCaseById(cases, 'positive-current-baseline').request.headers['webhook-id'] = 'msg.mutated';
    });

    expect(defects.some((defect) => defect.startsWith('positive-current-baseline'))).toBe(true);
  });

  it('changing a secret without re-signing is detected', () => {
    const defects = gpDefectsAfterMutation(POLAR_RAW_TEXT, 'polar', POLAR_CASE_IDS, (cases) => {
      gpCaseById(cases, 'positive-current-baseline').options.secrets = ['whsec_0123456789012345678901234567890123456789'];
    });

    expect(defects.some((defect) => defect.startsWith('positive-current-baseline'))).toBe(true);
  });

  it('flipping expected.ok on a positive result is detected', () => {
    const defects = gpDefectsAfterMutation(GRAFANA_RAW_TEXT, 'grafana', GRAFANA_CASE_IDS, (cases) => {
      gpCaseById(cases, 'positive-body-default-header').expected.ok = false;
    });

    expect(defects.some((defect) => defect.startsWith('positive-body-default-header'))).toBe(true);
  });

  it('swapping a failure reason is detected', () => {
    const defects = gpDefectsAfterMutation(POLAR_RAW_TEXT, 'polar', POLAR_CASE_IDS, (cases) => {
      gpCaseById(cases, 'wrong-key-valid-grammar').expected.reason = 'timestamp-expired';
    });

    expect(defects.some((defect) => defect.includes('record view mismatch'))).toBe(true);
  });

  it('removing a material webHeadersExpected override is detected', () => {
    const defects = gpDefectsAfterMutation(GRAFANA_RAW_TEXT, 'grafana', GRAFANA_CASE_IDS, (cases) => {
      delete gpCaseById(cases, 'signature-outer-whitespace-is-malformed-record-view').webHeadersExpected;
    });

    expect(defects.some((defect) => defect.startsWith('signature-outer-whitespace-is-malformed-record-view'))).toBe(true);
  });

  it('renaming or removing an invalid-options row is detected (inventory control)', () => {
    const renamed = ioDefectsAfterMutation((rows) => {
      ioRowById(rows, 'grafana-provider-options-absent-is-invalid').id = 'grafana-provider-options-mutated';
    });

    expect(renamed.filter((defect) => defect.startsWith('inventory mismatch')).length).toBeGreaterThan(0);

    const removed = ioDefectsAfterMutation((rows) => {
      const at = rows.findIndex((entry) => entry.id === 'polar-mixed-era-list-decodes-per-mode');

      if (at >= 0) rows.splice(at, 1);
    });

    expect(removed.filter((defect) => defect.startsWith('inventory mismatch')).length).toBeGreaterThan(0);
  });

  it('swapping an invalid-options expectedError is detected', () => {
    const defects = ioDefectsAfterMutation((rows) => {
      ioRowById(rows, 'grafana-secret-entry-beats-invalid-mode').expectedError = 'invalid-options';
    });

    expect(defects.some((defect) => defect.startsWith('grafana-secret-entry-beats-invalid-mode'))).toBe(true);
  });
});

describe('owned guard negative controls', () => {
  it('rejects header values carrying CR, LF or NUL', () => {
    const template = loadedCaseById(GRAFANA_CASES, 'positive-body-default-header');

    const brokenText = JSON.stringify({
      ...template,
      request: {
        bodyBase64: template.request.bodyBase64,
        headers: { 'x-grafana-alerting-signature': 'a\nb' },
      },
    });

    const broken: unknown = JSON.parse(brokenText);

    expect(isGpFixtureCase(broken)).toBe(false);
  });

  it('rejects a providerOptions value that is neither object nor omitted', () => {
    const template = loadedCaseById(POLAR_CASES, 'positive-current-baseline');

    const brokenText = JSON.stringify({
      ...template,
      options: { ...template.options, providerOptions: 'legacy' },
    });

    const broken: unknown = JSON.parse(brokenText);

    expect(isGpFixtureCase(broken)).toBe(false);
  });

  it('rejects a non-boolean expected ok flag', () => {
    const template = loadedCaseById(GRAFANA_CASES, 'positive-body-default-header');

    const brokenText = JSON.stringify({
      ...template,
      expected: { ok: 'yes' },
    });

    const broken: unknown = JSON.parse(brokenText);

    expect(isGpFixtureCase(broken)).toBe(false);
  });
});


describe('coordinator configuration-model regressions', () => {
  it('rejects a timestamp header added to a body-mode positive fixture', () => {
    const original = loadedCaseById(GRAFANA_CASES, 'positive-body-default-header');

    const changed = {
      ...original,
      options: { ...original.options, providerOptions: { mode: 'body', timestampHeader: 'x-unexpected-timestamp' } },
    };

    expect(gpCaseDefects(changed, 'grafana').length).toBeGreaterThan(0);
  });

  it('rejects a timestamp header colliding with the omitted default signature header', () => {
    const outcome = invalidRowOutcome({
      id: 'coordinator-default-header-collision',
      provider: 'grafana',
      providerOptions: { mode: 'timestamped', timestampHeader: 'X-Grafana-Alerting-Signature' },
      secrets: ['synthetic coordinator secret'],
      expectedError: 'invalid-options',
    });

    expect(outcome).toBe('invalid-options');
  });
});
