import { readFileSync } from 'node:fs';
import type { HeaderInput, Provider, VerifyOptions } from '../../src/types.js';

/**
 * Test-only fixture machinery. Nothing here is shared with `src/`; Base64 and
 * request building are independent of the implementation under test (the task
 * permits independent test-only signing/decoding).
 */

export interface FixtureProvenance {
  readonly class: 'reference' | 'local';
  readonly source: string;
  readonly commit?: string;
  readonly fetched?: string;
}

export interface FixtureExpected {
  readonly ok: boolean;
  readonly reason?: string;
  readonly identity?: {
    readonly deliveryId: string | number | null;
    readonly eventId: string | number | null;
    readonly timestamp: number | null;
    readonly authenticatedFields: readonly string[];
  };
}

/** Body-mode Grafana options; the timestamped header layout is forbidden entirely. */
export interface GrafanaBodyProviderOptions {
  readonly mode: 'body';
  readonly signatureHeader?: string;
  readonly timestampHeader?: never;
}

/** Timestamped-mode Grafana options; the timestamp header is required configuration. */
export interface GrafanaTimestampedProviderOptions {
  readonly mode: 'timestamped';
  readonly signatureHeader?: string;
  readonly timestampHeader: string;
}

/** Test-side mirror of the contract's public GrafanaOptions; Codex owns the public type. */
export type GrafanaProviderOptions = GrafanaBodyProviderOptions | GrafanaTimestampedProviderOptions;

/** Test-side mirror of the contract's public PolarOptions; Codex owns the public type. */
export interface PolarProviderOptions {
  readonly secretMode?: 'current' | 'legacy';
}

export type FixtureProviderOptions = GrafanaProviderOptions | PolarProviderOptions;

/** The 16 registered providers plus the two prepared Stage B providers. */
export type FixtureProvider = Provider | 'grafana' | 'polar';

export interface FixtureCase {
  readonly id: string;
  readonly provenance: FixtureProvenance;
  readonly request: {
    readonly bodyBase64: string;
    readonly headers: Readonly<Record<string, string | readonly string[]>>;
  };
  readonly options: {
    readonly secrets: readonly string[];
    readonly toleranceSeconds?: number;
    readonly now: number;
    readonly maxBodyBytes?: number;
    /** Typed provider configuration for Grafana/Polar; validated on load. */
    readonly providerOptions?: FixtureProviderOptions;
  };
  readonly expected: FixtureExpected;
  /** Explicit outcome after WHATWG Headers trims outer whitespace. */
  readonly webHeadersExpected?: FixtureExpected;
  readonly notes?: string;
}

/** Legacy fixture files keep exact mappings; grafana/polar map explicitly to their Stage A corpora. */
const PROVIDER_FILES: Partial<Record<FixtureProvider, string>> = {
  stripe: '../fixtures/stripe.json',
  github: '../fixtures/github.json',
  shopify: '../fixtures/shopify.json',
  'standard-webhooks': '../fixtures/standard-webhooks.json',
  // Configured-provider and Linear corpora are mapped explicitly; no inferred fallback.
  grafana: '../fixtures/grafana.json',
  polar: '../fixtures/polar.json',
  linear: '../fixtures/linear.json',
};

function isString(value: unknown): value is string { return typeof value === 'string'; }

function isIdentityValue(value: unknown): value is string | number | null { return value === null || typeof value === 'string' || typeof value === 'number'; }

function isHeaderValue(value: unknown): value is string | readonly string[] { return isString(value) || (Array.isArray(value) && value.every(isString)); }

function isNonEmptyToken(value: unknown): value is string { return isString(value) && value.length > 0; }

function isFixtureExpected(value: unknown): value is FixtureExpected {
  if (typeof value !== 'object' || value === null || !('ok' in value) || typeof value.ok !== 'boolean') return false;

  if ('reason' in value && typeof value.reason !== 'string') return false;

  if ('identity' in value) {
    const identity = value.identity;

    if (typeof identity !== 'object' || identity === null) return false;

    if (!('deliveryId' in identity) || !isIdentityValue(identity.deliveryId)) return false;

    if (!('eventId' in identity) || !isIdentityValue(identity.eventId)) return false;

    if (!('timestamp' in identity) || (identity.timestamp !== null && typeof identity.timestamp !== 'number')) return false;

    if (!('authenticatedFields' in identity) || !Array.isArray(identity.authenticatedFields) || !identity.authenticatedFields.every(isString)) return false;
  }

  return true;
}

export function isGrafanaProviderOptions(value: unknown): value is GrafanaProviderOptions {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || !('mode' in value)) return false;

  if (value.mode !== 'body' && value.mode !== 'timestamped') return false;

  if ('signatureHeader' in value && !isNonEmptyToken(value.signatureHeader)) return false;

  if (value.mode === 'body') {
    return !('timestampHeader' in value) && Object.keys(value).every((key) => key === 'mode' || key === 'signatureHeader');
  }

  return 'timestampHeader' in value
    && isNonEmptyToken(value.timestampHeader)
    && Object.keys(value).every((key) => key === 'mode' || key === 'signatureHeader' || key === 'timestampHeader');
}

export function isPolarProviderOptions(value: unknown): value is PolarProviderOptions {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;

  if ('secretMode' in value && value.secretMode !== 'current' && value.secretMode !== 'legacy') return false;

  return Object.keys(value).every((key) => key === 'secretMode');
}

export function isFixtureProviderOptions(value: unknown): value is FixtureProviderOptions {
  return isGrafanaProviderOptions(value) || isPolarProviderOptions(value);
}

interface FixtureFile { readonly cases: readonly FixtureCase[] }

export function isFixtureFile(value: unknown): value is FixtureFile {
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

    if ('maxBodyBytes' in entry.options && typeof entry.options.maxBodyBytes !== 'number') return false;

    if ('providerOptions' in entry.options && !isFixtureProviderOptions(entry.options.providerOptions)) return false;

    if (!('expected' in entry) || !isFixtureExpected(entry.expected)) return false;

    if ('webHeadersExpected' in entry && !isFixtureExpected(entry.webHeadersExpected)) return false;

    if (!('provenance' in entry) || typeof entry.provenance !== 'object' || entry.provenance === null) return false;

    if (!('class' in entry.provenance) || (entry.provenance.class !== 'reference' && entry.provenance.class !== 'local')) return false;

    if ('commit' in entry.provenance && typeof entry.provenance.commit !== 'string') return false;

    if ('fetched' in entry.provenance && typeof entry.provenance.fetched !== 'string') return false;

    if ('notes' in entry && typeof entry.notes !== 'string') return false;

    return 'source' in entry.provenance && typeof entry.provenance.source === 'string';
  });
}

/**
 * Provider-config correlation after typed validation: grafana rows must carry a
 * grafana-shaped {mode} configuration, polar rows may omit or carry the polar
 * shape, and legacy rows must never carry providerOptions.
 */
function hasProviderOptionsFor(provider: FixtureProvider, case_: FixtureCase): boolean {
  const config = case_.options.providerOptions;

  if (config === undefined) return provider !== 'grafana';

  if (provider === 'grafana') return 'mode' in config;

  return provider === 'polar' && !('mode' in config);
}

export function loadFixture(provider: FixtureProvider): readonly FixtureCase[] {
  const fixtureFile = PROVIDER_FILES[provider];

  if (fixtureFile === undefined) {
    throw new Error(`No fixture file is assigned to provider ${provider}`);
  }

  const raw = readFileSync(new URL(fixtureFile, import.meta.url), 'utf8');
  const parsed: unknown = JSON.parse(raw);

  if (!isFixtureFile(parsed)) throw new Error(`Fixture file for ${provider} is malformed`);

  const mismatched = parsed.cases.find((case_) => !hasProviderOptionsFor(provider, case_));

  if (mismatched !== undefined) {
    throw new Error(`Fixture file for ${provider} has invalid providerOptions for its provider contract (case ${mismatched.id})`);
  }

  return parsed.cases;
}

export function fixtureBytes(case_: FixtureCase): Uint8Array {
  if (case_.request.bodyBase64.length === 0) return new Uint8Array(0);
  const binary = atob(case_.request.bodyBase64);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);

  return bytes;
}

/** Correlated literal branches; no mapped dictionary and no Provider cast. */
export function fixtureOptions(provider: FixtureProvider, case_: FixtureCase): VerifyOptions {
  if (!hasProviderOptionsFor(provider, case_)) throw new Error('Invalid fixture providerOptions for selected provider');

  const secrets = [...case_.options.secrets];
  const now = (): number => case_.options.now;
  const toleranceSeconds = case_.options.toleranceSeconds;
  const maxBodyBytes = case_.options.maxBodyBytes;

  if (provider === 'grafana') {
    const config = case_.options.providerOptions;

    if (config === undefined || !('mode' in config)) {
      throw new Error(`Grafana fixture case ${case_.id} has no typed providerOptions`);
    }

    return {
      provider,
      secrets,
      now,
      providerOptions: config,
      ...(toleranceSeconds !== undefined && { toleranceSeconds }),
      ...(maxBodyBytes !== undefined && { maxBodyBytes }),
    };
  }

  if (provider === 'polar') {
    const config = case_.options.providerOptions;

    if (config !== undefined && 'mode' in config) {
      throw new Error(`Polar fixture case ${case_.id} carries a non-polar providerOptions shape`);
    }

    return {
      provider,
      secrets,
      now,
      ...(config !== undefined && { providerOptions: config }),
      ...(toleranceSeconds !== undefined && { toleranceSeconds }),
      ...(maxBodyBytes !== undefined && { maxBodyBytes }),
    };
  }

  return {
    provider,
    secrets,
    now,
    ...(toleranceSeconds !== undefined && { toleranceSeconds }),
    ...(maxBodyBytes !== undefined && { maxBodyBytes }),
  };
}

const UNSIGNED_OR_NULL = 'unsigned-or-null';

export function isUnsignedOrNull(value: string | number | null): boolean {
  return value === UNSIGNED_OR_NULL;
}

function isHeaderList(value: string | readonly string[]): value is readonly string[] { return Array.isArray(value); }

/** The three header representations the contract declares equivalent. */
export function representationsOf(
  case_: FixtureCase,
): readonly HeaderInput[] {
  const headers = case_.request.headers;

  const entries: readonly (readonly [string, string])[] = Object.entries(headers)
    .flatMap(([name, value]) => (isHeaderList(value)
      ? value.map((item): readonly [string, string] => [name, item])
      : [[name, value] as const]));

  return [
    headers,
    entries,
    entries.reduce((acc, [name, value]) => {
      acc.append(name, value);

      return acc;
    }, new Headers()),
  ];
}

/** Header value lookup used to validate unsigned identity metadata (case-insensitive). */
export function combinedHeader(case_: FixtureCase, name: string): string | undefined {
  const wanted = name.toLowerCase();

  for (const [key, value] of Object.entries(case_.request.headers)) {
    if (key.toLowerCase() !== wanted) continue;

    return isHeaderList(value) ? value.join(', ') : value;
  }

  return undefined;
}

export { UNSIGNED_OR_NULL };
