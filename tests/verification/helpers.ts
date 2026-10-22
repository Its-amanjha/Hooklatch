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
    /** Typed provider configuration for Grafana/Polar (Phase 7). */
    readonly providerOptions?: unknown;
  };
  readonly expected: FixtureExpected;
  /** Explicit outcome after WHATWG Headers trims outer whitespace. */
  readonly webHeadersExpected?: FixtureExpected;
  readonly notes?: string;
}

/** Legacy fixture files only. New provider presets must map explicitly or not at all. */
const PROVIDER_FILES: Partial<Record<Provider, string>> = {
  stripe: '../fixtures/stripe.json',
  github: '../fixtures/github.json',
  shopify: '../fixtures/shopify.json',
  'standard-webhooks': '../fixtures/standard-webhooks.json',
  // Phase 7 explicit mappings. These keys are not yet members of Provider (base
  // has 16 providers); the entries are RED at this base and become valid once
  // Codex adds 'grafana' and 'polar' to the Provider union in Stage B.
  grafana: '../fixtures/grafana.json',
  polar: '../fixtures/polar.json',
};

function isString(value: unknown): value is string { return typeof value === 'string'; }

function isIdentityValue(value: unknown): value is string | number | null { return value === null || typeof value === 'string' || typeof value === 'number'; }

function isHeaderValue(value: unknown): value is string | readonly string[] { return isString(value) || (Array.isArray(value) && value.every(isString)); }

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

    if ('providerOptions' in entry.options) {
      const providerOptions: unknown = entry.options.providerOptions;

      if (typeof providerOptions !== 'object' || providerOptions === null || Array.isArray(providerOptions)) return false;
    }

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

export function loadFixture(provider: Provider): readonly FixtureCase[] {
  const fixtureFile = PROVIDER_FILES[provider];

  if (fixtureFile === undefined) {
    throw new Error(`No fixture file is assigned to provider ${provider}`);
  }

  const raw = readFileSync(new URL(fixtureFile, import.meta.url), 'utf8');
  const parsed: unknown = JSON.parse(raw);

  if (!isFixtureFile(parsed)) throw new Error(`Fixture file for ${provider} is malformed`);

  return parsed.cases;
}

export function fixtureBytes(case_: FixtureCase): Uint8Array {
  if (case_.request.bodyBase64.length === 0) return new Uint8Array(0);
  const binary = atob(case_.request.bodyBase64);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);

  return bytes;
}

type MutableVerifyOptions = { -readonly [Key in keyof VerifyOptions]: VerifyOptions[Key] };

type MutableVerifyOptionsWithProviderOptions = MutableVerifyOptions & { providerOptions?: unknown };

export function fixtureOptions(provider: Provider, case_: FixtureCase): VerifyOptions {
  const options: MutableVerifyOptions = {
    provider,
    secrets: [...case_.options.secrets],
    now: () => case_.options.now,
  };

  if (case_.options.toleranceSeconds !== undefined) options.toleranceSeconds = case_.options.toleranceSeconds;

  if (case_.options.maxBodyBytes !== undefined) options.maxBodyBytes = case_.options.maxBodyBytes;

  // Preserve typed providerOptions when present. VerifyOptions does not yet carry
  // providerOptions at this base (Grafana/Polar are unregistered), so the
  // assignment is a type error here. SAFETY: this field is forwarded verbatim to
  // the future VerifyOptions union member; no transformation or defaulting.
  if (case_.options.providerOptions !== undefined) {
    // SAFETY: VerifyOptions has no providerOptions field at this base; the
    // named mutable type forwards the validated fixture value to the future
    // union member without discarding the known option evidence.
    (options as MutableVerifyOptionsWithProviderOptions).providerOptions = case_.options.providerOptions;
  }

  return options;
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
