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
  };
  readonly expected: {
    readonly ok: boolean;
    readonly reason?: string;
    readonly identity?: {
      readonly deliveryId: string | number | null;
      readonly eventId: string | number | null;
      readonly timestamp: number | null;
      readonly authenticatedFields: readonly string[];
    };
  };
  readonly notes?: string;
}

const PROVIDER_FILES: Record<Provider, string> = {
  stripe: '../fixtures/stripe.json',
  github: '../fixtures/github.json',
  shopify: '../fixtures/shopify.json',
  'standard-webhooks': '../fixtures/standard-webhooks.json',
};

export function loadFixture(provider: Provider): readonly FixtureCase[] {
  const raw = readFileSync(new URL(PROVIDER_FILES[provider], import.meta.url), 'utf8');
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object' || !Array.isArray((parsed as { cases: unknown }).cases)) {
    throw new Error(`Fixture file for ${provider} is malformed`);
  }
  return (parsed as { cases: FixtureCase[] }).cases;
}

export function fixtureBytes(case_: FixtureCase): Uint8Array {
  if (case_.request.bodyBase64.length === 0) return new Uint8Array(0);
  const binary = atob(case_.request.bodyBase64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export function fixtureOptions(provider: Provider, case_: FixtureCase): VerifyOptions {
  return {
    provider,
    secrets: [...case_.options.secrets],
    ...(case_.options.toleranceSeconds === undefined ? {} : { toleranceSeconds: case_.options.toleranceSeconds }),
    ...(case_.options.maxBodyBytes === undefined ? {} : { maxBodyBytes: case_.options.maxBodyBytes }),
    now: () => case_.options.now,
  };
}

const UNSIGNED_OR_NULL = 'unsigned-or-null';

export function isUnsignedOrNull(value: string | number | null): boolean {
  return value === UNSIGNED_OR_NULL;
}

/** The three header representations the contract declares equivalent. */
export function representationsOf(
  case_: FixtureCase,
): readonly HeaderInput[] {
  const headers = case_.request.headers;
  const entries: readonly (readonly [string, string])[] = Object.entries(headers)
    .flatMap(([name, value]) => (typeof value === 'object' && value !== null
      ? value.map((item): readonly [string, string] => [name, item])
      : [[name, value] as const]));
  return [
    headers as HeaderInput,
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
    return typeof value === 'object' && value !== null ? value.join(', ') : value;
  }
  return undefined;
}

export { UNSIGNED_OR_NULL };
