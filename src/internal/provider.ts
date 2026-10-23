import type { EventIdentity, FailureDetails, Provider } from '../types.js';

export type NormalizedHeaders = ReadonlyMap<string, string>;

export interface ParsedSignature {
  readonly ok: true;
  readonly signatures: readonly Uint8Array[];
  readonly signedContent: Uint8Array;
  /** Untrusted until core signature verification succeeds. */
  readonly identity: EventIdentity;
}

export type ParseResult = ParsedSignature | FailureDetails;

export type HmacPolicy =
  | { readonly kind: 'hmac'; readonly hash: 'SHA-1'; readonly signatureBytes: 20 }
  | { readonly kind: 'hmac'; readonly hash: 'SHA-256'; readonly signatureBytes: 32 };

export type FalParseResult = FailureDetails | (ParsedSignature & { readonly recipient: string });

export interface FalProviderDescriptor {
  readonly provider: 'fal';
  readonly crypto: { readonly kind: 'ed25519'; readonly signatureBytes: 64 };
  parse(headers: NormalizedHeaders, rawBody: Uint8Array): Promise<FalParseResult>;
}

export type AnyProviderDescriptor = ProviderDescriptor | FalProviderDescriptor;

export interface ProviderDescriptor {
  readonly provider: Exclude<Provider, 'fal'>;
  readonly crypto?: HmacPolicy;
  /** Throw HooklatchError('invalid-secret') on invalid configuration. */
  decodeSecret(secret: string): Uint8Array;
  /** Parse and format only. Freshness and HMAC checks belong to core. */
  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult;
}
