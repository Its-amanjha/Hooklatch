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
export interface ProviderDescriptor {
  readonly provider: Provider;
  /** Throw TernError('invalid-secret') on invalid configuration. */
  decodeSecret(secret: string): Uint8Array;
  /** Parse and format only. Freshness and HMAC checks belong to core. */
  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult;
}
