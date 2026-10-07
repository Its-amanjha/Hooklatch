import { createHmac } from 'node:crypto';
import { normalizeHeaders } from '../../src/internal/headers.js';
import type {
  NormalizedHeaders,
  ParsedSignature,
  ParseResult,
} from '../../src/internal/provider.js';
import type { FailureDetails } from '../../src/types.js';

export const headerMap = (
  input: Record<string, string | readonly string[]>,
): NormalizedHeaders => normalizeHeaders(input);

export function expectOk(result: ParseResult): ParsedSignature {
  if (!result.ok) {
    throw new Error(`Expected success but got ${result.reason}: ${result.message}`);
  }
  return result;
}

export function expectFailure(result: ParseResult): FailureDetails {
  if (result.ok) throw new Error('Expected a verification failure but parsing succeeded.');
  return result;
}

/** Independent, test-only HMAC signing used to build and cross-check anchors. */
export function hmacHex(
  key: string | Uint8Array,
  message: Uint8Array,
  algorithm: 'sha1' | 'sha256' = 'sha256',
): string {
  return createHmac(algorithm, key).update(message).digest('hex');
}

export function hmacBase64(key: string | Uint8Array, message: Uint8Array): string {
  return createHmac('sha256', key).update(message).digest('base64');
}

export function base64Of(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

export function ternErrorCode(run: () => unknown): string | undefined {
  try {
    run();
    return undefined;
  } catch (error) {
    return (error as { code?: string }).code;
  }
}
