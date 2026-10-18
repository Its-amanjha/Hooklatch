import { HooklatchError } from '../errors.js';
import { decodeBase64, decodeHex, utf8 } from '../internal/bytes.js';
import type { FailureDetails, VerificationFailureReason } from '../types.js';

/** HMAC-SHA256 signatures are always exactly 32 bytes. */
export const SIGNATURE_BYTES = 32;

/** Scheme/key tokens accepted in provider signature headers (e.g. `v1`, `sha256`). */
const TOKEN = /^[A-Za-z0-9_-]+$/;

export function failure(
  reason: VerificationFailureReason,
  message: string,
): FailureDetails {
  return { ok: false, reason, message };
}

export function isSchemeToken(value: string): boolean {
  return TOKEN.test(value);
}

/** Canonical decimal integer: `0`, or a nonzero digit followed by digits. */
export function isCanonicalTimestamp(value: string): boolean {
  if (!/^(?:0|[1-9]\d*)$/.test(value)) return false;
  const numeric = Number(value);

  return Number.isSafeInteger(numeric) && numeric >= 0;
}

/** Hex signature of exactly 32 bytes; accepts either hex case. */
export function decodeHexSignature(value: string): Uint8Array | null {
  const bytes = decodeHex(value);

  return bytes !== null && bytes.byteLength === SIGNATURE_BYTES ? bytes : null;
}

/** Canonical Base64 signature of exactly 32 bytes. */
export function decodeBase64Signature(value: string): Uint8Array | null {
  const bytes = decodeBase64(value);

  return bytes !== null && bytes.byteLength === SIGNATURE_BYTES ? bytes : null;
}

export function isNonEmptySecret(secret: string): secret is string {
  return typeof secret === 'string' && secret.length > 0;
}

/** Literal, untrimmed UTF-8 secret bytes for Stripe/GitHub/Shopify. */
export function decodeLiteralSecret(secret: string, label: string): Uint8Array {
  if (!isNonEmptySecret(secret)) {
    throw new HooklatchError('invalid-secret', `Invalid ${label} signing secret.`);
  }

  return utf8(secret);
}
