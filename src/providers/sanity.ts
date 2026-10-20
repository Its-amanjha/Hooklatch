import { concatBytes, utf8 } from '../internal/bytes.js';
import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import type { EventIdentity } from '../types.js';
import { decodeLiteralSecret, failure, isCanonicalTimestamp } from './shared.js';

const SIGNATURE_HEADER = 'sanity-webhook-signature';
const TIMESTAMP_FIELD = 't=';
const SIGNATURE_FIELD = 'v1=';
const DIGEST_CHARACTERS = 43;
const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Sanity does not send signed payloads before 2021-01-01T00:00:00.000Z, so a
 * millisecond timestamp below this bound is not a Sanity delivery. The bound
 * mirrors the reference toolkit; the failure code is Hooklatch policy.
 */
const MINIMUM_TIMESTAMP_MS = 1609459200000;

interface SanityHeaderFields {
  readonly timestampText: string;
  readonly digest: string;
}

/**
 * Split the exact accepted header grammar `t=<ms>,v1=<digest>`.
 *
 * The fields are ordered, appear exactly once, and carry no whitespace, extra
 * fields, duplicate fields, semicolon separators, or alternate versions. Any
 * other structure is rejected instead of being repaired.
 */
function splitHeader(raw: string): SanityHeaderFields | null {
  const separator = raw.indexOf(',');

  if (separator < 0) return null;

  const timestampField = raw.slice(0, separator);
  const signatureField = raw.slice(separator + 1);

  if (!timestampField.startsWith(TIMESTAMP_FIELD)) return null;

  if (!signatureField.startsWith(SIGNATURE_FIELD)) return null;

  const timestampText = timestampField.slice(TIMESTAMP_FIELD.length);
  const digest = signatureField.slice(SIGNATURE_FIELD.length);

  if (timestampText.length === 0) return null;

  return { timestampText, digest };
}

/**
 * Encode the 32 decoded digest bytes as canonical unpadded Base64url.
 *
 * 32 bytes are 256 bits: 42 characters carry 252 of them and the last four
 * bits close the 43rd character.
 */
function encodeBase64Url(bytes: Uint8Array): string {
  let output = '';
  let buffer = 0;
  let bits = 0;

  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;

    while (bits >= 6) {
      bits -= 6;
      output += BASE64URL_ALPHABET.charAt((buffer >>> bits) & 0x3f);
      buffer &= (1 << bits) - 1;
    }
  }

  return output + BASE64URL_ALPHABET.charAt((buffer << (6 - bits)) & 0x3f);
}

/**
 * Decode exactly 43 canonical unpadded Base64url characters into 32 bytes.
 *
 * The 43 characters carry 258 bits, so 32 bytes consume 256 of them and the
 * two remaining low bits of the final character are pad bits. Re-encoding the
 * decoded bytes must reproduce the input exactly, which rejects a digest whose
 * pad bits are not zero.
 */
function decodeBase64UrlDigest(value: string): Uint8Array | null {
  if (value.length !== DIGEST_CHARACTERS) return null;

  const bytes = new Uint8Array(32);
  let buffer = 0;
  let bits = 0;
  let offset = 0;

  for (let index = 0; index < value.length; index += 1) {
    const digit = BASE64URL_ALPHABET.indexOf(value.charAt(index));

    if (digit < 0) return null;

    buffer = (buffer << 6) | digit;
    bits += 6;

    if (bits < 8) continue;

    bits -= 8;
    bytes[offset] = (buffer >>> bits) & 0xff;
    offset += 1;
    buffer &= (1 << bits) - 1;
  }

  return encodeBase64Url(bytes) === value ? bytes : null;
}

/**
 * Sanity: `sanity-webhook-signature: t=<unix milliseconds>,v1=<base64url>`.
 *
 * The HMAC-SHA256 covers UTF8(the original `t` text + ".") concatenated with
 * the exact raw body. The secret is the literal, untrimmed UTF-8 text; it is
 * never Base64-decoded. The digest is canonical unpadded Base64url for exactly
 * 32 bytes, decoded by a descriptor-local decoder so the shared standard
 * Base64 handling stays unchanged.
 *
 * The accepted header is exactly `t=<ms>,v1=<digest>`: ordered fields, one
 * each, no whitespace anywhere or outer trimming, no extra or duplicate
 * fields, no semicolon separators, no padding, and no alternate versions. A
 * missing or blank header is `missing-signature`; every other nonmatching
 * structure is `malformed-signature`, with no alternate reason precedence.
 *
 * `t` must be a canonical nonnegative safe decimal integer of milliseconds
 * with no leading zeros, at or after 2021-01-01T00:00:00.000Z. Identity is
 * `timestamp = Number(t) / 1000` with no delivery or event id; freshness is
 * enforced by core and is never evaluated here.
 *
 * The reference SDK verifies UTF-8 text and refuses to sign an empty payload.
 * This descriptor accepts empty, NUL, invalid UTF-8, and non-JSON bodies as
 * opaque bytes, so it extends rather than matches that behavior, and it does
 * not claim exact SDK parity or live interoperability. The strict grammar
 * is checked at parse time. The reference decoder regex accepts spaces and
 * trimming, but full SDK verification compares the original header to canonical
 * re-encoding and also rejects these noncanonical header variants.
 *
 * Sources:
 * - https://www.sanity.io/docs/content-lake/webhook-best-practices
 * - https://github.com/sanity-io/webhook-toolkit/blob/e0c211ed6cd80465a70829e335c9e219f37839ba/src/signature.ts
 */
export const sanityDescriptor = {
  provider: 'sanity',

  decodeSecret(secret: string): Uint8Array {
    return decodeLiteralSecret(secret, 'Sanity');
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const raw = headers.get(SIGNATURE_HEADER);

    if (raw === undefined || raw.trim() === '') {
      return failure('missing-signature', 'No Sanity signature header was provided.');
    }

    const fields = splitHeader(raw);

    if (fields === null) {
      return failure('malformed-signature', 'The Sanity signature header is malformed.');
    }

    if (!isCanonicalTimestamp(fields.timestampText)) {
      return failure('malformed-signature', 'The Sanity signature header is malformed.');
    }

    const timestamp = Number(fields.timestampText);

    if (timestamp < MINIMUM_TIMESTAMP_MS) {
      return failure('malformed-signature', 'The Sanity signature header is malformed.');
    }

    const digest = decodeBase64UrlDigest(fields.digest);

    if (digest === null) {
      return failure('malformed-signature', 'The Sanity signature header is malformed.');
    }

    const identity: EventIdentity = {
      deliveryId: null,
      eventId: null,
      timestamp: timestamp / 1000,
      authenticatedFields: ['timestamp'],
    };

    return {
      ok: true,
      signatures: [digest],
      signedContent: concatBytes(utf8(`${fields.timestampText}.`), rawBody),
      identity,
    };
  },
} satisfies { readonly provider: 'sanity' } & Pick<ProviderDescriptor, 'decodeSecret' | 'parse'>;
