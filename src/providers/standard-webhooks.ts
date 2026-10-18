import { HooklatchError } from '../errors.js';
import { concatBytes, decodeBase64, utf8 } from '../internal/bytes.js';
import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import type { EventIdentity } from '../types.js';
import {
  decodeBase64Signature,
  failure,
  isCanonicalTimestamp,
  isSchemeToken,
} from './shared.js';

const ID_HEADER = 'webhook-id';
const TIMESTAMP_HEADER = 'webhook-timestamp';
const SIGNATURE_HEADER = 'webhook-signature';
const SCHEME = 'v1';
const SECRET_PREFIX = 'whsec_';
const MIN_KEY_BYTES = 24;
const MAX_KEY_BYTES = 64;

/**
 * Standard Webhooks v1: `webhook-id`, `webhook-timestamp`, and a
 * whitespace-separated `webhook-signature` list of `v1,<base64>` tokens.
 * The signature covers `${id}.${timestamp}.<raw body>`. The Ed25519
 * `v1a` scheme is recognized but unsupported in this release.
 */
export const standardWebhooksDescriptor: ProviderDescriptor = {
  provider: 'standard-webhooks',

  decodeSecret(secret: string): Uint8Array {
    if (typeof secret !== 'string' || secret.length === 0) {
      throw new HooklatchError('invalid-secret', 'Invalid Standard Webhooks signing secret.');
    }
    const encoded = secret.startsWith(SECRET_PREFIX)
      ? secret.slice(SECRET_PREFIX.length)
      : secret;
    const bytes = decodeBase64(encoded);
    if (bytes === null || bytes.byteLength < MIN_KEY_BYTES || bytes.byteLength > MAX_KEY_BYTES) {
      throw new HooklatchError('invalid-secret', 'Invalid Standard Webhooks signing secret.');
    }
    return bytes;
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const signatureRaw = headers.get(SIGNATURE_HEADER);
    if (signatureRaw === undefined || signatureRaw.trim() === '') {
      return failure('missing-signature', 'No Standard Webhooks signature header was provided.');
    }

    const signatures: Uint8Array[] = [];
    let unknownSchemes = 0;
    for (const piece of signatureRaw.split(/\s+/)) {
      if (piece === '') continue;
      const separator = piece.indexOf(',');
      if (separator <= 0 || separator === piece.length - 1) {
        return failure('malformed-signature', 'The Standard Webhooks signature header is malformed.');
      }
      const version = piece.slice(0, separator);
      const value = piece.slice(separator + 1);
      // HTTP comma-combined duplicate header values never form a valid token.
      if (!isSchemeToken(version) || /[,\s]/.test(value)) {
        return failure('malformed-signature', 'The Standard Webhooks signature header is malformed.');
      }
      if (version === SCHEME) {
        const decoded = decodeBase64Signature(value);
        // A malformed `v1` fails closed even when another `v1` value is valid.
        if (decoded === null) {
          return failure('malformed-signature', 'The Standard Webhooks signature header is malformed.');
        }
        signatures.push(decoded);
      } else {
        unknownSchemes += 1;
      }
    }

    if (signatures.length === 0) {
      return unknownSchemes > 0
        ? failure('unsupported-scheme', 'No supported Standard Webhooks signature scheme was provided.')
        : failure('missing-signature', 'No Standard Webhooks signature value was provided.');
    }

    const id = headers.get(ID_HEADER);
    if (id === undefined || id === '') {
      return failure('missing-identity', 'No Standard Webhooks message id was provided.');
    }
    if (id.includes('.') || id.includes(',')) {
      return failure('malformed-signature', 'The Standard Webhooks message id is malformed.');
    }

    const timestampText = headers.get(TIMESTAMP_HEADER);
    if (timestampText === undefined || timestampText === '') {
      return failure('missing-timestamp', 'No Standard Webhooks timestamp was provided.');
    }
    if (!isCanonicalTimestamp(timestampText)) {
      return failure('malformed-signature', 'The Standard Webhooks timestamp is malformed.');
    }

    const identity: EventIdentity = {
      deliveryId: null,
      eventId: id,
      timestamp: Number(timestampText),
      authenticatedFields: ['eventId', 'timestamp'],
    };
    return {
      ok: true,
      signatures,
      signedContent: concatBytes(utf8(`${id}.${timestampText}.`), rawBody),
      identity,
    };
  },
};
