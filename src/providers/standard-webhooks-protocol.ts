import { HooklatchError } from '../errors.js';
import { concatBytes, decodeBase64, utf8 } from '../internal/bytes.js';
import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import type { EventIdentity } from '../types.js';
import {
  decodeBase64Signature,
  failure,
  isCanonicalTimestamp,
  isNonEmptySecret,
  isSchemeToken,
} from './shared.js';

const SCHEME = 'v1';
const SECRET_PREFIX = 'whsec_';
const MIN_KEY_BYTES = 24;
const MAX_KEY_BYTES = 64;

export interface StandardWebhooksHeaderNames {
  readonly id: string;
  readonly timestamp: string;
  readonly signature: string;
}

/**
 * Internal Standard Webhooks v1 protocol factory. `headerNames` selects the
 * canonical or branded header family; callers own alias policy and must never
 * mix names from two families in one configuration.
 */
export function createStandardWebhooksProtocol<P extends string>(
  provider: P,
  label: string,
  headerNames: StandardWebhooksHeaderNames,
): { readonly provider: P } & Pick<ProviderDescriptor, 'decodeSecret' | 'parse'> {
  return {
    provider,

    decodeSecret(secret: string): Uint8Array {
      if (!isNonEmptySecret(secret)) {
        throw new HooklatchError('invalid-secret', `Invalid ${label} signing secret.`);
      }

      const encoded = secret.startsWith(SECRET_PREFIX)
        ? secret.slice(SECRET_PREFIX.length)
        : secret;

      const bytes = decodeBase64(encoded);

      if (bytes === null || bytes.byteLength < MIN_KEY_BYTES || bytes.byteLength > MAX_KEY_BYTES) {
        throw new HooklatchError('invalid-secret', `Invalid ${label} signing secret.`);
      }

      return bytes;
    },

    parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
      const signatureRaw = headers.get(headerNames.signature);

      if (signatureRaw === undefined || signatureRaw.trim() === '') {
        return failure('missing-signature', `No ${label} signature header was provided.`);
      }

      const signatures: Uint8Array[] = [];
      let unknownSchemes = 0;

      for (const piece of signatureRaw.split(/\s+/)) {
        if (piece === '') continue;
        const separator = piece.indexOf(',');

        if (separator <= 0 || separator === piece.length - 1) {
          return failure('malformed-signature', `The ${label} signature header is malformed.`);
        }

        const version = piece.slice(0, separator);
        const value = piece.slice(separator + 1);

        // HTTP comma-combined duplicate header values never form a valid token.
        if (!isSchemeToken(version) || /[,\s]/.test(value)) {
          return failure('malformed-signature', `The ${label} signature header is malformed.`);
        }

        if (version === SCHEME) {
          const decoded = decodeBase64Signature(value);

          // A malformed `v1` fails closed even when another `v1` value is valid.
          if (decoded === null) {
            return failure('malformed-signature', `The ${label} signature header is malformed.`);
          }

          signatures.push(decoded);
        } else {
          unknownSchemes += 1;
        }
      }

      if (signatures.length === 0) {
        return unknownSchemes > 0
          ? failure('unsupported-scheme', `No supported ${label} signature scheme was provided.`)
          : failure('missing-signature', `No ${label} signature value was provided.`);
      }

      const id = headers.get(headerNames.id);

      if (id === undefined || id === '') {
        return failure('missing-identity', `No ${label} message id was provided.`);
      }

      if (id.includes('.') || id.includes(',')) {
        return failure('malformed-signature', `The ${label} message id is malformed.`);
      }

      const timestampText = headers.get(headerNames.timestamp);

      if (timestampText === undefined || timestampText === '') {
        return failure('missing-timestamp', `No ${label} timestamp was provided.`);
      }

      if (!isCanonicalTimestamp(timestampText)) {
        return failure('malformed-signature', `The ${label} timestamp is malformed.`);
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
}
