import { concatBytes, utf8 } from '../internal/bytes.js';
import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import type { EventIdentity } from '../types.js';
import {
  decodeHexSignature,
  decodeLiteralSecret,
  failure,
  isCanonicalTimestamp,
  isSchemeToken,
} from './shared.js';

const SIGNATURE_HEADER = 'paddle-signature';
const TIMESTAMP_KEY = 'ts';
const SIGNATURE_KEY = 'h1';

/**
 * Opaque nonempty printable ASCII unknown-field value: no whitespace, commas,
 * semicolons, or additional equals signs. This is a bounded Hooklatch grammar,
 * not a promise to support an unspecified future signature version.
 */
const OPAQUE_VALUE = /^[\x21-\x2b\x2d-\x3a\x3c\x3e-\x7e]+$/;

/**
 * Paddle Billing: `Paddle-Signature: ts=<unix seconds>;h1=<64 hex>`.
 * The signature covers the exact `ts` text, a colon, and the untouched raw
 * body. Repeated `h1` values are a Hooklatch rotation accept-set; every `h1`
 * must be valid. Unknown fields such as `h2` are validated then ignored.
 * Freshness is enforced by core, never here.
 */
export const paddleDescriptor = {
  provider: 'paddle',

  decodeSecret(secret: string): Uint8Array {
    return decodeLiteralSecret(secret, 'Paddle');
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const raw = headers.get(SIGNATURE_HEADER);

    if (raw === undefined || raw.trim() === '') {
      return failure('missing-signature', 'No Paddle signature header was provided.');
    }

    // HTTP comma-combined duplicate header values never form a valid field list.
    if (raw.includes(',')) {
      return failure('malformed-signature', 'The Paddle signature header is malformed.');
    }

    const signatures: Uint8Array[] = [];
    let timestampText: string | undefined;
    let timestampCount = 0;
    let unknownSchemes = 0;

    for (const rawSegment of raw.split(';')) {
      // Trim outer segment whitespace only; keys and values stay exact.
      const segment = rawSegment.trim();

      if (segment === '') {
        return failure('malformed-signature', 'The Paddle signature header is malformed.');
      }

      // Reject missing keys, empty values, and extra equals signs.
      const separator = segment.indexOf('=');

      if (separator <= 0 || separator === segment.length - 1 || segment.indexOf('=', separator + 1) !== -1) {
        return failure('malformed-signature', 'The Paddle signature header is malformed.');
      }

      const key = segment.slice(0, separator);
      const value = segment.slice(separator + 1);

      if (!isSchemeToken(key)) {
        return failure('malformed-signature', 'The Paddle signature header is malformed.');
      }

      if (key === TIMESTAMP_KEY) {
        timestampCount += 1;

        if (timestampCount > 1) {
          return failure('malformed-signature', 'The Paddle signature header is malformed.');
        }

        if (!isCanonicalTimestamp(value)) {
          return failure('malformed-signature', 'The Paddle signature header is malformed.');
        }

        timestampText = value;
        continue;
      }

      if (key === SIGNATURE_KEY) {
        const decoded = decodeHexSignature(value);

        // One malformed h1 poisons the whole header, even beside a valid h1.
        if (decoded === null) {
          return failure('malformed-signature', 'The Paddle signature header is malformed.');
        }

        signatures.push(decoded);
        continue;
      }

      // Unknown fields are structurally validated, then ignored.
      if (!OPAQUE_VALUE.test(value)) {
        return failure('malformed-signature', 'The Paddle signature header is malformed.');
      }

      unknownSchemes += 1;
    }

    // Required-field checks run only after all structure/token validation.
    if (signatures.length === 0) {
      return unknownSchemes > 0
        ? failure('unsupported-scheme', 'No supported Paddle signature scheme was provided.')
        : failure('missing-signature', 'No Paddle signature value was provided.');
    }

    if (timestampText === undefined) {
      return failure('missing-timestamp', 'No Paddle timestamp was provided.');
    }

    const identity: EventIdentity = {
      deliveryId: null,
      eventId: null,
      timestamp: Number(timestampText),
      authenticatedFields: ['timestamp'],
    };

    return {
      ok: true,
      signatures,
      signedContent: concatBytes(utf8(`${timestampText}:`), rawBody),
      identity,
    };
  },
} satisfies { readonly provider: 'paddle' } & Pick<ProviderDescriptor, 'decodeSecret' | 'parse'>;
