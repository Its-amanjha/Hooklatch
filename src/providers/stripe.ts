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

const HEADER = 'stripe-signature';
const SCHEME = 'v1';
const TIMESTAMP_KEY = 't';

/**
 * Stripe `Stripe-Signature` header: `t=<timestamp>,v1=<hex>[,v1=<hex>][,v0=...]`.
 * Whitespace is permitted around comma-separated items. `t` is a singleton and
 * is signed; repeated `t` is rejected. The signature covers `${t}.<raw body>`.
 */
export const stripeDescriptor: ProviderDescriptor = {
  provider: 'stripe',

  decodeSecret(secret: string): Uint8Array {
    // Stripe keys the HMAC with the literal secret string, including `whsec_`.
    return decodeLiteralSecret(secret, 'Stripe');
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const raw = headers.get(HEADER);
    if (raw === undefined || raw.trim() === '') {
      return failure('missing-signature', 'No Stripe signature header was provided.');
    }

    const signatures: Uint8Array[] = [];
    let timestampText: string | undefined;
    let unknownSchemes = 0;

    for (const rawItem of raw.split(',')) {
      const item = rawItem.trim();
      const separator = item.indexOf('=');
      if (item === '' || separator <= 0 || separator === item.length - 1) {
        return failure('malformed-signature', 'The Stripe signature header is malformed.');
      }
      const key = item.slice(0, separator);
      const value = item.slice(separator + 1);

      if (key === TIMESTAMP_KEY) {
        if (timestampText !== undefined) {
          return failure('malformed-signature', 'The Stripe signature header is malformed.');
        }
        if (!isCanonicalTimestamp(value)) {
          return failure('malformed-signature', 'The Stripe signature header is malformed.');
        }
        timestampText = value;
      } else if (key === SCHEME) {
        const decoded = decodeHexSignature(value);
        // A malformed `v1` fails closed even when another `v1` value is valid.
        if (decoded === null) {
          return failure('malformed-signature', 'The Stripe signature header is malformed.');
        }
        signatures.push(decoded);
      } else if (isSchemeToken(key)) {
        unknownSchemes += 1;
      } else {
        return failure('malformed-signature', 'The Stripe signature header is malformed.');
      }
    }

    if (timestampText === undefined) {
      return failure('missing-timestamp', 'No Stripe signature timestamp was provided.');
    }
    if (signatures.length === 0) {
      return unknownSchemes > 0
        ? failure('unsupported-scheme', 'No supported Stripe signature scheme was provided.')
        : failure('missing-signature', 'No Stripe signature value was provided.');
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
      signedContent: concatBytes(utf8(`${timestampText}.`), rawBody),
      identity,
    };
  },
};
