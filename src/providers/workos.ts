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

const SIGNATURE_HEADER = 'workos-signature';
const TIMESTAMP_KEY = 't';
const SIGNATURE_KEY = 'v1';

/**
 * Opaque nonempty printable ASCII unknown-field value: no whitespace, commas,
 * or additional equals signs. This is a bounded Hooklatch grammar, not a
 * promise to support an unspecified future signature version.
 */
const OPAQUE_VALUE = /^[\x21-\x2b\x2d-\x3c\x3e-\x7e]+$/;

/**
 * WorkOS: `WorkOS-Signature: t=<unix milliseconds>, v1=<64 hex>`.
 *
 * The comma-separated field list is validated as a whole before required-field
 * checks. Segments are trimmed only at their outer edges, so whitespace around
 * `=` is rejected; field names are case-sensitive. `t` must appear exactly once
 * and be a canonical nonnegative safe decimal integer in milliseconds (zero is
 * allowed, leading zeros are not). Every `v1` must be a 32-byte hex digest in
 * either case; repeated `v1` values form a Hooklatch rotation accept-set, but a
 * malformed `v1` poisons the header. Unknown field names are validated as
 * opaque values and then ignored.
 *
 * The HMAC-SHA256 covers UTF8(original `t` text + ".") concatenated with the
 * exact raw body. The secret is the literal, untrimmed UTF-8 text; it is never
 * Base64-decoded. Invalid-UTF-8 body handling is a Hooklatch byte-preservation
 * policy, not claimed parity with SDKs that decode the body to a string.
 * Identity is `timestamp = Number(t) / 1000`; freshness is enforced by core and
 * is never evaluated here.
 *
 * This strict grammar, repeated-v1 accept-set, and millisecond identity are
 * documented receiver policies, not claims of exact WorkOS SDK parity. No
 * WorkOS-published signature vector is claimed; tests use synthetic anchors.
 * Sources:
 * - https://workos.com/docs/events/data-syncing/webhooks
 * - https://raw.githubusercontent.com/workos/workos-node/ad8bff226e9b37435f0c62390318d4819f76b3d1/src/common/crypto/signature-provider.ts
 */
export const workosDescriptor = {
  provider: 'workos',

  decodeSecret(secret: string): Uint8Array {
    return decodeLiteralSecret(secret, 'WorkOS');
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const raw = headers.get(SIGNATURE_HEADER);

    if (raw === undefined || raw.trim() === '') {
      return failure('missing-signature', 'No WorkOS signature header was provided.');
    }

    const signatures: Uint8Array[] = [];
    let timestampText: string | undefined;
    let timestampCount = 0;
    let unknownFields = 0;

    // Validate the complete structure before any required-field decision.
    for (const rawSegment of raw.split(',')) {
      const segment = rawSegment.trim();

      if (segment === '') {
        return failure('malformed-signature', 'The WorkOS signature header is malformed.');
      }

      // Reject missing keys, empty values, and extra equals signs.
      const separator = segment.indexOf('=');

      if (separator <= 0 || separator === segment.length - 1 || segment.indexOf('=', separator + 1) !== -1) {
        return failure('malformed-signature', 'The WorkOS signature header is malformed.');
      }

      const key = segment.slice(0, separator);
      const value = segment.slice(separator + 1);

      if (!isSchemeToken(key)) {
        return failure('malformed-signature', 'The WorkOS signature header is malformed.');
      }

      if (key === TIMESTAMP_KEY) {
        timestampCount += 1;

        // Duplicate timestamps fail even when the values agree.
        if (timestampCount > 1) {
          return failure('malformed-signature', 'The WorkOS signature header is malformed.');
        }

        if (!isCanonicalTimestamp(value)) {
          return failure('malformed-signature', 'The WorkOS signature header is malformed.');
        }

        timestampText = value;
        continue;
      }

      if (key === SIGNATURE_KEY) {
        const decoded = decodeHexSignature(value);

        // One malformed v1 poisons the whole header, even beside a valid v1.
        if (decoded === null) {
          return failure('malformed-signature', 'The WorkOS signature header is malformed.');
        }

        signatures.push(decoded);
        continue;
      }

      // Unknown fields are structurally validated, then ignored.
      if (!OPAQUE_VALUE.test(value)) {
        return failure('malformed-signature', 'The WorkOS signature header is malformed.');
      }

      unknownFields += 1;
    }

    // Required-field checks run only after the whole structure validated.
    if (signatures.length === 0) {
      return unknownFields > 0
        ? failure('unsupported-scheme', 'No supported WorkOS signature scheme was provided.')
        : failure('missing-signature', 'No WorkOS signature value was provided.');
    }

    if (timestampText === undefined) {
      return failure('missing-timestamp', 'No WorkOS timestamp was provided.');
    }

    const identity: EventIdentity = {
      deliveryId: null,
      eventId: null,
      timestamp: Number(timestampText) / 1000,
      authenticatedFields: ['timestamp'],
    };

    return {
      ok: true,
      signatures,
      signedContent: concatBytes(utf8(`${timestampText}.`), rawBody),
      identity,
    };
  },
} satisfies { readonly provider: 'workos' } & Pick<ProviderDescriptor, 'decodeSecret' | 'parse'>;
