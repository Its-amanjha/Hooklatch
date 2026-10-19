import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import type { EventIdentity } from '../types.js';
import { decodeHexSignature, decodeLiteralSecret, failure } from './shared.js';

const SIGNATURE_HEADER = 'x-razorpay-signature';
const EVENT_ID_HEADER = 'x-razorpay-event-id';

/**
 * Razorpay `X-Razorpay-Signature`: a single hex HMAC-SHA256 over the raw request
 * body only, keyed with the literal dashboard webhook secret. A missing,
 * blank, prefixed, non-hex, wrong-length or comma-combined value fails closed.
 * The optional `x-razorpay-event-id` is unsigned metadata and never proves
 * authenticity.
 *
 * Sources:
 * - https://razorpay.com/docs/webhooks/validate-test/
 * - https://github.com/razorpay/razorpay-node/blob/b9e8527225a7322ba2671a3bc0b848fd019d2d8c/lib/utils/razorpay-utils.js
 *
 * No Razorpay-published signature vector is claimed; test anchors are synthetic.
 */
export const razorpayDescriptor = {
  provider: 'razorpay',

  decodeSecret(secret: string): Uint8Array {
    return decodeLiteralSecret(secret, 'Razorpay');
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const raw = headers.get(SIGNATURE_HEADER);

    if (raw === undefined || raw.trim() === '') {
      return failure('missing-signature', 'No Razorpay signature header was provided.');
    }

    const signature = decodeHexSignature(raw);

    if (signature === null) {
      return failure('malformed-signature', 'The Razorpay signature header is malformed.');
    }

    const eventId = headers.get(EVENT_ID_HEADER);

    const identity: EventIdentity = {
      deliveryId: null,
      eventId: eventId === undefined || eventId.trim() === '' ? null : eventId,
      timestamp: null,
      authenticatedFields: [],
    };

    return { ok: true, signatures: [signature], signedContent: rawBody, identity };
  },
} satisfies { readonly provider: 'razorpay' } & Pick<ProviderDescriptor, 'decodeSecret' | 'parse'>;
