import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import type { EventIdentity } from '../types.js';
import { decodeBase64Signature, decodeLiteralSecret, failure } from './shared.js';

const SIGNATURE_HEADER = 'x-shopify-hmac-sha256';
const DELIVERY_HEADER = 'x-shopify-webhook-id';
const EVENT_HEADER = 'x-shopify-event-id';

function optionalHeader(headers: NormalizedHeaders, name: string): string | null {
  const value = headers.get(name);

  return value === undefined || value === '' ? null : value;
}

/**
 * Shopify HTTPS `X-Shopify-Hmac-Sha256`: canonical Base64 HMAC-SHA256 over the
 * raw body only, keyed with the app client secret. Delivery and event IDs are
 * unsigned metadata. EventBridge/Pub/Sub deliveries carry no HMAC header and are
 * therefore not verifiable by this descriptor.
 */
export const shopifyDescriptor: ProviderDescriptor = {
  provider: 'shopify',

  decodeSecret(secret: string): Uint8Array {
    return decodeLiteralSecret(secret, 'Shopify');
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const raw = headers.get(SIGNATURE_HEADER);

    if (raw === undefined || raw.trim() === '') {
      return failure('missing-signature', 'No Shopify signature header was provided.');
    }

    const signature = decodeBase64Signature(raw);

    if (signature === null) {
      return failure('malformed-signature', 'The Shopify signature header is malformed.');
    }

    const identity: EventIdentity = {
      deliveryId: optionalHeader(headers, DELIVERY_HEADER),
      eventId: optionalHeader(headers, EVENT_HEADER),
      timestamp: null,
      authenticatedFields: [],
    };

    return { ok: true, signatures: [signature], signedContent: rawBody, identity };
  },
};
