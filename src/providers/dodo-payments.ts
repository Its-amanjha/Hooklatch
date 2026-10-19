import { createStandardWebhooksProtocol } from './standard-webhooks-protocol.js';

/**
 * Dodo Payments delivers Standard Webhooks payloads with the canonical
 * `webhook-id`, `webhook-timestamp` and `webhook-signature` headers. The
 * secret is Base64-decoded (an optional `whsec_` prefix is stripped) and must
 * decode to 24-64 bytes; the signature covers the exact
 * `${webhook-id}.${webhook-timestamp}.` bytes followed by the raw body.
 *
 * These headers authenticate protocol bytes, not a unique Dodo identity: a
 * signature minted by any other canonical alias verifies here when the same
 * secret is configured. Use endpoint-specific secrets and route configuration
 * to prevent cross-endpoint replay. No event payload is parsed and no
 * resource id is inferred.
 *
 * No Dodo Payments-published signature vector is claimed; the direct tests use
 * synthetic anchors. Source:
 * https://docs.dodopayments.com/developer-resources/webhooks
 */
export const dodoPaymentsDescriptor = createStandardWebhooksProtocol(
  'dodo-payments',
  'Dodo Payments',
  {
    id: 'webhook-id',
    timestamp: 'webhook-timestamp',
    signature: 'webhook-signature',
  },
);
