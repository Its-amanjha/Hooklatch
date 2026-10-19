import { createStandardWebhooksProtocol } from './standard-webhooks-protocol.js';

/**
 * Replicate webhooks use the canonical Standard Webhooks `webhook-id`,
 * `webhook-timestamp` and `webhook-signature` headers. The secret is
 * Base64-decoded (an optional `whsec_` prefix is stripped) and must decode to
 * 24-64 bytes; the signature covers the exact
 * `${webhook-id}.${webhook-timestamp}.` bytes followed by the raw body.
 *
 * These headers authenticate protocol bytes, not a unique Replicate identity.
 * A signature minted by another canonical alias verifies here when the same
 * secret is configured, so use endpoint-specific secrets. No prediction or
 * event payload is parsed and no resource id is inferred.
 *
 * No Replicate-published signature vector is claimed; the direct tests use
 * synthetic anchors. Source:
 * https://replicate.com/docs/topics/webhooks/verify-webhook
 */
export const replicateDescriptor = createStandardWebhooksProtocol(
  'replicate',
  'Replicate',
  {
    id: 'webhook-id',
    timestamp: 'webhook-timestamp',
    signature: 'webhook-signature',
  },
);
