import { createStandardWebhooksProtocol } from './standard-webhooks-protocol.js';

/**
 * Standard Webhooks v1: `webhook-id`, `webhook-timestamp`, and a
 * whitespace-separated `webhook-signature` list of `v1,<base64>` tokens.
 * The signature covers `${id}.${timestamp}.<raw body>`. The Ed25519
 * `v1a` scheme is recognized but unsupported in this release.
 */
export const standardWebhooksDescriptor = createStandardWebhooksProtocol(
  'standard-webhooks',
  'Standard Webhooks',
  {
    id: 'webhook-id',
    timestamp: 'webhook-timestamp',
    signature: 'webhook-signature',
  },
);
