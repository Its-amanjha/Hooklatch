import { createStandardWebhooksProtocol } from './standard-webhooks-protocol.js';

/**
 * Clerk delivers Standard Webhooks payloads through Svix and its official
 * helper reads only the branded `svix-*` headers. Canonical `webhook-*`
 * headers are deliberately ignored and never repair a missing or invalid
 * branded field.
 */
export const clerkDescriptor = createStandardWebhooksProtocol(
  'clerk',
  'Clerk',
  {
    id: 'svix-id',
    timestamp: 'svix-timestamp',
    signature: 'svix-signature',
  },
);
