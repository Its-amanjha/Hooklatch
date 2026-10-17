import { createWebhookHandler } from '@hookflo/tern/nextjs';

export const POST = createWebhookHandler({
  provider: 'stripe',
  secrets: ['whsec_TEST_synthetic_replace_before_deployment'],
  handler: (_request, success) => {
    // The Request body has been consumed. Use the verified bytes.
    return Response.json({ received: true, bytes: success.rawBody.byteLength });
  },
});
