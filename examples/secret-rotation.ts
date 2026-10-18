/**
 * Secret rotation: accept multiple active secrets.
 *
 * Uses the implemented contract v1 public API.
 *
 * All values are synthetic placeholders.
 */

import { createVerifier, type VerifyOptions } from 'hooklatch';

/**
 * During a rotation window, configure every secret you accept. The verifier
 * tries all signatures against all secrets until one pair matches.
 *
 * Stripe sends one signature per active secret in `Stripe-Signature`.
 * Standard Webhooks sends a space-delimited list in `webhook-signature`.
 * GitHub and Shopify send a single secret but you may still configure an
 * old + new secret locally to avoid downtime during rotation.
 */
const options: VerifyOptions = {
  provider: 'stripe',
  secrets: [
    process.env.STRIPE_SECRET_NEW!, // current
    process.env.STRIPE_SECRET_OLD!, // retiring — remove after rotation ends
  ],
  toleranceSeconds: 300,
};

const verify = createVerifier(options);

/**
 * Express-style handler.
 *
 * @param rawBody - Exact bytes captured before body-parser runs.
 * @param headers - Normalized headers.
 */
export async function handleStripeWebhook(
  rawBody: Uint8Array,
  headers: Record<string, string>,
): Promise<{ status: number; body: string }> {
  const result = await verify({ rawBody, headers });

  if (!result.ok) {
    return { status: 401, body: JSON.stringify({ error: result.message }) };
  }

  // Verified — process the event.
  return { status: 200, body: JSON.stringify({ received: true }) };
}
