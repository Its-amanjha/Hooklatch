/**
 * Post-verification JSON and schema parsing.
 *
 * Uses the implemented contract v1 public API.
 *
 * Verification authenticates bytes. It does not parse or validate the
 * payload schema. Decode and validate with your own tools after success.
 */

import { verify, type VerifyOptions } from 'hooklatch';
import { isStripeEvent, type StripeEvent } from './event-validation.js';

// Synthetic placeholder — replace with your real secret.
const TEST_SECRET = 'TEST0stripe0secret0placeholder';

const options: VerifyOptions = {
  provider: 'stripe',
  secrets: [TEST_SECRET],
};

// Example schema using zod. The SDK does not depend on any schema library —
// use whatever you already use (zod, valibot, arktype, etc.).
// import { z } from 'zod';
// const StripeEventSchema = z.object({ id: z.string(), type: z.string() });

/**
 * Verify and parse a Stripe webhook.
 *
 * @param rawBody - Exact request bytes.
 * @param headers - Request headers.
 */
export async function handleStripeWebhook(
  rawBody: Uint8Array,
  headers: Headers,
): Promise<{ status: number; event?: StripeEvent; error?: string }> {
  const result = await verify({ rawBody, headers }, options);

  if (!result.ok) {
    return { status: 401, error: result.message };
  }

  // Step 1: Decode bytes to text (caller's choice of decoding).
  const text = new TextDecoder().decode(result.rawBody);

  // Step 2: Parse JSON.
  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch {
    return { status: 500, error: 'Verified body is not valid JSON' };
  }

  // Step 3: Validate with your schema.
  // const event = StripeEventSchema.parse(parsed);
  // For this example, we do a minimal manual check:
  if (!isStripeEvent(parsed)) {
    return { status: 500, error: 'Verified body does not match expected schema' };
  }

  return { status: 200, event: parsed };
}
