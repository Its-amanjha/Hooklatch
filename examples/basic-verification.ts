/**
 * Basic verification with explicit provider selection.
 *
 * Uses the implemented contract v1 public API.
 *
 * All values are synthetic placeholders. Never use real secrets or payloads
 * in examples.
 */

import { verify, type VerifyOptions, type VerificationResult } from 'hooklatch';

// Synthetic placeholder — replace with your real endpoint secret.
const TEST_SECRET = 'whsec_TEST0placeholder0secret0do0not0use';

const options: VerifyOptions = {
  provider: 'stripe',
  secrets: [TEST_SECRET],
};

/**
 * Verify a webhook request.
 *
 * @param rawBody - Exact request bytes captured before any JSON parsing.
 * @param headers - Request headers (Headers, tuple list, or record).
 */
export async function handleWebhook(
  rawBody: Uint8Array,
  headers: Headers,
): Promise<Response> {
  const result = await verify({ rawBody, headers }, options);
  return respond(result);
}

function respond(result: VerificationResult): Response {
  if (!result.ok) {
    // Request-validation failure — safe to log the reason (no secrets inside).
    // Map to 400 for malformed/missing, 401 for invalid signature or
    // expired/future timestamp.
    const status = result.reason === 'invalid-signature'
      || result.reason === 'timestamp-expired'
      || result.reason === 'timestamp-future'
      ? 401
      : 400;
    return Response.json({ error: result.message }, { status });
  }

  // Verified. The bytes are authentic; parsing is the caller's job.
  const text = new TextDecoder().decode(result.rawBody);
  const payload = JSON.parse(text) as unknown;

  return Response.json({ received: true, id: (payload as { id?: string }).id });
}
