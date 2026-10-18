/**
 * Verified non-JSON bodies.
 *
 * Uses the implemented contract v1 public API.
 *
 * Verification is byte-oriented and does not care about content type.
 * After verification succeeds, the caller decodes and interprets.
 */

import { verify, type VerifyOptions, type VerificationResult } from 'hooklatch';

// Synthetic placeholder — replace with your real shared secret.
const TEST_SECRET = 'TEST0github0shared0secret0placeholder';

const options: VerifyOptions = {
  provider: 'github',
  secrets: [TEST_SECRET],
};

/**
 * Handle a GitHub webhook that may deliver form-encoded or JSON bodies.
 *
 * @param rawBody - Exact request bytes.
 * @param headers - Request headers.
 */
export async function handleGitHubWebhook(
  rawBody: Uint8Array,
  headers: Headers,
): Promise<Response> {
  const result = await verify({ rawBody, headers }, options);
  if (!result.ok) {
    return Response.json({ error: result.message }, { status: 400 });
  }

  // Verified. The bytes are authentic — now interpret them.
  const text = new TextDecoder().decode(rawBody);

  // GitHub may send application/json or x-www-form-urlencoded.
  const contentType = headers.get('content-type') ?? '';
  let payload: unknown;
  if (contentType.includes('application/json')) {
    payload = JSON.parse(text) as unknown;
  } else {
    // Form-encoded: decode manually.
    const params = new URLSearchParams(text);
    payload = Object.fromEntries(params.entries());
  }

  return Response.json({ received: true, action: (payload as { action?: string }).action });
}
