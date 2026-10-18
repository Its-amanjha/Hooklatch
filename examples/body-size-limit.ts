/**
 * Configurable body size limits.
 *
 * Uses the implemented contract v1 public API.
 *
 * maxBodyBytes (default 1048576 = 1 MiB) is enforced while reading streams
 * and before copying raw inputs. Exceeding it returns { ok: false, reason:
 * 'body-too-large' } for request verification, or throws HooklatchError for
 * invalid limit configuration.
 *
 * Platform limits (e.g. Cloudflare Workers plan limits) may reject earlier.
 */

import { verify, HooklatchError, type VerifyOptions, type VerificationResult } from 'hooklatch';

// Synthetic placeholder — replace with your real secret.
const TEST_SECRET = 'TEST0shopify0secret0placeholder';

/**
 * Verify with a custom body size limit.
 *
 * @param rawBody - Exact request bytes.
 * @param headers - Request headers.
 * @param maxBodyBytes - Maximum allowed body size in bytes.
 */
export async function handleShopifyWebhook(
  rawBody: Uint8Array,
  headers: Headers,
  maxBodyBytes = 1048576,
): Promise<Response> {
  let options: VerifyOptions;
  try {
    options = {
      provider: 'shopify',
      secrets: [TEST_SECRET],
      maxBodyBytes,
    };
    // Validate options before use — invalid limits throw HooklatchError.
    // (In the real implementation, createVerifier or verify validates.)
  } catch (err) {
    if (err instanceof HooklatchError) {
      // Invalid configuration — respond with generic 500.
      return Response.json({ error: 'Internal error' }, { status: 500 });
    }
    throw err;
  }

  const result = await verify({ rawBody, headers }, options);
  if (!result.ok) {
    if (result.reason === 'body-too-large') {
      return Response.json({ error: 'Body too large' }, { status: 413 });
    }
    return Response.json({ error: result.message }, { status: 400 });
  }

  return Response.json({ received: true });
}
