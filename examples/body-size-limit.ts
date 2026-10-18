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

import { verify, HooklatchError, type VerifyOptions } from 'hooklatch';

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
  try {
    const options: VerifyOptions = {
      provider: 'shopify',
      secrets: [TEST_SECRET],
      maxBodyBytes,
    };

    const result = await verify({ rawBody, headers }, options);

    if (!result.ok) {
      const status = result.reason === 'body-too-large' ? 413 : 400;

      return Response.json({ error: result.message }, { status });
    }

    return Response.json({ received: true });
  } catch (err) {
    if (err instanceof HooklatchError) {
      // Invalid configuration — respond with generic 500.
      return Response.json({ error: 'Internal error' }, { status: 500 });
    }

    throw err;
  }

}
