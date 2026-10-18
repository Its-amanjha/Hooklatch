/**
 * Web Request convenience wrapper.
 *
 * Uses the implemented contract v1 Request wrapper.
 *
 * verifyRequest consumes the Request body once with bounded reading.
 * Already-consumed bodies throw HooklatchError (setup error, not a result).
 */

import { verifyRequest, HooklatchError, type VerifyOptions } from 'hooklatch';

// Synthetic placeholder — replace with your real secret.
const TEST_SECRET = 'TEST0workers0secret0placeholder';

const options: VerifyOptions = {
  provider: 'github',
  secrets: [TEST_SECRET],
  maxBodyBytes: 1048576, // 1 MiB default; adjust for your platform
};

/**
 * Cloudflare Workers fetch handler.
 *
 * @param request - Incoming Web Request (body not yet consumed).
 * @param env - Environment bindings.
 */
export async function handleWorkersWebhook(
  request: Request,
  env: Record<string, string>,
): Promise<Response> {
  const secret = env.GITHUB_SECRET;
  if (!secret) return new Response('Internal Server Error', { status: 500 });
  // Merge env-derived secrets into options.
  const opts: VerifyOptions = {
    ...options,
    secrets: [secret],
  };

  try {
    const result = await verifyRequest(request, opts);
    if (!result.ok) {
      return Response.json({ error: result.message }, { status: 400 });
    }
    // Verified. Use result.rawBody — do NOT re-read the Request body.
    const payload = JSON.parse(new TextDecoder().decode(result.rawBody)) as unknown;
    return Response.json({ received: true });
  } catch (err) {
    if (err instanceof HooklatchError) {
      // Setup error: consumed body, read failure, crypto unavailable, etc.
      // Respond with a generic 500 — do not leak internal details.
      return Response.json({ error: 'Internal error' }, { status: 500 });
    }
    throw err; // Unexpected — let the runtime handle it.
  }
}
