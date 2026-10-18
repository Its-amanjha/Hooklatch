/**
 * Separating request-validation failures from setup/runtime errors.
 *
 * Uses the implemented contract v1 public API.
 *
 * Request failures (bad signature, expired timestamp, etc.) are RETURNED
 * as { ok: false, reason, message }. Setup/runtime failures (unknown
 * provider, missing secrets, invalid options, consumed body, crypto
 * unavailable) are THROWN as HooklatchError.
 */

import {
  createVerifier,
  HooklatchError,
  type VerifyOptions,
  type VerificationResult,
} from 'hooklatch';

// Synthetic placeholder — replace with your real secret.
const TEST_SECRET = 'TEST0github0secret0placeholder';

/**
 * Boot-time setup: create the verifier. Errors here are fatal.
 */
export function createGitHubVerifier(): (request: {
  rawBody: Uint8Array;
  headers: Headers;
}) => Promise<VerificationResult> {
  try {
    const options: VerifyOptions = {
      provider: 'github',
      secrets: [TEST_SECRET],
      toleranceSeconds: 300,
    };
    return createVerifier(options);
  } catch (err) {
    if (err instanceof HooklatchError) {
      // Setup error: crash at boot, not per-request.
      // Possible codes: 'unknown-provider', 'missing-secrets',
      // 'invalid-secret', 'invalid-options'.
      throw err;
    }
    throw err;
  }
}

/**
 * Per-request handling: bad signatures are outcomes, not exceptions.
 */
export async function handleRequest(
  verify: (request: {
    rawBody: Uint8Array;
    headers: Headers;
  }) => Promise<VerificationResult>,
  rawBody: Uint8Array,
  headers: Headers,
): Promise<Response> {
  const result = await verify({ rawBody, headers });
  if (!result.ok) {
    // Request-validation failure — safe to log reason and message.
    // Map to appropriate status codes.
    switch (result.reason) {
      case 'invalid-signature':
      case 'timestamp-expired':
      case 'timestamp-future':
        return Response.json({ error: result.message }, { status: 401 });
      case 'missing-signature':
      case 'malformed-signature':
      case 'missing-identity':
      case 'missing-timestamp':
      case 'unsupported-scheme':
        return Response.json({ error: result.message }, { status: 400 });
      case 'body-too-large':
        return Response.json({ error: result.message }, { status: 413 });
      default:
        return Response.json({ error: result.message }, { status: 400 });
    }
  }

  // Verified — proceed.
  return Response.json({ received: true });
}
