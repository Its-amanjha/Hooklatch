import { HooklatchError } from './errors.js';
import type { VerificationResult, VerifyOptions, WebhookRequest } from './types.js';
import { prepareVerification } from './internal/prepare.js';
import { normalizeHeaders } from './internal/headers.js';
import { readBody } from './internal/body.js';
import { failure, readClock, verifyPrepared } from './internal/verification.js';

export async function verify(request: WebhookRequest, options: VerifyOptions): Promise<VerificationResult> {
  return verifyPrepared(request, prepareVerification(options));
}

export function createVerifier(options: VerifyOptions): (request: WebhookRequest) => Promise<VerificationResult> {
  const prepared = prepareVerification(options);

  return (request) => verifyPrepared(request, prepared);
}

/** Consumes the original Request once. Successful callers use result.rawBody. */
export async function verifyRequest(request: Request, options: VerifyOptions): Promise<VerificationResult> {
  const prepared = prepareVerification(options);
  const receivedAt = readClock(prepared);

  if (!(request instanceof Request)) throw new HooklatchError('invalid-input', 'A Web Request is required.');
  const headers = normalizeHeaders(request.headers);
  const rawBody = await readBody(request, prepared.options.maxBodyBytes);

  if (rawBody === null) return failure(prepared, 'body-too-large', 'Request body exceeds the configured limit.');

  // Normalize to tuples so byte and header snapshots share the raw-input path.
  return verifyPrepared({ rawBody, headers: [...headers] }, prepared, receivedAt);
}
