import { HooklatchError } from './errors.js';
import type { VerificationResult, VerifyOptions, WebhookRequest } from './types.js';
import { getProviderDescriptor } from './providers/index.js';
import { normalizeOptions } from './internal/options.js';
import { normalizeHeaders } from './internal/headers.js';
import { readBody } from './internal/body.js';
import { failure, prepareVerifier, readClock, verifyPrepared } from './internal/verification.js';

function prepare(options: VerifyOptions) {
  const normalized = normalizeOptions(options);

  return prepareVerifier(normalized, getProviderDescriptor(normalized.provider));
}

export async function verify(request: WebhookRequest, options: VerifyOptions): Promise<VerificationResult> {
  return verifyPrepared(request, prepare(options));
}

export function createVerifier(options: VerifyOptions): (request: WebhookRequest) => Promise<VerificationResult> {
  const prepared = prepare(options);

  return (request) => verifyPrepared(request, prepared);
}

/** Consumes the original Request once. Successful callers use result.rawBody. */
export async function verifyRequest(request: Request, options: VerifyOptions): Promise<VerificationResult> {
  const prepared = prepare(options);
  const receivedAt = readClock(prepared);

  if (!(request instanceof Request)) throw new HooklatchError('invalid-input', 'A Web Request is required.');
  const headers = normalizeHeaders(request.headers);
  const rawBody = await readBody(request, prepared.options.maxBodyBytes);

  if (rawBody === null) return failure(prepared, 'body-too-large', 'Request body exceeds the configured limit.');

  // Normalize to tuples so byte and header snapshots share the raw-input path.
  return verifyPrepared({ rawBody, headers: [...headers] }, prepared, receivedAt);
}
