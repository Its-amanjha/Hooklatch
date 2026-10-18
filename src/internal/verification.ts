import { HooklatchError } from '../errors.js';
import type { FailureDetails, VerificationResult, VerifyOptions, WebhookRequest } from '../types.js';
import type { ProviderDescriptor } from './provider.js';
import { normalizeOptions } from './options.js';
import type { NormalizedOptions } from './options.js';
import { normalizeHeaders } from './headers.js';
import { verifyHmac } from './crypto.js';

export interface PreparedVerifier {
  readonly options: NormalizedOptions;
  readonly descriptor: ProviderDescriptor;
  readonly keys: readonly Uint8Array[];
}

export function prepareVerifier(options: VerifyOptions, descriptor: ProviderDescriptor): PreparedVerifier {
  const normalized = normalizeOptions(options);
  const keys = normalized.secrets.map((secret) => new Uint8Array(descriptor.decodeSecret(secret)));

  if (keys.some((key) => key.byteLength === 0)) throw new HooklatchError('invalid-secret', 'Invalid signing secret.');

  return { options: normalized, descriptor, keys };
}

export function readClock(prepared: PreparedVerifier): number {
  let now: number;

  try { now = prepared.options.now(); }
  catch { throw new HooklatchError('invalid-options', 'Invalid verification clock.'); }

  if (!Number.isFinite(now) || now < 0 || now > Number.MAX_SAFE_INTEGER) {
    throw new HooklatchError('invalid-options', 'Invalid verification clock.');
  }

  return now;
}

export function failure(prepared: PreparedVerifier, reason: FailureDetails['reason'], message: string): VerificationResult {
  return { ok: false, provider: prepared.options.provider, reason, message };
}

export async function verifyPrepared(
  request: WebhookRequest, prepared: PreparedVerifier, receivedAt = readClock(prepared),
): Promise<VerificationResult> {
  if (!request || !(request.rawBody instanceof Uint8Array)) throw new HooklatchError('invalid-input', 'Raw body must be a Uint8Array.');

  if (request.rawBody.byteLength > prepared.options.maxBodyBytes) return failure(prepared, 'body-too-large', 'Request body exceeds the configured limit.');
  const rawBody = new Uint8Array(request.rawBody);
  const headers = normalizeHeaders(request.headers);
  const parsed = prepared.descriptor.parse(headers, rawBody);

  if (!parsed.ok) return { ...parsed, provider: prepared.options.provider };

  if (!await verifyHmac(prepared.keys, parsed.signatures, parsed.signedContent)) {
    return failure(prepared, 'invalid-signature', 'Webhook signature is invalid.');
  }

  const timestamp = parsed.identity.timestamp;

  if (timestamp !== null) {
    const age = receivedAt - timestamp;

    if (age > prepared.options.toleranceSeconds) return failure(prepared, 'timestamp-expired', 'Webhook timestamp is outside the allowed past window.');

    if (age < -prepared.options.toleranceSeconds) return failure(prepared, 'timestamp-future', 'Webhook timestamp is outside the allowed future window.');
  }

  return { ok: true, provider: prepared.options.provider, rawBody,
    identity: { ...parsed.identity, authenticatedFields: [...parsed.identity.authenticatedFields] } };
}
