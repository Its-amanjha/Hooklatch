import { TernError } from '../errors.js';
import type { Provider, VerifyOptions } from '../types.js';

export interface NormalizedOptions {
  readonly provider: Provider;
  readonly secrets: readonly string[];
  readonly toleranceSeconds: number;
  readonly maxBodyBytes: number;
  readonly now: () => number;
}

export function normalizeOptions(options: VerifyOptions): NormalizedOptions {
  if (!options || typeof options !== 'object') throw new TernError('invalid-options', 'Invalid verification options.');
  const { provider, secrets, now } = options;
  if (!['stripe', 'github', 'shopify', 'standard-webhooks'].includes(provider)) {
    throw new TernError('unknown-provider', 'Unsupported webhook provider.');
  }
  if (!Array.isArray(secrets) || secrets.length === 0) throw new TernError('missing-secrets', 'At least one signing secret is required.');
  const secretSnapshot = [...secrets];
  if (secretSnapshot.some((secret) => typeof secret !== 'string' || secret.length === 0)) throw new TernError('invalid-secret', 'Invalid signing secret.');
  const toleranceSeconds = options.toleranceSeconds ?? 300;
  const maxBodyBytes = options.maxBodyBytes ?? 1048576;
  if (!Number.isFinite(toleranceSeconds) || toleranceSeconds < 0
    || !Number.isSafeInteger(maxBodyBytes) || maxBodyBytes <= 0
    || (now !== undefined && typeof now !== 'function')) {
    throw new TernError('invalid-options', 'Invalid verification options.');
  }
  return { provider, secrets: secretSnapshot, toleranceSeconds, maxBodyBytes,
    now: now ?? (() => Math.floor(Date.now() / 1000)) };
}
