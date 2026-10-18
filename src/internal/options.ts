import { HooklatchError } from '../errors.js';
import type { Provider, VerifyOptions } from '../types.js';

export interface NormalizedOptions {
  readonly provider: Provider;
  readonly secrets: readonly string[];
  readonly toleranceSeconds: number;
  readonly maxBodyBytes: number;
  readonly now: () => number;
}

function isOptionsObject(options: VerifyOptions): options is VerifyOptions {
  return options !== null && typeof options === 'object';
}

function isNonEmptySecret(secret: string): secret is string {
  return typeof secret === 'string' && secret.length > 0;
}

function isClock(now: VerifyOptions['now']): now is () => number {
  return typeof now === 'function';
}

export function normalizeOptions(options: VerifyOptions): NormalizedOptions {
  if (!isOptionsObject(options)) throw new HooklatchError('invalid-options', 'Invalid verification options.');
  const { provider, secrets, now } = options;

  if (!['stripe', 'github', 'shopify', 'standard-webhooks'].includes(provider)) {
    throw new HooklatchError('unknown-provider', 'Unsupported webhook provider.');
  }

  if (!Array.isArray(secrets) || secrets.length === 0) throw new HooklatchError('missing-secrets', 'At least one signing secret is required.');
  const secretSnapshot = [...secrets];

  if (secretSnapshot.some((secret) => !isNonEmptySecret(secret))) throw new HooklatchError('invalid-secret', 'Invalid signing secret.');
  const toleranceSeconds = options.toleranceSeconds ?? 300;
  const maxBodyBytes = options.maxBodyBytes ?? 1048576;

  if (!Number.isFinite(toleranceSeconds) || toleranceSeconds < 0
    || !Number.isSafeInteger(maxBodyBytes) || maxBodyBytes <= 0
    || (now !== undefined && !isClock(now))) {
    throw new HooklatchError('invalid-options', 'Invalid verification options.');
  }

  return { provider, secrets: secretSnapshot, toleranceSeconds, maxBodyBytes,
    now: now ?? (() => Math.floor(Date.now() / 1000)) };
}
