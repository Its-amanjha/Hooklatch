import { HooklatchError } from '../errors.js';
import { SUPPORTED_PROVIDERS } from '../providers/index.js';
import { snapshotGrafanaOptions, snapshotPolarOptions } from './provider-options.js';
import type { VerifyOptions } from '../types.js';

export type NormalizedOptions = VerifyOptions & {
  readonly toleranceSeconds: number;
  readonly maxBodyBytes: number;
  readonly now: () => number;
};

function isOptionsObject(options: VerifyOptions): options is VerifyOptions {
  return options !== null && typeof options === 'object' && !Array.isArray(options);
}

function isNonEmptySecret(secret: string): secret is string {
  return typeof secret === 'string' && secret.length > 0;
}

function isClock(now: VerifyOptions['now']): now is () => number {
  return typeof now === 'function';
}

function invalidOptions(): never {
  throw new HooklatchError('invalid-options', 'Invalid verification options.');
}

/** Only observations of caller-owned data are caught; authored errors retain their codes. */
function observe<Value>(read: () => Value): Value {
  try { return read(); }
  catch { return invalidOptions(); }
}

export function normalizeOptions(options: VerifyOptions): NormalizedOptions {
  if (!observe(() => isOptionsObject(options))) invalidOptions();
  const provider = observe(() => options.provider);

  if (!SUPPORTED_PROVIDERS.includes(provider)) {
    throw new HooklatchError('unknown-provider', 'Unsupported webhook provider.');
  }

  const secrets = observe(() => options.secrets);

  if (!observe(() => Array.isArray(secrets)) || observe(() => secrets.length) === 0) {
    throw new HooklatchError('missing-secrets', 'At least one signing secret is required.');
  }

  const secretSnapshot = observe(() => [...secrets]);

  if (secretSnapshot.some((secret) => !isNonEmptySecret(secret))) {
    throw new HooklatchError('invalid-secret', 'Invalid signing secret.');
  }

  const supplied = observe(() => Object.hasOwn(options, 'providerOptions'));
  const configured = supplied ? observe(() => options.providerOptions) : undefined;

  if (supplied && configured === undefined) invalidOptions();

  if (provider !== 'grafana' && provider !== 'polar' && supplied) invalidOptions();

  const grafana = provider === 'grafana' ? observe(() => snapshotGrafanaOptions(configured)) : undefined;
  const polar = provider === 'polar' && supplied ? observe(() => snapshotPolarOptions(configured)) : undefined;
  const defaultTolerance = provider === 'paddle' ? 5 : provider === 'workos' ? 180 : 300;
  const toleranceSeconds = observe(() => options.toleranceSeconds) ?? defaultTolerance;
  const maxBodyBytes = observe(() => options.maxBodyBytes) ?? 1048576;
  const now = observe(() => options.now);

  if (!Number.isFinite(toleranceSeconds) || toleranceSeconds < 0
    || !Number.isSafeInteger(maxBodyBytes) || maxBodyBytes <= 0
    || (now !== undefined && !isClock(now))) invalidOptions();

  const common = { secrets: secretSnapshot, toleranceSeconds, maxBodyBytes,
    now: now ?? (() => (provider === 'workos' || provider === 'sanity') ? Date.now() / 1000 : Math.floor(Date.now() / 1000)) };

  if (provider === 'grafana') {
    if (grafana === undefined) invalidOptions();

    return { ...common, provider, providerOptions: grafana };
  }

  if (provider === 'polar') return { ...common, provider, ...(polar !== undefined && { providerOptions: polar }) };

  return { ...common, provider };
}
