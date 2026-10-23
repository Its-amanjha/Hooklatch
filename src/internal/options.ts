import { HooklatchError } from '../errors.js';
import { SUPPORTED_PROVIDERS } from '../providers/index.js';
import { snapshotGrafanaOptions, snapshotPolarOptions } from './provider-options.js';
import type { VerifyOptions, FalVerifyOptions } from '../types.js';

type FalCredentials = Pick<FalVerifyOptions, 'publicKeys' | 'expectedUserId'>;

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

function isUserId(value: unknown): value is string {
  return typeof value === 'string' && /^[\x21-\x2b\x2d-\x7e]{1,1024}$/.test(value);
}

/** Data descriptors avoid invoking credential accessors, including non-enumerable ones. */
function ownData(options: VerifyOptions | readonly unknown[], name: string): PropertyDescriptor {
  const property = observe(() => Object.getOwnPropertyDescriptor(options, name));

  if (!property || !Object.hasOwn(property, 'value')) invalidOptions();

  return property;
}

function isKeyArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
}

function snapshotFal(options: VerifyOptions): FalCredentials {
  for (const field of ['secrets', 'secret', 'providerOptions']) {
    if (observe(() => Object.hasOwn(options, field))) invalidOptions();
  }

  const input: unknown = ownData(options, 'publicKeys').value;
  const expectedUserId: unknown = ownData(options, 'expectedUserId').value;

  if (!isUserId(expectedUserId)) invalidOptions();

  const values = observe(() => {
    if (!isKeyArray(input)) invalidOptions();

    return input;
  });

  const length = observe(() => values.length);

  if (!Number.isSafeInteger(length) || length < 1 || length > 16) invalidOptions();
  const publicKeys: Uint8Array[] = [];

  for (let index = 0; index < length; index++) {
    const key: unknown = ownData(values, String(index)).value;

    publicKeys.push(observe(() => {
      if (!(key instanceof Uint8Array)) invalidOptions();

      const bytes = new Uint8Array(32);
      let offset = 0;

      // The intrinsic iterator reads real view bytes and rejects proxies/detached views.
      // Stop at byte 33 so malformed configuration cannot allocate an oversized copy.
      for (const byte of Uint8Array.prototype.values.call(key)) {
        if (offset === 32) invalidOptions();
        bytes[offset++] = byte;
      }

      if (offset !== 32) invalidOptions();

      return bytes;
    }));
  }

  return { publicKeys, expectedUserId };
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

  const fal = provider === 'fal' ? snapshotFal(options) : undefined;
  const secrets = provider === 'fal' ? [] : observe(() => options.secrets);

  if (provider !== 'fal' && (!observe(() => Array.isArray(secrets)) || observe(() => secrets?.length) === 0)) {
    throw new HooklatchError('missing-secrets', 'At least one signing secret is required.');
  }

  const secretSnapshot = observe(() => [...(secrets ?? [])]);

  if (secretSnapshot.some((secret) => !isNonEmptySecret(secret))) {
    throw new HooklatchError('invalid-secret', 'Invalid signing secret.');
  }

  const supplied = observe(() => Object.hasOwn(options, 'providerOptions'));
  const configured = supplied ? observe(() => options.providerOptions) : undefined;

  if (supplied && configured === undefined) invalidOptions();

  if (provider !== 'grafana' && provider !== 'polar' && supplied) invalidOptions();

  if (provider === 'vercel' && observe(() => Object.hasOwn(options, 'publicKeys') || Object.hasOwn(options, 'expectedUserId'))) invalidOptions();

  const grafana = provider === 'grafana' ? observe(() => snapshotGrafanaOptions(configured)) : undefined;
  const polar = provider === 'polar' && supplied ? observe(() => snapshotPolarOptions(configured)) : undefined;
  const defaultTolerance = provider === 'paddle' ? 5 : provider === 'workos' ? 180 : 300;
  const toleranceSeconds = observe(() => options.toleranceSeconds) ?? defaultTolerance;
  const maxBodyBytes = observe(() => options.maxBodyBytes) ?? 1048576;
  const now = observe(() => options.now);

  if (!Number.isFinite(toleranceSeconds) || toleranceSeconds < 0
    || !Number.isSafeInteger(maxBodyBytes) || maxBodyBytes <= 0
    || (now !== undefined && !isClock(now))) invalidOptions();

  const common = { toleranceSeconds, maxBodyBytes,
    now: now ?? (() => (provider === 'workos' || provider === 'sanity') ? Date.now() / 1000 : Math.floor(Date.now() / 1000)) };

  if (provider === 'fal') {
    if (fal === undefined) invalidOptions();

    return { ...common, provider, ...fal };
  }

  const hmac = { ...common, secrets: secretSnapshot };

  if (provider === 'grafana') {
    if (grafana === undefined) invalidOptions();

    return { ...hmac, provider, providerOptions: grafana };
  }

  if (provider === 'polar') return { ...hmac, provider, ...(polar !== undefined && { providerOptions: polar }) };

  return { ...hmac, provider };
}
