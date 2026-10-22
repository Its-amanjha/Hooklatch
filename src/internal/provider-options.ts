import { HooklatchError } from '../errors.js';
import { createGrafanaDescriptor } from '../providers/grafana.js';
import type { GrafanaOptions, PolarOptions } from '../types.js';

type Configuration = GrafanaOptions | PolarOptions;

function invalidOptions(): never {
  throw new HooklatchError('invalid-options', 'Invalid provider options.');
}

function isConfiguration(value: Configuration | undefined): value is Configuration {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isString(value: string | undefined): value is string {
  return typeof value === 'string';
}

function rejectUnexpectedKeys(value: Configuration, allowed: readonly string[]): void {
  for (const key of Reflect.ownKeys(value)) {
    if (Object.getOwnPropertyDescriptor(value, key)?.enumerable && !allowed.some((name) => name === key)) invalidOptions();
  }
}

/** Read selected own properties exactly once, before validation or asynchronous work. */
export function snapshotGrafanaOptions(value: Configuration | undefined): GrafanaOptions {
  if (!isConfiguration(value)) invalidOptions();
  rejectUnexpectedKeys(value, ['mode', 'signatureHeader', 'timestampHeader']);

  if (!Object.hasOwn(value, 'mode') || !('mode' in value)) invalidOptions();
  const mode = value.mode;
  const hasSignature = Object.hasOwn(value, 'signatureHeader');
  const signature = hasSignature && 'signatureHeader' in value ? value.signatureHeader : undefined;

  if (hasSignature && !isString(signature)) invalidOptions();
  const signatureOptions = signature !== undefined ? { signatureHeader: signature.toLowerCase() } : {};
  let snapshot: GrafanaOptions;

  if (mode === 'body') {
    if (Object.hasOwn(value, 'timestampHeader')) invalidOptions();

    snapshot = { mode, ...signatureOptions };
  } else if (mode === 'timestamped') {
    if (!Object.hasOwn(value, 'timestampHeader') || !('timestampHeader' in value)) invalidOptions();
    const timestamp = value.timestampHeader;

    if (!isString(timestamp)) invalidOptions();

    snapshot = { mode, ...signatureOptions, timestampHeader: timestamp.toLowerCase() };
  } else {
    return invalidOptions();
  }

  // The pure factory remains the authority for RFC field names, reservations and collisions.
  createGrafanaDescriptor(snapshot);

  return snapshot;
}

export function snapshotPolarOptions(value: Configuration | undefined): PolarOptions {
  if (!isConfiguration(value)) invalidOptions();
  rejectUnexpectedKeys(value, ['secretMode']);

  if (!Object.hasOwn(value, 'secretMode')) return {};

  if (!('secretMode' in value)) invalidOptions();
  const secretMode = value.secretMode;

  if (secretMode !== 'current' && secretMode !== 'legacy') invalidOptions();

  return { secretMode };
}
