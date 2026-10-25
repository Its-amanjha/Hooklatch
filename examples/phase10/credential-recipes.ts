/**
 * Credential and configuration recipes for Hooklatch providers that need
 * application-owned setup.
 *
 * These are example helpers, not new SDK exports. They use only the public
 * `hooklatch` API and portable Web APIs; no Buffer, Node imports, network
 * calls, JWKS lookup, or dummy secrets are used.
 */

import {
  HooklatchError,
  createVerifier,
  type FalVerifyOptions,
  type GrafanaOptions,
  type VerifyOptions,
} from 'hooklatch';

const VISIBLE_USER_ID = /^[\x21-\x2b\x2d-\x7e]{1,1024}$/;

function isString<T>(value: T): value is Extract<T, string> {
  return typeof value === 'string';
}

function invalidCredentialConfiguration(): never {
  throw new HooklatchError('invalid-options', 'Invalid fal credential configuration.');
}

function base64UrlUnpadded(bytes: Uint8Array): string {
  let binary = '';

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Build fal options from two environment-style strings.
 *
 * `publicKeysValue` is a comma-delimited list of 1..16 unpadded Base64url
 * entries. Each entry must be exactly 43 characters and decode to exactly
 * 32 bytes with canonical unused Base64 bits. Whitespace is never trimmed;
 * an entry containing whitespace, padding, or a wrong length is rejected.
 */
export function falOptionsFromEnv(
  publicKeysValue: string | undefined,
  expectedUserId: string | undefined,
): FalVerifyOptions {
  if (!isString(publicKeysValue) || publicKeysValue === '') {
    invalidCredentialConfiguration();
  }

  if (!isString(expectedUserId) || !VISIBLE_USER_ID.test(expectedUserId)) {
    invalidCredentialConfiguration();
  }

  const entries = publicKeysValue.split(',');

  if (entries.length < 1 || entries.length > 16) {
    invalidCredentialConfiguration();
  }

  const publicKeys: Uint8Array[] = [];

  for (const entry of entries) {
    if (entry.length !== 43 || !/^[A-Za-z0-9_-]{43}$/.test(entry)) {
      invalidCredentialConfiguration();
    }

    const padded = entry.replace(/-/g, '+').replace(/_/g, '/') + '=';

    let decoded: string;

    try {
      decoded = atob(padded);
    } catch {
      invalidCredentialConfiguration();
    }

    if (decoded.length !== 32) {
      invalidCredentialConfiguration();
    }

    const key = new Uint8Array(32);

    for (let index = 0; index < 32; index += 1) {
      key[index] = decoded.charCodeAt(index);
    }

    // Re-encoding proves the original unused Base64 bits were canonical.
    if (base64UrlUnpadded(key) !== entry) {
      invalidCredentialConfiguration();
    }

    publicKeys.push(key);
  }

  return {
    provider: 'fal',
    publicKeys,
    expectedUserId,
  };
}

export interface GrafanaTimestampedRecipeInput {
  readonly secret: string;
  readonly timestampHeader: string;
  readonly signatureHeader?: string;
  readonly toleranceSeconds?: number;
  readonly now?: () => number;
}

export function grafanaTimestampedOptions(input: GrafanaTimestampedRecipeInput): VerifyOptions {
  const providerOptions: GrafanaOptions =
    input.signatureHeader === undefined
      ? { mode: 'timestamped', timestampHeader: input.timestampHeader }
      : {
          mode: 'timestamped',
          signatureHeader: input.signatureHeader,
          timestampHeader: input.timestampHeader,
        };

  return {
    provider: 'grafana',
    secrets: [input.secret],
    providerOptions,
    ...(input.toleranceSeconds !== undefined && { toleranceSeconds: input.toleranceSeconds }),
    ...(input.now !== undefined && { now: input.now }),
  };
}

export function createGrafanaTimestampedVerifier(input: GrafanaTimestampedRecipeInput) {
  return createVerifier(grafanaTimestampedOptions(input));
}

export function grafanaCustomHeaderOptions(input: GrafanaTimestampedRecipeInput): VerifyOptions {
  return grafanaTimestampedOptions(input);
}

export function createGrafanaCustomHeaderVerifier(input: GrafanaTimestampedRecipeInput) {
  return createVerifier(grafanaCustomHeaderOptions(input));
}

export interface PolarRecipeInput {
  readonly secrets: readonly string[];
  readonly toleranceSeconds?: number;
  readonly now?: () => number;
}

export function polarCurrentOptions(input: PolarRecipeInput): VerifyOptions {
  return {
    provider: 'polar',
    secrets: [...input.secrets],
    providerOptions: { secretMode: 'current' },
    ...(input.toleranceSeconds !== undefined && { toleranceSeconds: input.toleranceSeconds }),
    ...(input.now !== undefined && { now: input.now }),
  };
}

export function polarLegacyOptions(input: PolarRecipeInput): VerifyOptions {
  return {
    provider: 'polar',
    secrets: [...input.secrets],
    providerOptions: { secretMode: 'legacy' },
    ...(input.toleranceSeconds !== undefined && { toleranceSeconds: input.toleranceSeconds }),
    ...(input.now !== undefined && { now: input.now }),
  };
}

export function createPolarCurrentVerifier(input: PolarRecipeInput) {
  return createVerifier(polarCurrentOptions(input));
}

export function createPolarLegacyVerifier(input: PolarRecipeInput) {
  return createVerifier(polarLegacyOptions(input));
}
