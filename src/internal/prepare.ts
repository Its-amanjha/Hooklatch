import type { VerifyOptions } from '../types.js';
import { getProviderDescriptor } from '../providers/index.js';
import { normalizeOptions } from './options.js';
import { prepareVerifier } from './verification.js';
import type { PreparedVerifier } from './verification.js';

/** Shared preparation validates and snapshots trusted options before any request body is read. */
export function prepareVerification(options: VerifyOptions): PreparedVerifier {
  const normalized = normalizeOptions(options);

  return prepareVerifier(normalized, getProviderDescriptor(normalized.provider, normalized.providerOptions));
}
