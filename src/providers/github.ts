import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import type { EventIdentity } from '../types.js';
import { decodeHexSignature, decodeLiteralSecret, failure } from './shared.js';

const SIGNATURE_HEADER = 'x-hub-signature-256';
const LEGACY_SIGNATURE_HEADER = 'x-hub-signature';
const SCHEME = 'sha256';
const DELIVERY_HEADER = 'x-github-delivery';

function optionalHeader(headers: NormalizedHeaders, name: string): string | null {
  const value = headers.get(name);
  return value === undefined || value === '' ? null : value;
}

/**
 * GitHub `X-Hub-Signature-256: sha256=<hex>` over the raw body only. The legacy
 * `X-Hub-Signature: sha1=<hex>` is recognized but never treated as SHA-256.
 * `X-GitHub-Delivery` is unsigned metadata and never proves authenticity.
 */
export const githubDescriptor: ProviderDescriptor = {
  provider: 'github',

  decodeSecret(secret: string): Uint8Array {
    return decodeLiteralSecret(secret, 'GitHub');
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const raw = headers.get(SIGNATURE_HEADER);
    if (raw === undefined || raw.trim() === '') {
      const legacy = headers.get(LEGACY_SIGNATURE_HEADER);
      if (legacy !== undefined && legacy.trim() !== '') {
        return failure('unsupported-scheme', 'Only the legacy SHA-1 GitHub signature was provided.');
      }
      return failure('missing-signature', 'No GitHub signature header was provided.');
    }

    const separator = raw.indexOf('=');
    if (separator <= 0 || separator === raw.length - 1) {
      return failure('malformed-signature', 'The GitHub signature header is malformed.');
    }
    const scheme = raw.slice(0, separator);
    if (scheme.toLowerCase() !== SCHEME) {
      return failure('unsupported-scheme', 'No supported GitHub signature scheme was provided.');
    }

    const signature = decodeHexSignature(raw.slice(separator + 1));
    if (signature === null) {
      return failure('malformed-signature', 'The GitHub signature header is malformed.');
    }

    const identity: EventIdentity = {
      deliveryId: optionalHeader(headers, DELIVERY_HEADER),
      eventId: null,
      timestamp: null,
      authenticatedFields: [],
    };
    return { ok: true, signatures: [signature], signedContent: rawBody, identity };
  },
};
