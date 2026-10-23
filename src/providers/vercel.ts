import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import { decodeLiteralSecret, failure } from './shared.js';

/** Scoped x-vercel-signature webhook recipe; exact bytes and literal UTF-8 keys.
 * https://vercel.com/docs/webhooks/webhooks-api
 * Either hex case is accepted as receiver policy. No freshness is inferred.
 */
export const vercelDescriptor = {
  provider: 'vercel',
  crypto: { kind: 'hmac', hash: 'SHA-1', signatureBytes: 20 },

  decodeSecret(secret: string): Uint8Array {
    return decodeLiteralSecret(secret, 'Vercel');
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const raw = headers.get('x-vercel-signature');

    if (raw === undefined || raw.trim() === '') {
      return failure('missing-signature', 'No Vercel signature header was provided.');
    }

    const signature = decodeSignature(raw);

    if (signature === null) {
      return failure('malformed-signature', 'The Vercel signature header is malformed.');
    }

    return {
      ok: true, signatures: [signature], signedContent: rawBody,
      identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    };
  },
} satisfies ProviderDescriptor;

/** Deliberately private: the existing shared SHA256 decoder stays 32 bytes. */
function decodeSignature(value: string): Uint8Array | null {
  if (!/^[a-fA-F0-9]{40}$/.test(value)) return null;
  const bytes = new Uint8Array(20);

  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }

  return bytes;
}
