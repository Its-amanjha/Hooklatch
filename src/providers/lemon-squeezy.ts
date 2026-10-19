import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import { decodeHexSignature, decodeLiteralSecret, failure } from './shared.js';

const SIGNATURE_HEADER = 'x-signature';

/**
 * Lemon Squeezy `X-Signature`: a single 64-character hex HMAC-SHA256 digest of
 * the exact raw body, keyed with the literal webhook signing secret. The docs
 * suggest 6-40 character secrets, but that UI guidance is not enforced as a
 * cryptographic limit. No timestamp or event identifier is documented for
 * verification, so identity stays null and unsigned (`X-Event-Name` is
 * metadata and is not interpreted).
 */
export const lemonSqueezyDescriptor = {
  provider: 'lemon-squeezy',

  decodeSecret(secret: string): Uint8Array {
    return decodeLiteralSecret(secret, 'Lemon Squeezy');
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const raw = headers.get(SIGNATURE_HEADER);

    if (raw === undefined || raw.trim() === '') {
      return failure('missing-signature', 'No Lemon Squeezy signature header was provided.');
    }

    const signature = decodeHexSignature(raw);

    if (signature === null) {
      return failure('malformed-signature', 'The Lemon Squeezy signature header is malformed.');
    }

    return {
      ok: true,
      signatures: [signature],
      signedContent: rawBody,
      identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    };
  },
} satisfies { readonly provider: 'lemon-squeezy' } & Pick<ProviderDescriptor, 'decodeSecret' | 'parse'>;
