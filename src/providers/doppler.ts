import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import type { EventIdentity } from '../types.js';
import { decodeHexSignature, decodeLiteralSecret, failure, isSchemeToken } from './shared.js';

const SIGNATURE_HEADER = 'x-doppler-signature';
const SIGNATURE_SCHEME = 'sha256';

/**
 * Doppler `X-Doppler-Signature: sha256=<hex HMAC-SHA256(raw request body)>`.
 *
 * Doppler documents exactly one `<scheme>=<64 hex>` value; there is no list and
 * no unknown-field tolerance. The complete value is validated before the scheme
 * decision, so a well-formed digest under another scheme token (`sha1=<64 hex>`)
 * fails as `unsupported-scheme`, while any nonconforming syntax — wrong length,
 * non-hex, bare hex, commas, extra equals, empty digest, or outer whitespace —
 * fails as `malformed-signature`. `sha256=` is case-sensitive; `SHA256=<64 hex>`
 * is a different scheme and therefore unsupported.
 *
 * The secret is the literal, untrimmed UTF-8 text of the webhook `Secret`. It is
 * never Base64-decoded and no `whsec_`-style prefix is inferred, so an empty
 * secret is an invalid configuration rather than an encoded empty key.
 *
 * The HMAC covers the exact raw body only. Doppler publishes no timestamp,
 * delivery ID or signed event identifier, so every identity field is null and
 * `authenticatedFields` is empty: this descriptor never establishes freshness and
 * offers no replay protection. Signing is optional on the Doppler side, so a
 * delivery without a configured secret carries no signature and cannot be
 * verified; there is no Basic/Bearer or unsigned fallback path here.
 *
 * The Doppler docs' Node example re-serializes with `JSON.stringify(req.body)`.
 * This descriptor authenticates the received bytes instead, so a caller that has
 * already parsed the body cannot reliably reconstruct the signed content and
 * should pass the original bytes.
 *
 * Source: https://docs.doppler.com/docs/webhooks
 *
 * No Doppler-published signature tuple was located; test anchors are synthetic.
 */
export const dopplerDescriptor = {
  provider: 'doppler',

  decodeSecret(secret: string): Uint8Array {
    return decodeLiteralSecret(secret, 'Doppler');
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const raw = headers.get(SIGNATURE_HEADER);

    if (raw === undefined || raw.trim() === '') {
      return failure('missing-signature', 'No Doppler signature header was provided.');
    }

    // Validate the whole value first: exactly one `=`, a nonempty scheme token,
    // and a nonempty digest. `decodeHexSignature` accepts either hex case but
    // requires exactly 64 hex characters (32 bytes).
    const separator = raw.indexOf('=');

    if (separator <= 0 || separator === raw.length - 1 || raw.indexOf('=', separator + 1) !== -1) {
      return failure('malformed-signature', 'The Doppler signature header is malformed.');
    }

    const scheme = raw.slice(0, separator);
    const signature = decodeHexSignature(raw.slice(separator + 1));

    if (!isSchemeToken(scheme) || signature === null) {
      return failure('malformed-signature', 'The Doppler signature header is malformed.');
    }

    if (scheme !== SIGNATURE_SCHEME) {
      return failure('unsupported-scheme', 'The Doppler signature scheme is not supported.');
    }

    const identity: EventIdentity = {
      deliveryId: null,
      eventId: null,
      timestamp: null,
      authenticatedFields: [],
    };

    return { ok: true, signatures: [signature], signedContent: rawBody, identity };
  },
} satisfies { readonly provider: 'doppler' } & Pick<ProviderDescriptor, 'decodeSecret' | 'parse'>;
