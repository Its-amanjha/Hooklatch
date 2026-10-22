import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import type { EventIdentity } from '../types.js';
import { decodeHexSignature, decodeLiteralSecret, failure } from './shared.js';

const SIGNATURE_HEADER = 'linear-signature';

/**
 * Linear webhook signature authentication: `Linear-Signature` is a single
 * 64-character hex HMAC-SHA256 over the exact visible raw request body, keyed
 * with the literal, untrimmed UTF-8 webhook secret. Missing or trim-blank values
 * are `missing-signature`; prefixes, outer whitespace, commas, lists, non-hex,
 * wrong length and all other nonconforming values fail closed as
 * `malformed-signature`. Either hex case is accepted as Hooklatch receiver
 * policy, not as a claim of exact Linear SDK parity.
 *
 * `Linear-Delivery`, `Linear-Event`, `linear-timestamp` and all alien
 * authentication headers are outside the MAC. They cannot establish freshness or
 * trusted identity. Every identity field is null and `authenticatedFields` is
 * empty: this descriptor intentionally performs body-only authentication, does
 * not parse JSON, and never derives identity or time from body content. Old or
 * future unsigned timestamps therefore cannot change authenticity, and this
 * descriptor does not provide replay protection or business idempotency.
 *
 * The secret is literal UTF-8 with no prefix stripping, Base64 decoding,
 * trimming or inferred length bound. Empty secrets are invalid configuration;
 * whitespace-only and non-ASCII secrets remain literal keys. The exact raw body
 * bytes are returned as signed content, so callers must retain the received
 * bytes rather than reserialize parsed JSON.
 *
 * Sources:
 * - https://linear.app/developers/webhooks
 * - https://linear.app/developers/sdk-webhooks
 * - https://github.com/linear/linear/blob/4d9cdbf0beb1d1da1824deb5ff3cd458c71380c9/packages/sdk/src/webhooks/client.ts
 *
 * No Linear-published signature tuple is claimed; test anchors are synthetic.
 */
export const linearDescriptor = {
  provider: 'linear',

  decodeSecret(secret: string): Uint8Array {
    return decodeLiteralSecret(secret, 'Linear');
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const raw = headers.get(SIGNATURE_HEADER);

    if (raw === undefined || raw.trim() === '') {
      return failure('missing-signature', 'No Linear signature header was provided.');
    }

    const signature = decodeHexSignature(raw);

    if (signature === null) {
      return failure('malformed-signature', 'The Linear signature header is malformed.');
    }

    const identity: EventIdentity = {
      deliveryId: null,
      eventId: null,
      timestamp: null,
      authenticatedFields: [],
    };

    return { ok: true, signatures: [signature], signedContent: rawBody, identity };
  },
} satisfies { readonly provider: 'linear' } & Pick<ProviderDescriptor, 'decodeSecret' | 'parse'>;
