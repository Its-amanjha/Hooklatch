import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import type { EventIdentity } from '../types.js';
import { decodeHexSignature, decodeLiteralSecret, failure } from './shared.js';

const SIGNATURE_HEADER = 'sentry-hook-signature';

/**
 * Sentry App integration-platform webhooks: `Sentry-Hook-Signature` is a single
 * 64-character hex HMAC-SHA256 over the exact raw request body, keyed with the
 * literal app client secret. Missing or trim-blank -> missing-signature; every
 * other nonconforming value (prefixes, whitespace, comma-combined duplicates,
 * lists, wrong length or non-hex) fails closed.
 *
 * `Request-Id`, `Sentry-Hook-Timestamp` and `Sentry-Hook-Resource` are outside
 * the MAC: they cannot establish freshness or trusted identity. Sentry's docs
 * examples re-serialize the parsed body, which changes the signed bytes; this
 * descriptor always returns the untouched `rawBody` as signed content.
 *
 * Scope is Sentry App integration-platform webhooks only, not every Sentry
 * webhook product. Sources:
 * - https://docs.sentry.io/integrations/integration-platform/webhooks/
 * - https://github.com/getsentry/sentry/blob/72757dae9b6d527e564c81d4921dec0d62d7beca/src/sentry/sentry_apps/api/serializers/app_platform_event.py
 *
 * No Sentry-published signature vector is claimed; test anchors are synthetic.
 */
export const sentryDescriptor = {
  provider: 'sentry',

  decodeSecret(secret: string): Uint8Array {
    return decodeLiteralSecret(secret, 'Sentry App');
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const raw = headers.get(SIGNATURE_HEADER);

    if (raw === undefined || raw.trim() === '') {
      return failure('missing-signature', 'No Sentry App signature header was provided.');
    }

    const signature = decodeHexSignature(raw);

    if (signature === null) {
      return failure('malformed-signature', 'The Sentry App signature header is malformed.');
    }

    const identity: EventIdentity = {
      deliveryId: null,
      eventId: null,
      timestamp: null,
      authenticatedFields: [],
    };

    return { ok: true, signatures: [signature], signedContent: rawBody, identity };
  },
} satisfies { readonly provider: 'sentry' } & Pick<ProviderDescriptor, 'decodeSecret' | 'parse'>;
