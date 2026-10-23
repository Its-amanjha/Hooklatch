import { HooklatchError } from '../errors.js';
import { utf8 } from '../internal/bytes.js';
import type { FalParseResult, FalProviderDescriptor, NormalizedHeaders } from '../internal/provider.js';
import type { FailureDetails } from '../types.js';
import { failure, isCanonicalTimestamp } from './shared.js';

/** Static-key fal webhook formatting only; key authentication belongs to core.
 * https://fal.ai/docs/documentation/model-apis/inference/webhooks
 * Strict ID and hex grammars are Hooklatch receiver policy, not vendor parity.
 */
export const falDescriptor = {
  provider: 'fal',
  crypto: { kind: 'ed25519', signatureBytes: 64 },

  async parse(headers: NormalizedHeaders, rawBody: Uint8Array): Promise<FalParseResult> {
    const signatureRaw = headers.get('x-fal-webhook-signature');
    const requestId = headers.get('x-fal-webhook-request-id');
    const userId = headers.get('x-fal-webhook-user-id');
    const timestamp = headers.get('x-fal-webhook-timestamp');

    if (signatureRaw === undefined || signatureRaw.trim() === '') {
      return failure('missing-signature', 'No fal signature header was provided.');
    }

    const signature = decodeSignature(signatureRaw);

    if (signature === null) return malformed();

    // Presence of both IDs takes precedence over grammar of either ID.
    if (requestId === undefined || requestId.trim() === '') {
      return failure('missing-identity', 'No fal request identity was provided.');
    }

    if (userId === undefined || userId.trim() === '') {
      return failure('missing-identity', 'No fal user identity was provided.');
    }

    if (!isIdentity(requestId) || !isIdentity(userId)) return malformed();

    if (timestamp === undefined || timestamp.trim() === '') {
      return failure('missing-timestamp', 'No fal timestamp was provided.');
    }

    if (!isCanonicalTimestamp(timestamp)) return malformed();

    const body = new Uint8Array(rawBody);
    const subtle = globalThis.crypto?.subtle;

    if (!subtle) throw new HooklatchError('crypto-unavailable', 'Web Crypto is unavailable.');
    let digest: ArrayBuffer;

    try {
      digest = await subtle.digest('SHA-256', body);
    } catch (error) {
      if (isUnsupported(error)) {
        throw new HooklatchError('crypto-unavailable', 'Web Crypto is unavailable.');
      }

      throw new HooklatchError('internal', 'Cryptographic verification failed.');
    }

    const hex = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');

    return {
      ok: true, signatures: [signature],
      signedContent: utf8(`${requestId}\n${userId}\n${timestamp}\n${hex}`),
      recipient: userId,
      identity: { deliveryId: null, eventId: null, timestamp: Number(timestamp), authenticatedFields: ['timestamp'] },
    };
  },
} satisfies FalProviderDescriptor;

function malformed(): FailureDetails {
  return failure('malformed-signature', 'The fal signature headers are malformed.');
}

/** DOM exceptions may originate outside this realm. */
function isUnsupported(error: unknown): error is { readonly name: 'NotSupportedError' } {
  return error !== null && typeof error === 'object' && 'name' in error && error.name === 'NotSupportedError';
}

function isIdentity(value: string): boolean {
  return /^[\x21-\x7e]{1,1024}$/.test(value) && !value.includes(',');
}

function decodeSignature(value: string): Uint8Array | null {
  if (!/^[a-fA-F0-9]{128}$/.test(value)) return null;
  const bytes = new Uint8Array(64);

  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }

  return bytes;
}
