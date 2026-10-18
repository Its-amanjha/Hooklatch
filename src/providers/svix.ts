import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import { failure } from './shared.js';
import { createStandardWebhooksProtocol } from './standard-webhooks-protocol.js';
import type { StandardWebhooksHeaderNames } from './standard-webhooks-protocol.js';

const BRANDED_HEADERS: StandardWebhooksHeaderNames = {
  id: 'svix-id',
  timestamp: 'svix-timestamp',
  signature: 'svix-signature',
};

const CANONICAL_HEADERS: StandardWebhooksHeaderNames = {
  id: 'webhook-id',
  timestamp: 'webhook-timestamp',
  signature: 'webhook-signature',
};

const brandedDescriptor = createStandardWebhooksProtocol('svix', 'Svix', BRANDED_HEADERS);
const canonicalDescriptor = createStandardWebhooksProtocol('svix', 'Svix', CANONICAL_HEADERS);

function familyPresent(headers: NormalizedHeaders, names: StandardWebhooksHeaderNames): boolean {
  return headers.has(names.id) || headers.has(names.timestamp) || headers.has(names.signature);
}

function familyComplete(headers: NormalizedHeaders, names: StandardWebhooksHeaderNames): boolean {
  const id = headers.get(names.id);
  const timestamp = headers.get(names.timestamp);
  const signature = headers.get(names.signature);

  return id !== undefined && id !== ''
    && timestamp !== undefined && timestamp !== ''
    && signature !== undefined && signature !== '';
}

function familiesEqual(headers: NormalizedHeaders): boolean {
  return familyComplete(headers, BRANDED_HEADERS)
    && familyComplete(headers, CANONICAL_HEADERS)
    && headers.get(BRANDED_HEADERS.id) === headers.get(CANONICAL_HEADERS.id)
    && headers.get(BRANDED_HEADERS.timestamp) === headers.get(CANONICAL_HEADERS.timestamp)
    && headers.get(BRANDED_HEADERS.signature) === headers.get(CANONICAL_HEADERS.signature);
}

/**
 * Svix accepts the branded `svix-*` and canonical `webhook-*` Standard
 * Webhooks header families. A single family is parsed with the existing
 * signature -> identity -> timestamp ordering. When both families have any
 * header present, both must be complete and value-identical; otherwise the
 * request is malformed. A failed family is never rescued by the other one.
 */
export const svixDescriptor: ProviderDescriptor = {
  provider: 'svix',

  decodeSecret(secret: string): Uint8Array {
    return brandedDescriptor.decodeSecret(secret);
  },

  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
    const brandedPresent = familyPresent(headers, BRANDED_HEADERS);
    const canonicalPresent = familyPresent(headers, CANONICAL_HEADERS);

    if (brandedPresent && canonicalPresent) {
      if (!familiesEqual(headers)) {
        return failure('malformed-signature', 'The Svix signature headers are malformed.');
      }

      return brandedDescriptor.parse(headers, rawBody);
    }

    if (canonicalPresent) return canonicalDescriptor.parse(headers, rawBody);

    if (brandedPresent) return brandedDescriptor.parse(headers, rawBody);

    return failure('missing-signature', 'No Svix signature header was provided.');
  },
};
