import { HooklatchError } from '../errors.js';
import type { ProviderDescriptor } from '../internal/provider.js';
import { decodeLiteralSecret } from './shared.js';
import { createStandardWebhooksProtocol } from './standard-webhooks-protocol.js';

export interface PolarDescriptorOptions {
  readonly secretMode?: 'current' | 'legacy';
}

type PolarDescriptor = { readonly provider: 'polar' } & Pick<
  ProviderDescriptor,
  'decodeSecret' | 'parse'
>;

const CANONICAL_HEADERS = {
  id: 'webhook-id',
  timestamp: 'webhook-timestamp',
  signature: 'webhook-signature',
} as const;

const currentDescriptor = createStandardWebhooksProtocol('polar', 'Polar', CANONICAL_HEADERS);

const legacyDescriptor: PolarDescriptor = {
  provider: 'polar',

  decodeSecret(secret: string): Uint8Array {
    return decodeLiteralSecret(secret, 'Polar');
  },

  parse: currentDescriptor.parse,
};

function invalidOptions(): never {
  throw new HooklatchError('invalid-options', 'Invalid Polar provider options.');
}

function isConfigObject(
  value: PolarDescriptorOptions | null | undefined,
): value is PolarDescriptorOptions {
  if (value === null || typeof value !== 'object') return false;

  try {
    return !Array.isArray(value);
  } catch {
    return false;
  }
}

/**
 * Read the selected mode as an own field and snapshot it before returning the
 * descriptor. Inherited fields are not configuration; an own `secretMode:
 * undefined` is invalid rather than an omitted optional field.
 */
function snapshotSecretMode(options: PolarDescriptorOptions | undefined): 'current' | 'legacy' {
  if (options === undefined) return 'current';

  if (!isConfigObject(options)) invalidOptions();

  let keys: readonly (string | symbol)[] = [];
  let hasMode = false;
  let mode: PolarDescriptorOptions['secretMode'] = undefined;

  try {
    keys = Reflect.ownKeys(options).filter(
      (key) => Object.getOwnPropertyDescriptor(options, key)?.enumerable,
    );
    hasMode = Object.hasOwn(options, 'secretMode');
    mode = hasMode ? options.secretMode : undefined;
  } catch {
    invalidOptions();
  }

  if (keys.some((key) => key !== 'secretMode')) invalidOptions();

  if (!hasMode) return 'current';

  if (mode !== 'current' && mode !== 'legacy') invalidOptions();

  return mode;
}

/**
 * Polar webhooks use the canonical Standard Webhooks headers and signed
 * content: `${webhook-id}.${webhook-timestamp}.${rawBody}`.
 *
 * `current` (the default) keeps the shared Standard Webhooks decoder: an
 * optional `whsec_` prefix is removed and the remainder must decode as
 * canonical Base64 to 24..64 bytes. `legacy` treats the complete secret string
 * as literal UTF-8 bytes, including any `whsec_` prefix, with only the shared
 * nonempty policy. Exactly one mode applies to every secret configured for the
 * descriptor; there is no prefix inference or cross-mode fallback.
 *
 * Polar's SDK tries both key interpretations and floors fractional timestamps.
 * Hooklatch deliberately does neither, and does not decode opaque bodies as
 * text. Source:
 * https://raw.githubusercontent.com/polarsource/polar/89917ad4fe752b06ff84bd31c313d2a53a6085f1/sdk/typescript/src/webhooks.ts
 */
export function createPolarDescriptor(options?: PolarDescriptorOptions): PolarDescriptor {
  return snapshotSecretMode(options) === 'current' ? currentDescriptor : legacyDescriptor;
}
