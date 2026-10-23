import { HooklatchError } from '../errors.js';
import type { HmacPolicy } from './provider.js';

function isUnsupported(error: unknown): error is { readonly name: 'NotSupportedError' } {
  return error !== null && typeof error === 'object' && 'name' in error && error.name === 'NotSupportedError';
}

export async function verifyHmac(
  keys: readonly Uint8Array[], signatures: readonly Uint8Array[], content: Uint8Array,
  policy: HmacPolicy = { kind: 'hmac', hash: 'SHA-256', signatureBytes: 32 },
): Promise<boolean> {
  const subtle = globalThis.crypto?.subtle;

  if (!subtle) throw new HooklatchError('crypto-unavailable', 'Web Crypto is unavailable.');

  try {
    for (const bytes of keys) {
      const key = await subtle.importKey('raw', new Uint8Array(bytes), { name: 'HMAC', hash: policy.hash }, false, ['verify']);

      for (const signature of signatures) {
        if (signature.byteLength !== policy.signatureBytes) continue;

        if (await subtle.verify('HMAC', key, new Uint8Array(signature), new Uint8Array(content))) return true;
      }
    }

    return false;
  } catch (error) {
    if (isUnsupported(error)) throw new HooklatchError('crypto-unavailable', 'Web Crypto is unavailable.');

    throw new HooklatchError('internal', 'Cryptographic verification failed.');
  }
}

export async function verifyEd25519(
  keys: readonly Uint8Array[], signatures: readonly Uint8Array[], content: Uint8Array,
): Promise<boolean> {
  const subtle = globalThis.crypto?.subtle;

  if (!subtle) throw new HooklatchError('crypto-unavailable', 'Web Crypto is unavailable.');

  try {
    for (const bytes of keys) {
      const key = await subtle.importKey('raw', new Uint8Array(bytes), 'Ed25519', false, ['verify']);

      for (const signature of signatures) {
        if (signature.byteLength !== 64) continue;

        if (await subtle.verify('Ed25519', key, new Uint8Array(signature), new Uint8Array(content))) return true;
      }
    }

    return false;
  } catch (error) {
    if (isUnsupported(error)) throw new HooklatchError('crypto-unavailable', 'Web Crypto is unavailable.');

    throw new HooklatchError('internal', 'Cryptographic verification failed.');
  }
}
