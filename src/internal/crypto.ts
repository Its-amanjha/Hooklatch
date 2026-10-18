import { HooklatchError } from '../errors.js';

export async function verifyHmac(
  keys: readonly Uint8Array[], signatures: readonly Uint8Array[], content: Uint8Array,
): Promise<boolean> {
  const subtle = globalThis.crypto?.subtle;

  if (!subtle) throw new HooklatchError('crypto-unavailable', 'Web Crypto is unavailable.');

  try {
    for (const bytes of keys) {
      const key = await subtle.importKey('raw', new Uint8Array(bytes), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);

      for (const signature of signatures) {
        if (await subtle.verify('HMAC', key, new Uint8Array(signature), new Uint8Array(content))) return true;
      }
    }

    return false;
  } catch { throw new HooklatchError('internal', 'Cryptographic verification failed.'); }
}
