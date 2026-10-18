import type { AddressInfo } from 'node:net';
import { createHmac } from 'node:crypto';

/** Independent Node signer; adapters exercise the real verification core. */
export function signedHeaders(body: string, secret = 's') {
  return { 'x-hub-signature-256': `sha256=${createHmac('sha256', secret).update(body).digest('hex')}` };
}

export function isTcpAddress(value: AddressInfo | string | null): value is AddressInfo {
  return value !== null && typeof value === 'object';
}
