import { HooklatchError } from '../errors.js';
import type { HeaderInput } from '../types.js';

export function normalizeHeaders(input: HeaderInput): Map<string, string> {
  const result = new Map<string, string>();
  const invalid = (): never => { throw new HooklatchError('invalid-input', 'Invalid header input.'); };
  const append = (name: unknown, value: unknown): void => {
    if (typeof name !== 'string' || typeof value !== 'string'
      || !/^[!#$%&'*+.^_`|~\da-z-]+$/i.test(name) || /[\r\n\0]/.test(value)) invalid();
    const key = (name as string).toLowerCase();
    const previous = result.get(key);
    result.set(key, previous === undefined ? value as string : `${previous}, ${value as string}`);
  };
  if (input instanceof Headers) {
    input.forEach((value, key) => append(key, value));
  } else if (Array.isArray(input)) {
    for (const entry of input) {
      if (!Array.isArray(entry) || entry.length !== 2) invalid();
      append(entry[0], entry[1]);
    }
  } else if (input && typeof input === 'object') {
    for (const [key, value] of Object.entries(input)) {
      if (value === undefined) continue;
      if (Array.isArray(value)) for (const item of value) append(key, item);
      else append(key, value);
    }
  } else invalid();
  return result;
}
