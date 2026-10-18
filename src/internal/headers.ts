import { HooklatchError } from '../errors.js';
import type { HeaderInput } from '../types.js';

function isHeaderName(name: string): name is string {
  return typeof name === 'string' && /^[!#$%&'*+.^_`|~\da-z-]+$/i.test(name);
}

function isHeaderValue(value: string): value is string {
  return typeof value === 'string' && !/[\r\n\0]/.test(value);
}

function isHeaderRecord(input: HeaderInput): input is Readonly<Record<string, string | readonly string[] | undefined>> {
  return input !== null && typeof input === 'object';
}

function isHeaderValues(value: string | readonly string[]): value is readonly string[] {
  return Array.isArray(value);
}

export function normalizeHeaders(input: HeaderInput): Map<string, string> {
  const result = new Map<string, string>();
  const invalid = (): never => { throw new HooklatchError('invalid-input', 'Invalid header input.'); };

  const append = (name: string, value: string): void => {
    if (!isHeaderName(name) || !isHeaderValue(value)) invalid();

    const key = name.toLowerCase();
    const previous = result.get(key);
    result.set(key, previous === undefined ? value : `${previous}, ${value}`);
  };

  if (input instanceof Headers) {
    input.forEach((value, key) => append(key, value));
  } else if (Array.isArray(input)) {
    for (const entry of input) {
      if (!Array.isArray(entry) || entry.length !== 2) invalid();
      append(entry[0], entry[1]);
    }
  } else if (isHeaderRecord(input)) {
    for (const [key, value] of Object.entries(input)) {
      if (value === undefined) continue;

      if (isHeaderValues(value)) {
        for (const item of value) append(key, item);
      } else {
        append(key, value);
      }
    }
  } else invalid();

  return result;
}
