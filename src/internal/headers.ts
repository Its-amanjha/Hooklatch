import { HooklatchError } from '../errors.js';
import type { HeaderInput } from '../types.js';

function isHeaderName(name: string): name is string {
  return typeof name === 'string' && /^[!#$%&'*+.^_`|~\da-z-]+$/i.test(name);
}

function isHeaderValue(value: string, opaque: boolean): value is string {
  return typeof value === 'string' && (opaque || !/[\r\n\0]/.test(value));
}

function isHeaderRecord(input: HeaderInput): input is Readonly<Record<string, string | readonly string[] | undefined>> {
  return input !== null && typeof input === 'object';
}

function isHeaderValues(value: string | readonly string[]): value is readonly string[] {
  return Array.isArray(value);
}

/** Opaque values are used only by fal so its signed-field grammar owns rejection. */
const FAL_HEADER_NAMES = new Set([
  'x-fal-webhook-signature', 'x-fal-webhook-request-id',
  'x-fal-webhook-user-id', 'x-fal-webhook-timestamp',
]);

function isFalHeaderName(name: string): name is string {
  return typeof name === 'string' && FAL_HEADER_NAMES.has(name.toLowerCase());
}

export function normalizeHeaders(input: HeaderInput, opaqueValues = false): Map<string, string> {
  const result = new Map<string, string>();
  const invalid = (): never => { throw new HooklatchError('invalid-input', 'Invalid header input.'); };

  const append = (name: string, value: string): void => {
    if (opaqueValues && !isFalHeaderName(name)) return;

    if (!isHeaderName(name) || !isHeaderValue(value, opaqueValues)) invalid();

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
    const entries: [string, string | readonly string[] | undefined][] = [];

    if (opaqueValues) {
      for (const key of Object.keys(input)) {
        if (isFalHeaderName(key)) entries.push([key, input[key]]);
      }
    } else entries.push(...Object.entries(input));

    for (const [key, value] of entries) {
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
