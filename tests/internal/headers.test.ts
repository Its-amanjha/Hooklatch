import { normalizeHeaders } from '../../src/internal/headers.js';

test('normalizes names and combines values identically for accepted representations', () => {
  const entries: [string, string][] = [['X-Test', 'ABC'], ['x-test', 'def']];
  expect(normalizeHeaders(entries).get('x-test')).toBe('ABC, def');
  expect(normalizeHeaders(new Headers(entries)).get('x-test')).toBe('ABC, def');
  expect(normalizeHeaders({ 'X-Test': ['ABC', 'def'], absent: undefined }).get('x-test'))
    .toBe('ABC, def');
});

test('takes a snapshot and rejects invalid header inputs safely', () => {
  const source = { 'X-Test': ['first'] };
  const snapshot = normalizeHeaders(source);
  source['X-Test'].push('second');
  expect(snapshot.get('x-test')).toBe('first');
  // SAFETY: Deliberately malformed input crosses the static API boundary to assert its runtime rejection.
  expect(() => normalizeHeaders(null as never)).toThrow('Invalid header input.');
  // SAFETY: Deliberately malformed input crosses the static API boundary to assert its runtime rejection.
  expect(() => normalizeHeaders({ invalid: 123 } as never)).toThrow('Invalid header input.');
});


test('fal opaque normalization preserves selected control bytes for descriptor rejection while default stays strict', () => {
  const fields = { 'x-fal-webhook-user-id': 'bad\nuser' };

  expect(() => normalizeHeaders(fields)).toThrow('Invalid header input.');
  expect(normalizeHeaders(fields, true).get('x-fal-webhook-user-id')).toBe('bad\nuser');
  // SAFETY: A deliberately malformed value must still be rejected in opaque mode.
  expect(() => normalizeHeaders({ 'x-fal-webhook-user-id': 123 } as never, true)).toThrow('Invalid header input.');
});


test('fal normalization reads only its four selected headers', () => {
  let reads = 0;
  const fields = { 'x-fal-webhook-user-id': 'account', 'bad name': 'ignored' };
  Object.defineProperty(fields, 'unrelated', { enumerable: true, get() { reads++; throw new Error('must not read'); } });

  expect(normalizeHeaders(fields, true)).toEqual(new Map([['x-fal-webhook-user-id', 'account']]));
  expect(reads).toBe(0);
});
