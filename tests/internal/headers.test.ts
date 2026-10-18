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
