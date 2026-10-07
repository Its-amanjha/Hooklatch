import { normalizeOptions } from '../../src/internal/options.js';

test('default options and secret arrays are snapshotted', () => {
  const secrets = [' secret with whitespace '];
  const result = normalizeOptions({ provider: 'github', secrets });
  secrets[0] = 'changed';
  expect(result.secrets).toEqual([' secret with whitespace ']);
  expect(result.maxBodyBytes).toBe(1048576);
  expect(result.toleranceSeconds).toBe(300);
});

test('zero tolerance remains zero and invalid configuration throws safe typed errors', () => {
  expect(normalizeOptions({ provider: 'stripe', secrets: ['s'], toleranceSeconds: 0 }).toleranceSeconds).toBe(0);
  expect(() => normalizeOptions({ provider: 'unknown', secrets: ['s'] } as never)).toThrow('Unsupported webhook provider.');
  expect(() => normalizeOptions({ provider: 'github', secrets: [] })).toThrow('At least one signing secret is required.');
  expect(() => normalizeOptions({ provider: 'github', secrets: [''] })).toThrow('Invalid signing secret.');
  expect(() => normalizeOptions({ provider: 'github', secrets: new Array<string>(1) })).toThrow('Invalid signing secret.');
  for (const value of [-1, NaN, Infinity]) expect(() => normalizeOptions({ provider: 'github', secrets: ['s'], toleranceSeconds: value })).toThrow();
  for (const value of [0, -1, 1.1, Infinity]) expect(() => normalizeOptions({ provider: 'github', secrets: ['s'], maxBodyBytes: value })).toThrow();
});
