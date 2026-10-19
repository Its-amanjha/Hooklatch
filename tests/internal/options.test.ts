import { normalizeOptions } from '../../src/internal/options.js';
import { jest } from '@jest/globals';

test('default options and secret arrays are snapshotted', () => {
  const secrets = [' secret with whitespace '];
  const result = normalizeOptions({ provider: 'github', secrets });
  secrets[0] = 'changed';
  expect(result.secrets).toEqual([' secret with whitespace ']);
  expect(result.maxBodyBytes).toBe(1048576);
  expect(result.toleranceSeconds).toBe(300);
});

test('WorkOS defaults preserve milliseconds while older provider clocks stay unchanged', () => {
  const clock = jest.spyOn(Date, 'now').mockReturnValue(1792368000123);

  try {
    const workos = normalizeOptions({ provider: 'workos', secrets: ['literal-key'] });

    expect(workos.toleranceSeconds).toBe(180);
    expect(workos.now()).toBe(1792368000.123);
    expect(normalizeOptions({ provider: 'workos', secrets: ['s'], toleranceSeconds: 0 }).toleranceSeconds).toBe(0);
    expect(normalizeOptions({ provider: 'workos', secrets: ['s'], toleranceSeconds: 7.5 }).toleranceSeconds).toBe(7.5);
    expect(normalizeOptions({ provider: 'paddle', secrets: ['s'] }).toleranceSeconds).toBe(5);

    for (const provider of ['github', 'stripe', 'paddle', 'standard-webhooks'] as const) {
      expect(normalizeOptions({ provider, secrets: ['s'] }).now()).toBe(1792368000);
    }

    expect(normalizeOptions({ provider: 'workos', secrets: ['s'], now: () => 5.125 }).now()).toBe(5.125);
  } finally {
    clock.mockRestore();
  }
});

test('zero tolerance remains zero and invalid configuration throws safe typed errors', () => {
  expect(normalizeOptions({ provider: 'stripe', secrets: ['s'], toleranceSeconds: 0 }).toleranceSeconds).toBe(0);
  // SAFETY: Deliberately malformed input crosses the static API boundary to assert its runtime rejection.
  expect(() => normalizeOptions({ provider: 'unknown', secrets: ['s'] } as never)).toThrow('Unsupported webhook provider.');
  expect(() => normalizeOptions({ provider: 'github', secrets: [] })).toThrow('At least one signing secret is required.');
  expect(() => normalizeOptions({ provider: 'github', secrets: [''] })).toThrow('Invalid signing secret.');
  const sparseSecrets: string[] = [];
  sparseSecrets.length = 1;
  expect(() => normalizeOptions({ provider: 'github', secrets: sparseSecrets })).toThrow('Invalid signing secret.');

  for (const value of [-1, NaN, Infinity]) expect(() => normalizeOptions({ provider: 'github', secrets: ['s'], toleranceSeconds: value })).toThrow();

  for (const value of [0, -1, 1.1, Infinity]) expect(() => normalizeOptions({ provider: 'github', secrets: ['s'], maxBodyBytes: value })).toThrow();
});
