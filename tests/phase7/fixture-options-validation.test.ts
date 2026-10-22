import { fixtureOptions, isFixtureProviderOptions, isPolarProviderOptions, loadFixture } from '../verification/helpers.js';
import type { FixtureCase } from '../verification/helpers.js';

test('fixture guards reject arrays as provider configuration', () => {
  expect(isPolarProviderOptions([])).toBe(false);
  expect(isFixtureProviderOptions([])).toBe(false);
  expect(isPolarProviderOptions({})).toBe(true);
  expect(isPolarProviderOptions({ secretMode: 'current' })).toBe(true);
  expect(isPolarProviderOptions({ secretMode: 'legacy' })).toBe(true);
});

test('fixture construction rejects configuration for a legacy provider instead of dropping it', () => {
  const original = loadFixture('github')[0];

  if (original === undefined) throw new Error('Missing GitHub fixture');

  const configured: FixtureCase = {
    ...original,
    options: { ...original.options, providerOptions: { secretMode: 'legacy' } },
  };

  expect(() => fixtureOptions('github', configured)).toThrow('providerOptions');
});
