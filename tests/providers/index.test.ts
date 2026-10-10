import { getProviderDescriptor, stripeDescriptor } from '../../src/providers/index.js';

test('resolves each supported provider descriptor and rejects unknown providers', () => {
  expect(getProviderDescriptor('stripe')).toBe(stripeDescriptor);
  expect(getProviderDescriptor('stripe').provider).toBe('stripe');
  expect(getProviderDescriptor('github').provider).toBe('github');
  expect(getProviderDescriptor('shopify').provider).toBe('shopify');
  expect(getProviderDescriptor('standard-webhooks').provider).toBe('standard-webhooks');
  expect(() => getProviderDescriptor('unknown' as never)).toThrow('Unsupported webhook provider.');
});
